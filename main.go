package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/agent"
	"github.com/OliverKruecken/waverms-agent/internal/config"
	"github.com/OliverKruecken/waverms-agent/internal/hardware"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// Version is set at build time by -ldflags "-X main.Version=...".
var Version = "1.0.0"

func main() {
	// On embedded targets GOMAXPROCS defaults to the number of CPU cores, which
	// causes the Go runtime to reserve proportionally more virtual address space
	// and spin up more GC workers. Single-threading the scheduler keeps VSZ in
	// check on devices with tight memory.
	runtime.GOMAXPROCS(1)

	// GOMEMLIMIT caps the soft heap target so the GC runs more aggressively
	// before the OOM killer steps in. The default (math.MaxInt64) is fine on
	// servers but wrong for embedded. Honour the env var if set; otherwise
	// default to 32 MiB, which is enough for normal operation.
	if limitStr := os.Getenv("GOMEMLIMIT"); limitStr != "" {
		if v, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			debug.SetMemoryLimit(v)
		}
	} else {
		debug.SetMemoryLimit(32 << 20) // 32 MiB
	}

	// -debug is a run-time-only override for one-off diagnostic runs (e.g.
	// stopping the procd-managed instance and running the binary by hand over
	// SSH) without editing the persistent DEBUG=true key in /etc/waverms/config.
	// It's equivalent to that config key, not additive to it — see cfg.Debug
	// below, which both the initial handler and agent.go's later live-logs
	// handler key off of.
	debugFlag := flag.Bool("debug", false, "enable debug-level logging for this run")
	flag.Parse()

	// WaitForBrokerHost polls /etc/waverms/config and the DHCP overlay
	// /etc/waverms/dhcp (written by /etc/udhcpc.user.d/60-waverms-bootstrap
	// from option 225) until BROKER_HOST is non-empty or 120 s elapse.
	cfg, err := config.WaitForBrokerHost("/etc/waverms/config", "/etc/waverms/dhcp", 120*time.Second)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.AgentVersion = Version
	if *debugFlag {
		cfg.Debug = true
	}

	// logLevel is a LevelVar rather than a static Level so the log-level/control
	// MQTT topic (agent.go's handleLogLevelControl) can raise/lower verbosity at
	// runtime without a restart — every handler in the chain built below shares
	// this same instance.
	logLevel := new(slog.LevelVar)
	if cfg.Debug {
		logLevel.Set(slog.LevelDebug)
	} else {
		logLevel.Set(slog.LevelInfo)
	}
	// Prefer writing straight to the local syslog socket over plain stderr text:
	// procd (per procd_set_param stdout/stderr 1 in the init script) tags every
	// line it captures from stderr as LOG_ERR regardless of content, so routing
	// normal logging through stderr made every record — including plain INFO
	// lines — show up in logd, and therefore the live-logs snapshot, as an error.
	// See internal/agent/syslog_handler.go. A missing /dev/log (devcontainer, CI,
	// any non-OpenWrt host) falls back to the old stderr-text behavior.
	var textHandler slog.Handler
	if sh, sErr := agent.NewSyslogHandler(logLevel); sErr == nil {
		textHandler = sh
	} else {
		textHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
		slog.SetDefault(slog.New(textHandler))
		slog.Warn("syslog: failed to dial /dev/log, falling back to stderr text logging", "err", sErr)
	}

	// Persist agent activity to /etc/waverms/agent.log (survives reboot, unlike
	// the syslog ring buffer) so a slow-reconnecting device can be diagnosed after
	// the fact. A broken log file must never stop the agent from booting, so a
	// failure here just falls back to whatever textHandler above resolved to.
	activityLog, err := agent.NewActivityLogHandler(textHandler)
	if err != nil {
		slog.SetDefault(slog.New(textHandler))
		slog.Warn("activity log: failed to open persistent log file, continuing without it", "err", err)
	} else {
		slog.SetDefault(slog.New(activityLog))
	}
	log.SetFlags(0) // slog handler owns timestamps
	slog.Info("waverms-agent starting",
		"version", Version,
		"go", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
	)

	creds, err := config.LoadCredentials("/etc/waverms/credentials")
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("credentials: %v", err)
	}

	mac, err := hardware.GetFirstPhysicalMAC()
	if err != nil {
		slog.Warn("cannot determine MAC address", "err", err)
	}

	var tlsCfg *tls.Config
	if cfg.TLSInsecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	} else {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}

	a := agent.New(&agent.Options{
		Config:         cfg,
		Creds:          creds,
		MAC:            mac,
		Model:          hardware.GetModel(),
		OpenWrtVersion: hardware.GetOpenWrtVersion(),
		Target:         hardware.GetTarget(),
		Profile:        hardware.GetBoardName(),
		VersionCode:    hardware.GetVersionCode(),
		MQTT:           mqttclient.NewPahoClient(tlsCfg),
		UCI:            &uci.RealUCIRunner{},
		Version:        Version,
		ActivityLog:    activityLog,
		LogLevel:       logLevel,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil {
		log.Fatalf("agent: %v", err)
	}
}
