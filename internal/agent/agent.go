// Package agent implements the main agent event loop.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/bootstrap"
	"github.com/OliverKruecken/waverms-agent/internal/config"
	"github.com/OliverKruecken/waverms-agent/internal/filewriter"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// Command is the payload received on device/{id}/cmd.
type Command struct {
	CmdID   string          `json:"cmd_id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// UCICommandPayload is the inner payload for type "uci_set".
type UCICommandPayload struct {
	Commands []string `json:"commands"`
}

// FileWriteCommandPayload is the inner payload for type "file_write".
//
// Format controls how Content is decoded before writing:
//   - "openssh" or "" (default): Content is a UTF-8 string, written as-is.
//   - "dropbear": Content is standard base64 (RFC 4648); the agent decodes it to raw bytes.
//     Required for native Dropbear binary host key files that are not valid UTF-8.
type FileWriteCommandPayload struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Format  string `json:"format"` // "openssh" (default/absent) | "dropbear" (base64 binary)
	Mode    string `json:"mode"`
}

// HostKeyRestorePayload is the inner payload for type "host_key_restore".
// Keys maps each filename (e.g. "dropbear_ed25519_host_key") to its raw file content.
// Values are base64-encoded in the JSON payload (RFC 4648); encoding/json decodes them
// automatically into []byte so they can be written as binary to disk.
// Files are written to the SSH daemon's key directory (detected at startup) with mode 0600.
type HostKeyRestorePayload struct {
	Keys map[string][]byte `json:"keys"`
}

// sshDaemonInfo describes the SSH daemon running on this device.
type sshDaemonInfo struct {
	Name    string // "dropbear" or "openssh"
	Dir     string // directory where host keys live, e.g. "/etc/dropbear/"
	Service string // init script path, e.g. "/etc/init.d/dropbear"
}

var (
	daemonDropbear = sshDaemonInfo{Name: "dropbear", Dir: "/etc/dropbear/", Service: "/etc/init.d/dropbear"}
	daemonOpenSSH  = sshDaemonInfo{Name: "openssh", Dir: "/etc/ssh/", Service: "/etc/init.d/sshd"}
)

// detectSSHDaemon checks which SSH daemon binary is present and returns its
// sshDaemonInfo. Falls back to Dropbear when neither binary is found.
func detectSSHDaemon() sshDaemonInfo {
	if _, err := os.Stat("/usr/sbin/sshd"); err == nil {
		return daemonOpenSSH
	}
	return daemonDropbear
}

// StateRequestPayload is received on device/{id}/state/request.
type StateRequestPayload struct {
	Packages []string `json:"packages"`
}

// StatePayload is published to device/{id}/state.
type StatePayload struct {
	Timestamp string                                         `json:"timestamp"`
	Trigger   string                                         `json:"trigger"`
	Packages  map[string]map[string][]map[string]interface{} `json:"packages"`
	// RawFiles contains the verbatim content of /etc/config/<pkg> for each package,
	// preserving comments and formatting that uci export strips.
	RawFiles map[string]string `json:"raw_files,omitempty"`
	// AuthorizedKeys holds one normalized public key string per line currently
	// installed in authorizedKeysPath, in the form "<type> <base64blob>" (comment
	// stripped). Malformed lines and a missing file are silently skipped.
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
	// HostKeyFingerprints maps SSH host key filename -> lowercase hex SHA-256 of
	// the raw file content.
	HostKeyFingerprints map[string]string `json:"host_key_fingerprints,omitempty"`
	// TLSCertFingerprint is the lowercase hex SHA-256 of the TLS certificate file
	// currently deployed at the most recently pushed cert_path (falling back to
	// defaultTLSCertPath if no tls_cert_push has succeeded this session). Empty
	// when no readable cert file is found.
	TLSCertFingerprint string `json:"tls_cert_fingerprint,omitempty"`
	// PasswordHash is the root user's current /etc/shadow hash field. Empty when
	// /etc/shadow cannot be read.
	PasswordHash string `json:"password_hash,omitempty"`
}

// authorizedKeysPath is where SSH public keys are distributed (file_write),
// matching the backend's hardcoded SshKeyService.AUTHORIZED_KEYS_PATH.
const authorizedKeysPath = "/etc/dropbear/authorized_keys"

// defaultTLSCertPath is used to look up the deployed cert's fingerprint when no
// tls_cert_push has succeeded yet this session (e.g. right after a restart).
// Matches TlsCertService.DEFAULT_CERT_PATH on the backend.
const defaultTLSCertPath = "/etc/uhttpd.crt"

// installedAuthorizedKeys reads authorizedKeysPath via fw and returns one
// normalized public key string per valid line, in the form "<type> <base64blob>"
// (comment stripped). The base64 blob is validated but not decoded further.
// Malformed lines and a missing file are silently skipped/ignored.
func installedAuthorizedKeys(fw filewriter.FileAccess) []string {
	data, err := fw.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
			continue
		}
		out = append(out, fields[0]+" "+fields[1])
	}
	return out
}

// rootPasswordHash reads the root user's hash field from /etc/shadow via
// a.fileAccess. Returns "" when the file cannot be read or root has no entry.
func (a *Agent) rootPasswordHash() string {
	data, err := a.fileAccess.ReadFile("/etc/shadow")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) >= 2 && fields[0] == "root" {
			return fields[1]
		}
	}
	return ""
}

// tlsCertFingerprint returns the lowercase-hex SHA-256 of the deployed TLS
// cert file, read from the most recently pushed cert_path (or
// defaultTLSCertPath if none was pushed this session). Returns "" when the
// file cannot be read.
func (a *Agent) tlsCertFingerprint() string {
	path := a.getTLSCertPath()
	if path == "" {
		path = defaultTLSCertPath
	}
	data, err := a.fileAccess.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// AckPayload is published to device/{id}/ack after command execution.
// Keys is non-nil only for host_key_fetch acks; encoding/json base64-encodes []byte automatically.
type AckPayload struct {
	CmdID     string            `json:"cmd_id"`
	Status    string            `json:"status"`
	Output    string            `json:"output"`
	Timestamp string            `json:"timestamp"`
	Keys      map[string][]byte `json:"keys,omitempty"`
}

// ServiceInfo describes a single OpenWrt init.d service discovered on the device.
type ServiceInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Running bool   `json:"running"`
}

// InfoPayload is published to device/{id}/info every HeartbeatInterval seconds.
type InfoPayload struct {
	DeviceID          string           `json:"device_id"`
	Hostname          string           `json:"hostname"`
	UptimeSeconds     int64            `json:"uptime_seconds"`
	AgentVersion      string           `json:"agent_version"`
	Model             string           `json:"model"`
	OpenWrtVersion    string           `json:"openwrt_version"`
	Target            string           `json:"target"`
	Profile           string           `json:"profile"`
	VersionCode       string           `json:"version_code"`
	Timestamp         string           `json:"timestamp"`
	Capabilities      []string         `json:"capabilities"`
	Services          []ServiceInfo    `json:"services,omitempty"`
	InstalledPackages []ApkPackageInfo `json:"installed_packages,omitempty"`
}

// hostKeyFingerprints returns a map of filename → lowercase hex SHA-256 for each
// allowed host key file that currently exists in dir. Files that cannot be read
// (missing or permission error) are silently omitted.
func hostKeyFingerprints(allowedNames map[string]bool, dir string) map[string]string {
	out := make(map[string]string, len(allowedNames))
	for name := range allowedNames {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		out[name] = hex.EncodeToString(sum[:])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// allowedUCISubcmds is the set of UCI subcommands that uci_set is permitted to
// execute. Only these safe, non-destructive subcommands are accepted; anything
// else (e.g. "batch", "import") is rejected to prevent command injection if the
// MQTT broker is compromised or a message is replayed.
var allowedUCISubcmds = map[string]bool{
	"set":      true,
	"commit":   true,
	"revert":   true,
	"delete":   true,
	"add":      true,
	"add_list": true,
	"del_list": true,
	"get":      true,
}

// allowedHostKeyFilenamesByDaemon maps each SSH daemon to the set of host-key
// filenames it is permitted to write/remove. filepath.Base() strips directory
// components before the check to prevent path-traversal attacks.
//
// Dropbear accepts both its own binary format and OpenSSH PEM format.
// OpenSSH only uses its own PEM format — accepting Dropbear filenames would
// write files that OpenSSH ignores, which is misleading and unnecessary.
var allowedHostKeyFilenamesByDaemon = map[string]map[string]bool{
	"dropbear": {
		"dropbear_ed25519_host_key":     true,
		"dropbear_rsa_host_key":         true,
		"dropbear_ecdsa_host_key":       true,
		"dropbear_ed25519_host_key.pub": true,
		"dropbear_rsa_host_key.pub":     true,
		"dropbear_ecdsa_host_key.pub":   true,
		"ssh_host_ed25519_key":          true,
		"ssh_host_rsa_key":              true,
		"ssh_host_ecdsa_key":            true,
		"ssh_host_ed25519_key.pub":      true,
		"ssh_host_rsa_key.pub":          true,
		"ssh_host_ecdsa_key.pub":        true,
	},
	"openssh": {
		"ssh_host_ed25519_key":     true,
		"ssh_host_rsa_key":         true,
		"ssh_host_ecdsa_key":       true,
		"ssh_host_ed25519_key.pub": true,
		"ssh_host_rsa_key.pub":     true,
		"ssh_host_ecdsa_key.pub":   true,
	},
}

// fileWriteAllowedDirs is the directory allowlist for the file_write command.
// Only paths whose filepath.Clean result begins with one of these prefixes are
// accepted. This prevents a compromised or replayed MQTT message from overwriting
// arbitrary system files (e.g. /etc/shadow, /usr/bin/waverms-agent).
var fileWriteAllowedDirs = []string{
	"/etc/dropbear/",
	"/etc/ssh/",
	"/etc/waverms/",
	"/tmp/",
}

// tlsCertAllowedDirs is the directory allowlist for tls_cert_push/remove paths.
var tlsCertAllowedDirs = []string{"/etc/", "/tmp/"}

// pathHasAllowedPrefix returns true when path, after filepath.Clean, begins
// with one of prefixes.
func pathHasAllowedPrefix(path string, prefixes []string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range prefixes {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

// isFileWritePathAllowed returns true when path, after filepath.Clean, begins
// with one of the entries in fileWriteAllowedDirs.
func isFileWritePathAllowed(path string) bool {
	return pathHasAllowedPrefix(path, fileWriteAllowedDirs)
}

// supportedCapabilities is the list of command types this agent version supports.
// Append to this list whenever a new command type is implemented.
var supportedCapabilities = []string{
	"uci_set",
	"config_apply",
	"config_confirm",
	"file_write",
	"state_report",
	"host_key_restore",
	"host_key_remove",
	"host_key_fetch",
	"set_password",
	"tls_cert_push",
	"tls_cert_remove",
	"service_apply",
	"apk_report",
	"apk_manage",
	"sysupgrade",
	"log_control",
	"logs_fetch",
	"log_level_control",
}

// fallbackStatePackages is used only when /etc/config cannot be read.
var fallbackStatePackages = []string{"system", "network", "wireless", "firewall", "dhcp"}

// discoverPackages lists all regular files in /etc/config and returns them as
// UCI package names. Falls back to fallbackStatePackages on any read error.
func discoverPackages() []string {
	entries, err := os.ReadDir("/etc/config")
	if err != nil {
		return fallbackStatePackages
	}
	pkgs := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			pkgs = append(pkgs, e.Name())
		} else if e.Type()&os.ModeSymlink != 0 {
			// Some OpenWrt setups symlink UCI packages into /etc/config/.
			// We skip symlinks because os.ReadDir does not follow them and
			// resolving them safely would require extra stat calls. Log at
			// debug so operators can spot unexpected symlinks.
			slog.Debug("discoverPackages: skipping symlink in /etc/config", "name", e.Name())
		}
	}
	if len(pkgs) == 0 {
		return fallbackStatePackages
	}
	return pkgs
}

// serviceNameRe matches valid OpenWrt init.d service names: alphanumeric, dash, underscore.
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// discoverServices scans initdDir for service scripts and returns their enabled/running state.
// Best-effort: entries that cannot be checked are skipped silently.
func discoverServices(runner uci.UCIRunner, initdDir string) []ServiceInfo {
	entries, err := os.ReadDir(initdDir)
	if err != nil {
		slog.Debug("discoverServices: cannot read initd dir", "dir", initdDir, "err", err)
		return nil
	}
	var services []ServiceInfo
	for _, e := range entries {
		if !e.Type().IsRegular() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		name := e.Name()
		if !serviceNameRe.MatchString(name) {
			continue
		}
		script := initdDir + "/" + name
		_, errEnabled := runner.ExecCmd(script, "enabled")
		enabled := errEnabled == nil
		_, errRunning := runner.ExecCmd(script, "running")
		running := errRunning == nil
		services = append(services, ServiceInfo{Name: name, Enabled: enabled, Running: running})
	}
	return services
}

// Options holds all dependencies for the Agent.
type Options struct {
	Config         *config.Config
	Creds          *config.Credentials
	MAC            string
	Model          string
	OpenWrtVersion string
	Target         string
	Profile        string
	VersionCode    string
	MQTT           mqttclient.MQTTClient
	UCI            uci.UCIRunner
	Version        string
	// FileAccess is used to read/write files on the device filesystem. Defaults to OSFileAccess.
	FileAccess filewriter.FileAccess
	// PasswordSetter is used to set system user passwords. Defaults to OSPasswordSetter.
	PasswordSetter PasswordSetter
	// FirmwareDownloader downloads firmware images. Defaults to HTTPFirmwareDownloader.
	FirmwareDownloader FirmwareDownloader
	// SysupgradeRunner tests and executes sysupgrade. Defaults to OSSysupgradeRunner.
	SysupgradeRunner SysupgradeRunner
	// DiskSpaceChecker reports available disk space. Defaults to StatfsDiskSpaceChecker.
	DiskSpaceChecker DiskSpaceChecker
	// BootstrapOpts overrides the default bootstrap options (useful in tests).
	BootstrapOpts *bootstrap.Options
	// BootstrapTokenPath is used if BootstrapOpts is nil. Defaults to /etc/waverms/bootstrap_token.
	BootstrapTokenPath string
	// BootstrapTokenWaitTimeout is how long the agent waits for the token file to
	// appear before giving up. Defaults to 120 s, which covers slow DHCP on embedded
	// links. Set to 0 to disable waiting (fail immediately if token is absent).
	BootstrapTokenWaitTimeout time.Duration
	// CredsPath is where credentials are stored. Defaults to /etc/waverms/credentials.
	CredsPath string
	// SSHDaemon overrides the SSH daemon detection (useful in tests). Defaults to detectSSHDaemon().
	SSHDaemon *sshDaemonInfo
	// InitdDir is the path scanned for available services. Defaults to /etc/init.d.
	InitdDir string
	// CleanStartSentinelPath is checked at startup; if present the first MQTT
	// connect uses CleanStart=true to discard broker-queued messages left over
	// from a sysupgrade. Defaults to /etc/config/waverms-agent-clean-start.
	CleanStartSentinelPath string
	// AckRetryDelay is the pause between ack publish retry attempts (useful in
	// tests). Defaults to 5 s.
	AckRetryDelay time.Duration
	// ActivityLog persists agent log records to a local file across reboots.
	// Constructed once in main.go (the only place that should perform the
	// real file I/O — see the nil-safe fallback in New() below) and reused
	// here so bootstrap-phase and session-phase log lines land in the same
	// file. Nil if the file could not be opened at startup, or in tests.
	ActivityLog *ActivityLogHandler
	// LogLevel is the shared slog.LevelVar backing every handler in main.go's
	// chain. handleLogLevelControl mutates it at runtime in response to the
	// log-level/control MQTT topic. Nil in tests that don't care about dynamic
	// level control — handleLogLevelControl no-ops in that case.
	LogLevel *slog.LevelVar
}

// Agent is the main runtime component.
type Agent struct {
	cfg                *config.Config
	creds              *config.Credentials
	mac                string
	model              string
	openwrtVersion     string
	target             string
	profile            string
	versionCode        string
	mqtt               mqttclient.MQTTClient
	uci                uci.UCIRunner
	fileAccess         filewriter.FileAccess
	passwordSetter     PasswordSetter
	firmwareDownloader FirmwareDownloader
	sysupgradeRunner   SysupgradeRunner
	diskSpaceChecker   DiskSpaceChecker
	version            string
	sshDaemon          sshDaemonInfo
	initdDir           string

	bootstrapTokenPath        string
	bootstrapTokenWaitTimeout time.Duration
	credsPath                 string
	liveLogsHandler           *mqttLiveLogsHandler
	activityLog               *ActivityLogHandler
	logLevel                  *slog.LevelVar
	cmdHandlers               map[string]func(Command)
	ackRetryDelay             time.Duration

	// sessionMu protects sessionDisconnCh, which is set for the lifetime of
	// each MQTT session and read by the config_apply connectivity watchdog.
	sessionMu        sync.RWMutex
	sessionDisconnCh <-chan struct{}

	// pendingAckMu protects pendingAck, which holds a deferred ACK that must
	// be sent on the next session start after a config_apply rollback.
	pendingAckMu sync.Mutex
	pendingAck   *rollbackAck

	// confirmMu protects the active watchdog confirm channel.
	// When a config_apply watchdog is running, confirmCmdID and confirmCh are
	// set. handleConfigConfirm closes confirmCh to cut the watchdog short.
	confirmMu    sync.Mutex
	confirmCmdID string
	confirmCh    chan struct{}

	// tlsCertMu protects tlsCertPath and tlsKeyPath — the paths of the most
	// recently successful tls_cert_push this session. Used by tlsCertFingerprint
	// to know which file to read, and by tls_cert_remove to know what to delete.
	tlsCertMu   sync.RWMutex
	tlsCertPath string
	tlsKeyPath  string

	// watchdogActive is set while a config_apply connectivity watchdog is
	// running. The reconnect loop uses this to bypass exponential backoff so
	// the device reconnects quickly after a network-interface restart caused
	// by the apply, giving the watchdog the best chance to observe the new
	// session within its 2-minute window.
	watchdogActive atomic.Bool

	// cleanStartSentinelPath is the file written before sysupgrade so the first
	// post-reboot connect can use CleanStart=true to discard re-delivered commands.
	cleanStartSentinelPath string
	// needsCleanStart is true for the first connect after a sysupgrade reboot.
	needsCleanStart atomic.Bool
}

func (a *Agent) setTLSCertPaths(certPath, keyPath string) {
	a.tlsCertMu.Lock()
	a.tlsCertPath = certPath
	a.tlsKeyPath = keyPath
	a.tlsCertMu.Unlock()
}

// setTLSCertPath is kept for use by tests that only care about the cert path.
func (a *Agent) setTLSCertPath(path string) { a.setTLSCertPaths(path, "") }

func (a *Agent) getTLSCertPath() string {
	a.tlsCertMu.RLock()
	defer a.tlsCertMu.RUnlock()
	return a.tlsCertPath
}

func (a *Agent) getTLSKeyPath() string {
	a.tlsCertMu.RLock()
	defer a.tlsCertMu.RUnlock()
	return a.tlsKeyPath
}

// publishStateAfterSuccess re-publishes the full state report after a command
// that mutates a state-report dimension (SSH keys, host keys, TLS cert,
// password) succeeds, so the backend can confirm the change landed without
// waiting for the next heartbeat or periodic state publish.
func (a *Agent) publishStateAfterSuccess(trigger string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.publishState(ctx, trigger, nil); err != nil {
		slog.Warn("publish state after command", "trigger", trigger, "err", err)
	}
}

// New creates an Agent from the provided options.
func New(opts *Options) *Agent {
	tokenPath := opts.BootstrapTokenPath
	if tokenPath == "" {
		tokenPath = "/etc/waverms/bootstrap_token"
	}
	tokenWait := opts.BootstrapTokenWaitTimeout
	if tokenWait == 0 {
		tokenWait = 120 * time.Second
	}
	credsPath := opts.CredsPath
	if credsPath == "" {
		credsPath = "/etc/waverms/credentials"
	}

	fw := opts.FileAccess
	if fw == nil {
		fw = &filewriter.OSFileAccess{}
	}
	ps := opts.PasswordSetter
	if ps == nil {
		ps = &OSPasswordSetter{}
	}
	fd := opts.FirmwareDownloader
	if fd == nil {
		fd = &HTTPFirmwareDownloader{}
	}
	sr := opts.SysupgradeRunner
	if sr == nil {
		sr = &OSSysupgradeRunner{}
	}
	dc := opts.DiskSpaceChecker
	if dc == nil {
		dc = &StatfsDiskSpaceChecker{}
	}

	daemon := daemonDropbear
	if opts.SSHDaemon != nil {
		daemon = *opts.SSHDaemon
	} else {
		daemon = detectSSHDaemon()
	}

	initdDir := opts.InitdDir
	if initdDir == "" {
		initdDir = "/etc/init.d"
	}

	sentinelPath := opts.CleanStartSentinelPath
	if sentinelPath == "" {
		sentinelPath = "/etc/config/waverms-agent-clean-start"
	}

	ackRetryDelay := opts.AckRetryDelay
	if ackRetryDelay == 0 {
		ackRetryDelay = defaultAckRetryDelay
	}

	a := &Agent{
		cfg:                       opts.Config,
		creds:                     opts.Creds,
		mac:                       opts.MAC,
		model:                     opts.Model,
		openwrtVersion:            opts.OpenWrtVersion,
		target:                    opts.Target,
		profile:                   opts.Profile,
		versionCode:               opts.VersionCode,
		mqtt:                      opts.MQTT,
		uci:                       opts.UCI,
		fileAccess:                fw,
		passwordSetter:            ps,
		firmwareDownloader:        fd,
		sysupgradeRunner:          sr,
		diskSpaceChecker:          dc,
		version:                   opts.Version,
		sshDaemon:                 daemon,
		initdDir:                  initdDir,
		bootstrapTokenPath:        tokenPath,
		bootstrapTokenWaitTimeout: tokenWait,
		credsPath:                 credsPath,
		activityLog:               opts.ActivityLog,
		logLevel:                  opts.LogLevel,
		cleanStartSentinelPath:    sentinelPath,
		ackRetryDelay:             ackRetryDelay,
	}

	// If the sentinel file exists from a prior sysupgrade, request a clean
	// broker session on the first connect to discard re-delivered commands.
	if _, err := os.Stat(sentinelPath); err == nil {
		slog.Info("sysupgrade sentinel found — will use CleanStart on first connect", "path", sentinelPath)
		a.needsCleanStart.Store(true)
	}
	a.cmdHandlers = map[string]func(Command){
		"uci_set":          a.handleUCISet,
		"config_apply":     a.handleConfigApply,
		"config_confirm":   a.handleConfigConfirm,
		"file_write":       a.handleFileWrite,
		"host_key_restore": a.handleHostKeyRestore,
		"host_key_remove":  a.handleHostKeyRemove,
		"host_key_fetch":   a.handleHostKeyFetch,
		"set_password":     a.handleSetPassword,
		"tls_cert_push":    a.handleTlsCertPush,
		"tls_cert_remove":  a.handleTlsCertRemove,
		"service_apply":    a.handleServiceApply,
		"apk_report":       a.handleApkReport,
		"apk_manage":       a.handleApkManage,
		"sysupgrade":       a.handleSysupgrade,
		"log_control":      a.handleLogControl,
		"logs_fetch":       a.handleLogsFetch,
	}
	return a
}

func (a *Agent) setWatchdogConfirm(cmdID string, ch chan struct{}) {
	a.confirmMu.Lock()
	a.confirmCmdID = cmdID
	a.confirmCh = ch
	a.confirmMu.Unlock()
}

func (a *Agent) clearWatchdogConfirm(cmdID string) {
	a.confirmMu.Lock()
	if a.confirmCmdID == cmdID {
		a.confirmCmdID = ""
		a.confirmCh = nil
	}
	a.confirmMu.Unlock()
}

// isDuplicateConfigApply reports whether cmdID matches the config_apply
// currently tracked by an in-flight connectivity watchdog.
//
// The broker redelivers an un-acked QoS-1 command whenever the session drops
// before the client's ack for it round-trips — exactly what a config_apply
// that restarts networking tends to trigger. Without this guard the agent
// would reprocess the same apply from scratch on redelivery: a second
// backup+reload+watchdog racing the still-running original, which can
// observe no session yet at its own start and roll back a change that was
// never actually in trouble.
func (a *Agent) isDuplicateConfigApply(cmdID string) bool {
	a.confirmMu.Lock()
	defer a.confirmMu.Unlock()
	return a.confirmCmdID == cmdID
}

// signalWatchdogConfirm closes the stored confirm channel if cmdID matches the
// active watchdog. Returns true when the signal was delivered.
func (a *Agent) signalWatchdogConfirm(cmdID string) bool {
	a.confirmMu.Lock()
	defer a.confirmMu.Unlock()
	if a.confirmCmdID == cmdID {
		close(a.confirmCh)
		a.confirmCh = nil
		a.confirmCmdID = ""
		return true
	}
	return false
}

// handleConfigConfirm is dispatched when the server sends a config_confirm
// command referencing an in-flight config_apply. It signals the connectivity
// watchdog to confirm the apply immediately instead of waiting for the timeout.
func (a *Agent) handleConfigConfirm(cmd Command) {
	if !a.signalWatchdogConfirm(cmd.CmdID) {
		slog.Warn("config_confirm: no active watchdog", "cmd_id", cmd.CmdID)
	}
}

func (a *Agent) setSessionDisconnCh(ch <-chan struct{}) {
	a.sessionMu.Lock()
	a.sessionDisconnCh = ch
	a.sessionMu.Unlock()
}

func (a *Agent) getSessionDisconnCh() <-chan struct{} {
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	return a.sessionDisconnCh
}

func (a *Agent) setPendingRollbackAck(ack *rollbackAck) {
	a.pendingAckMu.Lock()
	a.pendingAck = ack
	a.pendingAckMu.Unlock()
}

// takePendingRollbackAck atomically reads and clears the pending rollback ACK.
func (a *Agent) takePendingRollbackAck() *rollbackAck {
	a.pendingAckMu.Lock()
	defer a.pendingAckMu.Unlock()
	ack := a.pendingAck
	a.pendingAck = nil
	return ack
}

// Run is the main entry point. It bootstraps if needed, then enters the
// reconnect loop. It returns nil when ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if !a.creds.HasCredentials() {
		bopts := bootstrap.Options{
			TokenPath:        a.bootstrapTokenPath,
			CredsPath:        a.credsPath,
			TokenWaitTimeout: a.bootstrapTokenWaitTimeout,
			MAC:              a.mac,
			Model:            a.model,
			OpenWrtVersion:   a.openwrtVersion,
			AgentVersion:     a.version,
			Target:           a.target,
			Profile:          a.profile,
			VersionCode:      a.versionCode,
		}
		// Retry bootstrap with exponential backoff so transient DNS / network
		// failures at startup (e.g. dnsmasq not ready yet) don't crash the
		// process and exhaust procd's respawn limit.
		bDelay := 5 * time.Second
		const bMaxDelay = 5 * time.Minute
		var resp *bootstrap.BootstrapResponse
		for {
			var err error
			resp, err = bootstrap.Run(ctx, a.cfg, bopts, a.mqtt)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			slog.Info("bootstrap failed, retrying", "err", err, "delay", bDelay)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(bDelay):
			}
			bDelay = min(bDelay*2, bMaxDelay)
		}
		// Bootstrap uses the shared MQTT client for its temporary connection.
		// Disconnect it explicitly now so the TCP socket is released before
		// runSession opens a new session with the permanent device credentials.
		a.mqtt.Disconnect()

		// Reload credentials from the just-written file.
		creds, err := config.LoadCredentials(a.credsPath)
		if err != nil {
			return fmt.Errorf("load credentials after bootstrap: %w", err)
		}
		a.creds = creds
		// Update broker host/port if the server provided overrides.
		if resp.BrokerHost != "" {
			a.cfg.BrokerHost = resp.BrokerHost
		}
		if resp.BrokerPort > 0 {
			a.cfg.BrokerPort = resp.BrokerPort
		}

		// Force CleanStart=true on the very next connect, independent of the
		// sysupgrade sentinel below. The backend looks up devices by MAC on
		// bootstrap/register, so a device that just re-bootstrapped (e.g. after a
		// keep_config=false sysupgrade, which wipes /etc/waverms/ including
		// credentials, but NOT the backend's device record) gets back the SAME
		// device.id — and therefore the same MQTT ClientID — it had before. A
		// keep_config=false sysupgrade never writes the sentinel (below) because
		// it also wipes wherever that sentinel would live, so without this, the
		// broker resumes the pre-flash persistent session and immediately
		// redelivers the still-queued, un-acked sysupgrade command that caused
		// this reboot in the first place — flashing again, forever, until the
		// agent is disabled. A fresh bootstrap has no meaningful prior session to
		// resume regardless of whether it's truly the device's first connect ever
		// or a re-enrollment, so CleanStart=true is always correct here.
		a.needsCleanStart.Store(true)
	}

	// Replace the global slog default with the MQTT-aware live-logs handler now that we
	// have credentials. If main.go constructed a persistent ActivityLogHandler, reuse
	// it here so bootstrap-phase and session-phase log lines land in the same file
	// (and so the file is only ever opened by main.go — see the ActivityLog doc
	// comment on Options, and the nil branch below, which must stay pure in-memory
	// so tests that build an Agent directly via New() never touch the real filesystem).
	//
	// This branch is only actually reached in tests: in production a.activityLog is
	// always non-nil (set by main.go), so innerHandler below reuses its handler chain
	// — which already shares a.logLevel via main.go's HandlerOptions — without needing
	// a fresh HandlerOptions here at all.
	var localLevel slog.Leveler = slog.LevelInfo
	if a.logLevel != nil {
		localLevel = a.logLevel
	} else if a.cfg.Debug {
		localLevel = slog.LevelDebug
	}
	var innerHandler slog.Handler
	if a.activityLog != nil {
		innerHandler = a.activityLog
	} else {
		innerHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: localLevel})
	}
	a.liveLogsHandler = newMQTTLiveLogsHandler(innerHandler, a.mqtt, a.creds.DeviceID)
	slog.SetDefault(slog.New(a.liveLogsHandler))
	log.SetFlags(0) // TextHandler owns timestamps; avoid double prefix on log.Printf calls

	delay := time.Second
	maxDelay := 300 * time.Second
	// A session that stays connected longer than this threshold is considered
	// healthy; on disconnect the backoff resets so the next reconnect is fast.
	const sessionHealthyThreshold = 30 * time.Second

	for {
		sessionStart := time.Now()
		err := a.runSession(ctx)
		if ctx.Err() != nil {
			return nil
		}
		// Reset the backoff delay when the session ran long enough to be
		// considered stable. Without this, a device that reconnects after days
		// of uptime would wait up to 300 s before its first reconnect attempt.
		if time.Since(sessionStart) >= sessionHealthyThreshold {
			delay = time.Second
		}
		// During a config_apply watchdog, reconnect immediately (1 s) so the
		// device gets back online within the 2-minute watchdog window even when
		// the normal backoff delay has grown large (up to 5 min). The backoff
		// state is not updated during this fast path so it resumes normally once
		// the watchdog phase ends.
		if a.watchdogActive.Load() {
			slog.Info("session ended during config_apply watchdog, reconnecting without backoff", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		slog.Info("session ended, reconnecting", "err", err, "delay", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay = min(delay*2, maxDelay)
	}
}

// runSession connects the device credentials, subscribes to the command topic,
// sends an initial heartbeat, and then drives the heartbeat loop until the
// connection is lost or ctx is cancelled.
func (a *Agent) runSession(ctx context.Context) error {
	slog.Debug("connecting", "host", a.cfg.BrokerHost, "port", a.cfg.BrokerPort, "client_id", a.creds.DeviceID)

	lwt := &mqttclient.LWT{
		Topic:   mqttclient.TopicStatus(a.creds.DeviceID),
		Payload: []byte("offline"),
		QoS:     1,
		Retain:  true,
	}

	cleanStart := a.needsCleanStart.CompareAndSwap(true, false)
	connOpts := mqttclient.ConnectOptions{
		BrokerHost: a.cfg.BrokerHost,
		BrokerPort: a.cfg.BrokerPort,
		ClientID:   a.creds.DeviceID,
		Username:   a.creds.DeviceID,
		Password:   a.creds.Secret,
		LWT:        lwt,
		CleanStart: cleanStart,
	}

	if err := a.mqtt.Connect(ctx, connOpts); err != nil {
		// Restore the flag so the next attempt also requests a clean session.
		if cleanStart {
			a.needsCleanStart.Store(true)
		}
		return fmt.Errorf("connect: %w", err)
	}
	if cleanStart {
		slog.Info("clean-start connect succeeded, removing sysupgrade sentinel")
		_ = os.Remove(a.cleanStartSentinelPath)
	}
	slog.Debug("connected", "client_id", a.creds.DeviceID)

	// subscribeOrDisconnect subscribes and disconnects (releasing the TCP fd)
	// if the subscription fails, so that the next reconnect attempt starts clean.
	subscribeOrDisconnect := func(topic string, qos byte, handler mqttclient.MessageHandler) error {
		if err := a.mqtt.Subscribe(ctx, topic, qos, handler); err != nil {
			a.mqtt.Disconnect()
			return err
		}
		return nil
	}

	cmdTopic := mqttclient.TopicCommand(a.creds.DeviceID)
	if err := subscribeOrDisconnect(cmdTopic, 1, a.handleCommand); err != nil {
		return fmt.Errorf("subscribe cmd: %w", err)
	}
	slog.Debug("subscribed", "topic", cmdTopic)

	stateReqTopic := mqttclient.TopicStateRequest(a.creds.DeviceID)
	if err := subscribeOrDisconnect(stateReqTopic, 1, a.handleStateRequest); err != nil {
		return fmt.Errorf("subscribe state/request: %w", err)
	}
	slog.Debug("subscribed", "topic", stateReqTopic)

	infoReqTopic := mqttclient.TopicInfoRequest(a.creds.DeviceID)
	if err := subscribeOrDisconnect(infoReqTopic, 1, a.handleInfoRequest); err != nil {
		return fmt.Errorf("subscribe info/request: %w", err)
	}
	slog.Debug("subscribed", "topic", infoReqTopic)

	controlTopic := mqttclient.TopicLiveLogsControl(a.creds.DeviceID)
	if err := subscribeOrDisconnect(controlTopic, 1, a.handleLiveLogsControl); err != nil {
		return fmt.Errorf("subscribe live-logs/control: %w", err)
	}
	slog.Debug("subscribed", "topic", controlTopic)

	logLevelTopic := mqttclient.TopicLogLevelControl(a.creds.DeviceID)
	if err := subscribeOrDisconnect(logLevelTopic, 1, a.handleLogLevelControl); err != nil {
		return fmt.Errorf("subscribe log-level/control: %w", err)
	}
	slog.Debug("subscribed", "topic", logLevelTopic)

	// Clear the retained "offline" LWT so a restarting server does not receive a
	// stale offline status for a device that is actually online.
	if err := a.mqtt.Publish(ctx, mqttclient.TopicStatus(a.creds.DeviceID), []byte{}, 1, true); err != nil {
		slog.Warn("failed to clear retained status", "err", err)
	}

	// Send a deferred rollback ACK before the connect-triggered state report. The
	// backend marks the dimension apply_failed on this ACK; sending it first means
	// the upcoming state report (which still reflects the rolled-back config) lands
	// against an already-apply_failed status instead of re-triggering an immediate
	// redeploy of the config that just failed.
	if ack := a.takePendingRollbackAck(); ack != nil {
		a.publishAck(ack.cmdID, ack.status, ack.output)
	}

	if err := a.publishInfo(ctx); err != nil {
		slog.Error("initial heartbeat failed", "err", err)
	}

	if err := a.publishState(ctx, "connect", nil); err != nil {
		slog.Error("initial state publish failed", "err", err)
	}

	heartbeatInterval := time.Duration(a.cfg.HeartbeatInterval) * time.Second
	if heartbeatInterval <= 0 {
		heartbeatInterval = 60 * time.Second
	}
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	stateInterval := time.Duration(a.cfg.StateInterval) * time.Second
	if stateInterval <= 0 {
		stateInterval = 10 * time.Minute
	}
	stateTicker := time.NewTicker(stateInterval)
	defer stateTicker.Stop()

	disconnCh := a.mqtt.Disconnected()
	a.setSessionDisconnCh(disconnCh)
	defer a.setSessionDisconnCh(nil)

	for {
		select {
		case <-ctx.Done():
			a.mqtt.Disconnect()
			return nil
		case <-disconnCh:
			if reason := a.mqtt.DisconnectReason(); reason != nil {
				return fmt.Errorf("connection lost: %w", reason)
			}
			return fmt.Errorf("connection lost")
		case <-ticker.C:
			if err := a.publishInfo(ctx); err != nil {
				slog.Error("heartbeat failed", "err", err)
			}
			// Safety net: send a rollback ACK that was set after session start
			// (e.g. when the rollback goroutine races with a fast reconnect).
			if ack := a.takePendingRollbackAck(); ack != nil {
				a.publishAck(ack.cmdID, ack.status, ack.output)
			}
		case <-stateTicker.C:
			if err := a.publishState(ctx, "periodic", nil); err != nil {
				slog.Error("periodic state publish failed", "err", err)
			}
		}
	}
}

// publishInfo sends the current device status to device/{id}/info.
func (a *Agent) publishInfo(ctx context.Context) error {
	hostname := readHostname()
	uptime := readUptimeSeconds()
	slog.Debug("publishing heartbeat", "hostname", hostname, "uptime_seconds", uptime)

	caps := append(supportedCapabilities, "ssh_daemon:"+a.sshDaemon.Name)
	services := discoverServices(a.uci, a.initdDir)
	pkgs := a.installedPackages()
	info := InfoPayload{
		DeviceID:          a.creds.DeviceID,
		Hostname:          hostname,
		UptimeSeconds:     uptime,
		AgentVersion:      a.version,
		Model:             a.model,
		OpenWrtVersion:    a.openwrtVersion,
		Target:            a.target,
		Profile:           a.profile,
		VersionCode:       a.versionCode,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Capabilities:      caps,
		Services:          services,
		InstalledPackages: pkgs,
	}

	payload, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal info: %w", err)
	}

	return a.mqtt.Publish(ctx, mqttclient.TopicInfo(a.creds.DeviceID), payload, 1, false)
}

// handleCommand processes an incoming ad-hoc command.
func (a *Agent) handleCommand(topic string, payload []byte) {
	var cmd Command
	if err := json.Unmarshal(payload, &cmd); err != nil {
		slog.Error("invalid command payload", "topic", topic, "err", err)
		return
	}
	slog.Debug("received command", "cmd_id", cmd.CmdID, "type", cmd.Type)

	handler, ok := a.cmdHandlers[cmd.Type]
	if !ok {
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("unknown command type: %s", cmd.Type))
		return
	}
	handler(cmd)
}

// ackPublishAttempts bounds how often an ack publish is tried. A lost ack leaves
// the backend command unacknowledged until its timeout scheduler marks the
// dimension apply_failed even though the command succeeded on-device, so acks
// are worth a few attempts. Bounded so a dead session cannot block the handler
// for long — reconnects are the session watchdog's job. Worst case
// (attempts × 10 s publish timeout + delays) stays well inside the backend's
// 5-minute command timeout, so a retried ack still lands in time.
const (
	ackPublishAttempts   = 3
	defaultAckRetryDelay = 5 * time.Second
)

// publishAck sends the command acknowledgement to device/{id}/ack.
func (a *Agent) publishAck(cmdID, status, output string) {
	slog.Debug("publishing ack", "cmd_id", cmdID, "status", status)
	ack := AckPayload{
		CmdID:     cmdID,
		Status:    status,
		Output:    output,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	a.publishAckPayload(cmdID, ack)
}

// publishAckKeys publishes an ACK_OK carrying the fetched host key map (host_key_fetch).
func (a *Agent) publishAckKeys(cmdID string, keys map[string][]byte) {
	slog.Debug("publishing ack keys", "cmd_id", cmdID, "files", len(keys))
	ack := AckPayload{
		CmdID:     cmdID,
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Keys:      keys,
	}
	a.publishAckPayload(cmdID, ack)
}

// publishAckPayload marshals ack and publishes it to device/{id}/ack, retrying
// up to ackPublishAttempts times with a.ackRetryDelay between attempts.
func (a *Agent) publishAckPayload(cmdID string, ack AckPayload) {
	payload, err := json.Marshal(ack)
	if err != nil {
		slog.Error("marshal ack", "cmd_id", cmdID, "err", err)
		return
	}
	topic := mqttclient.TopicAck(a.creds.DeviceID)
	for attempt := 1; attempt <= ackPublishAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = a.mqtt.Publish(ctx, topic, payload, 1, false)
		cancel()
		if err == nil {
			if attempt > 1 {
				slog.Info("publish ack succeeded after retry", "cmd_id", cmdID, "attempt", attempt)
			}
			return
		}
		if attempt < ackPublishAttempts {
			slog.Warn("publish ack failed, retrying", "cmd_id", cmdID, "attempt", attempt, "err", err)
			time.Sleep(a.ackRetryDelay)
		}
	}
	slog.Error("publish ack failed, giving up", "cmd_id", cmdID, "attempts", ackPublishAttempts, "err", err)
}

// handleInfoRequest processes an incoming info/request message by publishing a fresh heartbeat.
func (a *Agent) handleInfoRequest(_ string, _ []byte) {
	slog.Debug("info request received — publishing fresh heartbeat")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.publishInfo(ctx); err != nil {
		slog.Error("publish info on request", "err", err)
	}
}

// handleStateRequest processes an incoming state/request message.
func (a *Agent) handleStateRequest(topic string, payload []byte) {
	var req StateRequestPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		slog.Error("invalid state/request payload", "topic", topic, "err", err)
		return
	}
	slog.Debug("state request received", "packages", req.Packages)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.publishState(ctx, "request", req.Packages); err != nil {
		slog.Error("publish state on request", "err", err)
	}
}

// handleLiveLogsControl toggles MQTT live log streaming at runtime.
// The server publishes {"enabled": true|false} to device/{id}/live-logs/control (retain: true).
func (a *Agent) handleLiveLogsControl(_ string, payload []byte) {
	var msg struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		slog.Error("invalid live-logs/control payload", "err", err)
		return
	}
	if a.liveLogsHandler != nil {
		a.liveLogsHandler.SetEnabled(msg.Enabled)
	}
}

// handleLogLevelControl processes an incoming log-level/control message by
// raising or lowering the agent's baseline slog level at runtime — no restart
// needed. Unlike handleLiveLogsControl (which only affects what's streamed
// live), this changes what's written to the persistent activity log file too,
// since a.logLevel is the same LevelVar every handler in main.go's chain reads
// from. The retained MQTT topic re-delivers the last value on every
// (re)subscribe, so the setting survives an agent restart without the agent
// ever needing to persist it to disk itself.
func (a *Agent) handleLogLevelControl(_ string, payload []byte) {
	var msg struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		slog.Error("invalid log-level/control payload", "err", err)
		return
	}
	if a.logLevel == nil {
		return
	}
	if msg.Enabled {
		a.logLevel.Set(slog.LevelDebug)
	} else {
		a.logLevel.Set(slog.LevelInfo)
	}
	slog.Info("log level updated via log-level/control", "debug_enabled", msg.Enabled)
}

// publishState collects UCI state for the given packages and publishes it
// to device/{id}/state. If pkgs is empty, defaultStatePackages is used.
// Packages that fail to export are skipped and logged.
func (a *Agent) publishState(ctx context.Context, trigger string, pkgs []string) error {
	if len(pkgs) == 0 {
		pkgs = discoverPackages()
	}
	slog.Debug("publishing state", "trigger", trigger, "packages", pkgs)

	packages := make(map[string]map[string][]map[string]interface{})
	rawFiles := make(map[string]string)
	for _, pkg := range pkgs {
		out, err := a.uci.Export(pkg)
		if err != nil {
			slog.Warn("uci export failed, skipping", "package", pkg, "err", err)
			continue
		}
		sections, err := uci.ParseUCIExport(out)
		if err != nil {
			slog.Warn("uci export parse failed, skipping", "package", pkg, "err", err)
			continue
		}
		if len(sections) > 0 {
			packages[pkg] = sections
		}
		if raw, readErr := os.ReadFile("/etc/config/" + pkg); readErr == nil {
			rawFiles[pkg] = string(raw)
		}
	}

	state := StatePayload{
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		Trigger:             trigger,
		Packages:            packages,
		RawFiles:            rawFiles,
		AuthorizedKeys:      installedAuthorizedKeys(a.fileAccess),
		HostKeyFingerprints: hostKeyFingerprints(allowedHostKeyFilenamesByDaemon[a.sshDaemon.Name], a.sshDaemon.Dir),
		TLSCertFingerprint:  a.tlsCertFingerprint(),
		PasswordHash:        a.rootPasswordHash(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return a.mqtt.Publish(ctx, mqttclient.TopicState(a.creds.DeviceID), data, 1, false)
}

// readHostname reads the kernel hostname from /proc/sys/kernel/hostname.
// Returns "unknown" on any error.
func readHostname() string {
	data, err := os.ReadFile("/proc/sys/kernel/hostname")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// readUptimeSeconds reads the system uptime from /proc/uptime.
// Returns 0 on any error.
func readUptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return 0
	}
	var secs float64
	fmt.Sscanf(parts[0], "%f", &secs)
	return int64(secs)
}
