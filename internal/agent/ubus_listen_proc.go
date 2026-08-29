package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// UbusListenProcess is a running `ubus subscribe <object>...` subprocess.
// Unlike every other ubus interaction in this agent (a single buffered
// request → response via UCIRunner.ExecCmd), it never exits on its own — it
// streams one JSON line per received event until killed. This is the first
// genuinely long-lived subprocess primitive in the codebase; kept as its own
// narrow interface (rather than folded into UCIRunner) following this
// agent's convention of one small interface per handler — see
// FileTransferDownloader in file_transfer.go for the same pattern.
type UbusListenProcess interface {
	// Lines delivers one raw JSON line per received ubus event, in order —
	// unfiltered, so a caller subscribed for "assoc" will also see "auth" and
	// "probe" lines on the same stream (see RealUbusListenStarter). Closed
	// when the process exits for any reason (Stop() or a crash) — range over
	// it to detect that without a separate "done" signal.
	Lines() <-chan string
	// Wait blocks until the subprocess has fully exited and returns its exit
	// error — nil if Stop() caused the exit, non-nil otherwise (crash, killed
	// externally, ubus binary missing, etc.). Safe to call any time; typically
	// called after Lines() has been drained/closed.
	Wait() error
	// Stop kills the subprocess if still running. Idempotent.
	Stop()
}

// UbusListenStarter starts a new UbusListenProcess. objectPrefix selects
// which ubus objects to subscribe to (see discoverUbusObjects); eventType is
// not used to build the subprocess's command line (see RealUbusListenStarter)
// — it exists so the caller (runUbusListen) can filter the unfiltered Lines()
// stream down to the one notify type it actually asked for.
type UbusListenStarter interface {
	Start(ctx context.Context, objectPrefix, eventType string) (UbusListenProcess, error)
}

// defaultHostapdObjectPrefix is used when a ubus_listen payload omits (or
// sends empty) object_prefix — reproduces this primitive's original,
// hardcoded hostapd-only discovery exactly. "hostapd." matches hostapd's
// per-BSS ubus objects (e.g. "hostapd.phy0-ap0"), registered one per
// configured AP interface, while excluding the two fixed top-level objects
// "hostapd" and "hostapd-auth" (too short / no dot).
const defaultHostapdObjectPrefix = "hostapd."

// RealUbusListenStarter subscribes to ubus objects matching a caller-supplied
// prefix and streams their notify events — the production UbusListenStarter.
//
// hostapd's assoc/auth/probe notifications are NOT global ubus events
// (`ubus listen <event>`, backed by `ubus_send_event`) — they are per-object
// *subscriber* notifications: `ubus_notify(ctx, &hapd->ubus.obj, type, ...)`,
// which hostapd's own source (src/ap/ubus.c) skips sending entirely unless
// `obj.has_subscribers` is true. The only way to receive them is
// `ubus subscribe <object> [<object>...]` — which, conveniently, prints the
// identical `{ "<type>": {...} }\n` line format `ubus listen` does (see
// ubus's own cli.c print_event()), so nothing downstream of Start() needed to
// change once this was corrected. This starter generalizes past hostapd by
// letting the caller supply which object-name prefix to discover and
// subscribe to (see discoverUbusObjects) instead of hardcoding it — object
// discovery via `ubus list` plus a prefix match, not a subsystem-specific
// API, so any ubus object family that emits per-object subscriber
// notifications this same way can reuse it.
//
// Subscribing to an object yields every notify type it sends — "assoc",
// "auth", and "probe" all interleaved on the same stream for hostapd, not
// just the one eventType asked for — so Lines() is intentionally unfiltered
// here; runUbusListen filters by eventType before publishing. This also
// means two concurrent ubus_listen registrations for different event types
// targeting the same object prefix would each open their own redundant
// subscription to those objects — harmless today since the backend only ever
// requests "assoc", but worth knowing if a second event type is ever added.
type RealUbusListenStarter struct {
	UCI uci.UCIRunner
}

// discoverUbusObjects runs `ubus list` and returns every object whose name
// starts with prefix, discovered fresh on each Start() so a reconfigured
// device (radio interface added/removed/renamed, or any other prefix-matched
// subsystem) is picked up on the next restart rather than needing an agent
// restart. Prefix, not a compiled pattern: OpenWrt's own ubus ACL vocabulary
// (/usr/share/rpcd/acl.d/*.json, e.g. "hostapd.*") is glob/prefix-based, not
// regex, and this primitive's original hardcoded hostapd discovery already
// reduced to nothing more than a prefix match — see docs/roaming.md.
func discoverUbusObjects(runner uci.UCIRunner, prefix string) ([]string, error) {
	out, err := runner.ExecCmd("ubus", "list")
	if err != nil {
		return nil, fmt.Errorf("ubus list: %w", err)
	}
	var objects []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			objects = append(objects, line)
		}
	}
	return objects, nil
}

func (s *RealUbusListenStarter) Start(ctx context.Context, objectPrefix, _ string) (UbusListenProcess, error) {
	objects, err := discoverUbusObjects(s.UCI, objectPrefix)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("no ubus objects found matching prefix %q", objectPrefix)
	}

	cmd := exec.CommandContext(ctx, "ubus", append([]string{"subscribe"}, objects...)...)
	// Own process group so Stop() can kill the whole tree, not just the
	// immediate child — ubus itself never forks, but this stays correct even
	// if the binary on $PATH is ever a wrapper script that does.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	p := &realUbusListenProcess{
		cmd:   cmd,
		lines: make(chan string, 16),
		done:  make(chan struct{}),
	}
	go p.pump(stdout)
	return p, nil
}

type realUbusListenProcess struct {
	cmd     *exec.Cmd
	lines   chan string
	done    chan struct{}
	waitErr error
}

// pump scans stdout line by line and forwards each to lines, then waits for
// the process to exit and closes both channels. A non-blocking send means a
// stalled consumer drops events rather than backing up ubus's own stdout
// pipe — the subscribed objects also emit "probe" notifications (one per
// nearby device's WiFi scan, far more frequent than actual assoc/roam
// events), so unlike the old single-event design this buffer can plausibly
// fill in a dense environment; a dropped line here is an acceptable loss
// (the next tick/line still arrives), but the pipe must never stall.
func (p *realUbusListenProcess) pump(stdout io.ReadCloser) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		select {
		case p.lines <- sc.Text():
		default:
			slog.Warn("ubus_listen: line channel full, dropping event")
		}
	}
	p.waitErr = p.cmd.Wait()
	close(p.lines)
	close(p.done)
}

func (p *realUbusListenProcess) Lines() <-chan string { return p.lines }

func (p *realUbusListenProcess) Wait() error {
	<-p.done
	return p.waitErr
}

func (p *realUbusListenProcess) Stop() {
	if p.cmd.Process == nil {
		return
	}
	// Negative pid targets the whole process group (see Setpgid above).
	if err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = p.cmd.Process.Kill() // fall back to killing just the direct child
	}
}

// MockUbusListenStarter is a call-recording UbusListenStarter test double —
// mirrors MockMQTTClient's ability to simulate incoming messages/disconnects.
// Tests drive a specific started process via StartedProcessesSnapshot()[i],
// pushing synthetic lines onto it and closing it (with an injected exit
// error) to simulate a crash. Start() runs in the agent's own goroutine (the
// handler dispatches it via `go`), so StartCalls/StartedProcesses are
// mutex-guarded — tests must read them through the Snapshot methods rather
// than the fields directly, or the race detector (correctly) flags a
// concurrent unsynchronized access even when timing alone would happen to
// avoid actually corrupting data.
type MockUbusListenStarter struct {
	mu               sync.Mutex
	StartCalls       []UbusListenStartCall // (objectPrefix, eventType) per call, in order
	StartErr         error
	StartedProcesses []*MockUbusListenProcess
}

// UbusListenStartCall records one call to MockUbusListenStarter.Start.
type UbusListenStartCall struct {
	ObjectPrefix string
	EventType    string
}

func (m *MockUbusListenStarter) Start(_ context.Context, objectPrefix, eventType string) (UbusListenProcess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StartCalls = append(m.StartCalls, UbusListenStartCall{ObjectPrefix: objectPrefix, EventType: eventType})
	if m.StartErr != nil {
		return nil, m.StartErr
	}
	p := &MockUbusListenProcess{lines: make(chan string, 16), done: make(chan struct{})}
	m.StartedProcesses = append(m.StartedProcesses, p)
	return p, nil
}

// StartCallsSnapshot returns a copy of the calls recorded so far.
func (m *MockUbusListenStarter) StartCallsSnapshot() []UbusListenStartCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]UbusListenStartCall, len(m.StartCalls))
	copy(out, m.StartCalls)
	return out
}

// StartedProcessesSnapshot returns a copy of the process pointers started so far.
func (m *MockUbusListenStarter) StartedProcessesSnapshot() []*MockUbusListenProcess {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*MockUbusListenProcess, len(m.StartedProcesses))
	copy(out, m.StartedProcesses)
	return out
}

// MockUbusListenProcess is a synthetic UbusListenProcess driven by tests.
type MockUbusListenProcess struct {
	lines   chan string
	done    chan struct{}
	exitErr error

	mu      sync.Mutex
	stopped bool
}

func (p *MockUbusListenProcess) Lines() <-chan string { return p.lines }

func (p *MockUbusListenProcess) Wait() error {
	<-p.done
	return p.exitErr
}

func (p *MockUbusListenProcess) Stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.SimulateExit(nil)
}

// IsStopped reports whether Stop() has been called. Stop() runs in the
// agent's own goroutine (runUbusListen's cleanup), so tests must read this
// through the method rather than a plain field.
func (p *MockUbusListenProcess) IsStopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}

// Push feeds one synthetic ubus JSON line, as if `ubus subscribe` had received it.
func (p *MockUbusListenProcess) Push(line string) { p.lines <- line }

// SimulateExit closes the process as if it exited (a crash if err != nil),
// unblocking Wait() and closing Lines(). Safe to call more than once (e.g.
// Stop() after an already-simulated crash) — subsequent calls are no-ops.
func (p *MockUbusListenProcess) SimulateExit(err error) {
	select {
	case <-p.done:
		return
	default:
	}
	p.exitErr = err
	close(p.lines)
	close(p.done)
}
