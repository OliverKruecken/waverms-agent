package agent

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"syscall"
)

// UbusListenProcess is a running `ubus listen <event>` subprocess. Unlike
// every other ubus interaction in this agent (a single buffered request →
// response via UCIRunner.ExecCmd), `ubus listen` never exits on its own — it
// streams one JSON line per received event until killed. This is the first
// genuinely long-lived subprocess primitive in the codebase; kept as its own
// narrow interface (rather than folded into UCIRunner) following this
// agent's convention of one small interface per handler — see
// FileTransferDownloader in file_transfer.go for the same pattern.
type UbusListenProcess interface {
	// Lines delivers one raw JSON line per received ubus event, in order.
	// Closed when the process exits for any reason (Stop() or a crash) —
	// range over it to detect that without a separate "done" signal.
	Lines() <-chan string
	// Wait blocks until the subprocess has fully exited and returns its exit
	// error — nil if Stop() caused the exit, non-nil otherwise (crash, killed
	// externally, ubus binary missing, etc.). Safe to call any time; typically
	// called after Lines() has been drained/closed.
	Wait() error
	// Stop kills the subprocess if still running. Idempotent.
	Stop()
}

// UbusListenStarter starts a new UbusListenProcess for one ubus event type.
type UbusListenStarter interface {
	Start(ctx context.Context, eventType string) (UbusListenProcess, error)
}

// RealUbusListenStarter runs `ubus listen <eventType>` via os/exec — the
// production UbusListenStarter.
type RealUbusListenStarter struct{}

func (s *RealUbusListenStarter) Start(ctx context.Context, eventType string) (UbusListenProcess, error) {
	cmd := exec.CommandContext(ctx, "ubus", "listen", eventType)
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
// pipe — hostapd assoc events are infrequent enough that a full 16-entry
// buffer should never happen in practice, but the pipe must never stall.
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
// Tests drive a specific started process via StartedProcesses[i], pushing
// synthetic lines onto it and closing it (with an injected exit error) to
// simulate a crash.
type MockUbusListenStarter struct {
	StartCalls       []string // eventType per call, in order
	StartErr         error
	StartedProcesses []*MockUbusListenProcess
}

func (m *MockUbusListenStarter) Start(_ context.Context, eventType string) (UbusListenProcess, error) {
	m.StartCalls = append(m.StartCalls, eventType)
	if m.StartErr != nil {
		return nil, m.StartErr
	}
	p := &MockUbusListenProcess{lines: make(chan string, 16), done: make(chan struct{})}
	m.StartedProcesses = append(m.StartedProcesses, p)
	return p, nil
}

// MockUbusListenProcess is a synthetic UbusListenProcess driven by tests.
type MockUbusListenProcess struct {
	lines   chan string
	done    chan struct{}
	exitErr error
	Stopped bool
}

func (p *MockUbusListenProcess) Lines() <-chan string { return p.lines }

func (p *MockUbusListenProcess) Wait() error {
	<-p.done
	return p.exitErr
}

func (p *MockUbusListenProcess) Stop() {
	p.Stopped = true
	p.SimulateExit(nil)
}

// Push feeds one synthetic ubus JSON line, as if `ubus listen` had received it.
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
