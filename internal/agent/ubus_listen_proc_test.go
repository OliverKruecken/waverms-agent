package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// writeFakeUbus creates a fake `ubus` binary on $PATH for the duration of the
// test, running script as its body. No real device/ubus binary is ever
// required to run this suite. script receives "$1" as the subcommand
// (RealUbusListenStarter now shells out to both `ubus list` and
// `ubus subscribe <objects...>`), so fakes that care which one was invoked
// should branch on it.
func writeFakeUbus(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ubus")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake ubus: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeUbusListAndSubscribe is the common fake `ubus` script body: `ubus list`
// reports one hostapd BSS object (plus a non-hostapd one, to exercise the
// discovery filter), `ubus subscribe ...` streams the given lines.
func fakeUbusListAndSubscribe(subscribeLines string) string {
	return `
case "$1" in
  list)
    echo "hostapd.phy0-ap0"
    echo "network.interface"
    ;;
  subscribe)
` + subscribeLines + `
    ;;
esac
`
}

func TestRealUbusListenStarter_LinesArriveInOrder(t *testing.T) {
	writeFakeUbus(t, fakeUbusListAndSubscribe(`
    echo '{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }'
    echo '{ "assoc": {"address":"aa:bb:cc:dd:ee:02"} }'
`))

	s := &RealUbusListenStarter{UCI: &uci.RealUCIRunner{}}
	proc, err := s.Start(context.Background(), "assoc")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	var got []string
	for line := range proc.Lines() {
		got = append(got, line)
	}
	if err := proc.Wait(); err != nil {
		t.Errorf("Wait: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(got), got)
	}
	if got[0] != `{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }` {
		t.Errorf("line 0 = %q", got[0])
	}
	if got[1] != `{ "assoc": {"address":"aa:bb:cc:dd:ee:02"} }` {
		t.Errorf("line 1 = %q", got[1])
	}
}

func TestRealUbusListenStarter_StopKillsProcessAndUnblocksWait(t *testing.T) {
	writeFakeUbus(t, fakeUbusListAndSubscribe(`
    echo '{ "assoc": {} }'
    sleep 30
`))

	s := &RealUbusListenStarter{UCI: &uci.RealUCIRunner{}}
	proc, err := s.Start(context.Background(), "assoc")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for the one line so we know the subprocess is past the sleep's
	// startup, then stop it — Stop should kill it well before the 30s sleep
	// would otherwise return.
	<-proc.Lines()

	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()

	proc.Stop()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected a non-nil exit error from a killed process")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() did not return within 5s of Stop()")
	}
}

func TestRealUbusListenStarter_StartErrorOnMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir — no ubus binary anywhere on PATH

	s := &RealUbusListenStarter{UCI: &uci.RealUCIRunner{}}
	_, err := s.Start(context.Background(), "assoc")
	if err == nil {
		t.Fatal("expected an error when the ubus binary cannot be found")
	}
}

func TestRealUbusListenStarter_StartErrorWhenNoHostapdObjects(t *testing.T) {
	// `ubus list` reports objects, but none of them are hostapd's — Start
	// should fail rather than launching `ubus subscribe` with no arguments.
	writeFakeUbus(t, `
case "$1" in
  list)
    echo "network.interface"
    echo "system"
    ;;
esac
`)

	s := &RealUbusListenStarter{UCI: &uci.RealUCIRunner{}}
	_, err := s.Start(context.Background(), "assoc")
	if err == nil {
		t.Fatal("expected an error when no hostapd ubus objects are found")
	}
}

func TestHostapdObjects_FiltersToBSSObjectsOnly(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"cmd ubus list": "hostapd\nhostapd-auth\nhostapd.phy0-ap0\nhostapd.phy0-ap1\nnetwork.interface\n",
		},
	}

	got, err := hostapdObjects(mock)
	if err != nil {
		t.Fatalf("hostapdObjects: %v", err)
	}

	want := []string{"hostapd.phy0-ap0", "hostapd.phy0-ap1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHostapdObjects_PropagatesExecError(t *testing.T) {
	boom := errors.New("boom")
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{"cmd ubus list": boom},
	}

	_, err := hostapdObjects(mock)
	if err == nil {
		t.Fatal("expected an error to propagate from ExecCmd")
	}
}

func TestMockUbusListenProcess_PushAndSimulateExit(t *testing.T) {
	p := &MockUbusListenProcess{lines: make(chan string, 4), done: make(chan struct{})}
	p.Push(`{"assoc":{}}`)

	select {
	case line := <-p.Lines():
		if line != `{"assoc":{}}` {
			t.Errorf("line = %q", line)
		}
	default:
		t.Fatal("expected a pushed line to be immediately available")
	}

	boom := errors.New("boom")
	p.SimulateExit(boom)
	if err := p.Wait(); err != boom {
		t.Errorf("Wait() = %v, want %v", err, boom)
	}
	if _, open := <-p.Lines(); open {
		t.Error("expected Lines() to be closed after SimulateExit")
	}

	// Idempotent: a second SimulateExit (e.g. via Stop() after a crash) must not panic.
	p.SimulateExit(nil)
}
