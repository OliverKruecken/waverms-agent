package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFakeUbus creates a fake `ubus` binary on $PATH for the duration of the
// test, running script as its body. No real device/ubus binary is ever
// required to run this suite.
func writeFakeUbus(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ubus")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake ubus: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRealUbusListenStarter_LinesArriveInOrder(t *testing.T) {
	writeFakeUbus(t, `
echo '{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }'
echo '{ "assoc": {"address":"aa:bb:cc:dd:ee:02"} }'
`)

	s := &RealUbusListenStarter{}
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
	writeFakeUbus(t, `
echo '{ "assoc": {} }'
sleep 30
`)

	s := &RealUbusListenStarter{}
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

	s := &RealUbusListenStarter{}
	_, err := s.Start(context.Background(), "assoc")
	if err == nil {
		t.Fatal("expected an error when the ubus binary cannot be found")
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
