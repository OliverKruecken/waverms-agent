package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func newTestAgentWithSysupgrade(
	mock *mqttclient.MockMQTTClient,
	downloader FirmwareDownloader,
	runner SysupgradeRunner,
	checker DiskSpaceChecker,
) *Agent {
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	a.firmwareDownloader = downloader
	a.sysupgradeRunner = runner
	a.diskSpaceChecker = checker
	return a
}

func sysupgradeCmd(cmdID, url, sha256 string, sizeBytes int64, keepConfig bool) Command {
	b, _ := json.Marshal(map[string]any{
		"url":         url,
		"sha256":      sha256,
		"size_bytes":  sizeBytes,
		"version":     "23.05.3",
		"keep_config": keepConfig,
	})
	return Command{CmdID: cmdID, Type: "sysupgrade", Payload: b}
}

func lastAckStatus(mock *mqttclient.MockMQTTClient) string {
	for i := len(mock.Published) - 1; i >= 0; i-- {
		if strings.Contains(mock.Published[i].Topic, "/ack") {
			var a AckPayload
			if err := json.Unmarshal(mock.Published[i].Payload, &a); err == nil {
				return a.Status
			}
		}
	}
	return ""
}

func TestHandleSysupgrade_HappyPath(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	runner := &MockSysupgradeRunner{}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.handleSysupgrade(sysupgradeCmd("cmd-1", "http://host/fw.bin", "abc123", 5*1024*1024, true))

	if len(downloader.Calls) != 1 {
		t.Fatalf("expected 1 download call, got %d", len(downloader.Calls))
	}
	if len(runner.TestCalls) != 1 {
		t.Fatalf("expected 1 Test call, got %d", len(runner.TestCalls))
	}
	if len(runner.ExecCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(runner.ExecCalls))
	}
	if !strings.Contains(runner.ExecCalls[0], "keepConfig=true") {
		t.Errorf("expected keepConfig=true in exec call, got %s", runner.ExecCalls[0])
	}
	if got := lastAckStatus(mock); got != "started" {
		t.Errorf("expected ack status 'started', got %q", got)
	}
	_ = os.Remove(sysupgradeTmpPath)
}

func TestHandleSysupgrade_FactoryReset(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	runner := &MockSysupgradeRunner{}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.handleSysupgrade(sysupgradeCmd("cmd-2", "http://host/fw.bin", "abc123", 5*1024*1024, false))

	if len(runner.ExecCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(runner.ExecCalls))
	}
	if !strings.Contains(runner.ExecCalls[0], "keepConfig=false") {
		t.Errorf("expected keepConfig=false in exec call, got %s", runner.ExecCalls[0])
	}
	_ = os.Remove(sysupgradeTmpPath)
}

func TestHandleSysupgrade_MalformedPayload(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgentWithSysupgrade(mock, &MockFirmwareDownloader{}, &MockSysupgradeRunner{}, &MockDiskSpaceChecker{Free: 100 * 1024 * 1024})

	a.handleSysupgrade(Command{CmdID: "cmd-3", Type: "sysupgrade", Payload: json.RawMessage(`{invalid`)})

	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}

func TestHandleSysupgrade_InsufficientSpace(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	checker := &MockDiskSpaceChecker{Free: 1024} // way too small

	a := newTestAgentWithSysupgrade(mock, downloader, &MockSysupgradeRunner{}, checker)
	a.handleSysupgrade(sysupgradeCmd("cmd-4", "http://host/fw.bin", "abc", 10*1024*1024, true))

	if len(downloader.Calls) != 0 {
		t.Error("expected no download calls when disk space is insufficient")
	}
	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}

func TestHandleSysupgrade_DownloadFailure(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{Err: fmt.Errorf("connection refused")}
	runner := &MockSysupgradeRunner{}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.handleSysupgrade(sysupgradeCmd("cmd-5", "http://host/fw.bin", "abc", 5*1024*1024, true))

	if len(runner.TestCalls) != 0 {
		t.Error("expected no Test calls on download failure")
	}
	if len(runner.ExecCalls) != 0 {
		t.Error("expected no Exec calls on download failure")
	}
	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}

func TestHandleSysupgrade_TestFailure(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	runner := &MockSysupgradeRunner{TestErr: fmt.Errorf("wrong board")}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.handleSysupgrade(sysupgradeCmd("cmd-6", "http://host/fw.bin", "abc", 5*1024*1024, true))

	if len(runner.ExecCalls) != 0 {
		t.Error("expected no Exec calls when sysupgrade --test fails")
	}
	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}

func TestHandleSysupgrade_MissingURL(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	a := newTestAgentWithSysupgrade(mock, downloader, &MockSysupgradeRunner{}, &MockDiskSpaceChecker{Free: 100 * 1024 * 1024})

	payload, _ := json.Marshal(map[string]any{"sha256": "abc", "size_bytes": 1024})
	a.handleSysupgrade(Command{CmdID: "cmd-7", Type: "sysupgrade", Payload: payload})

	if len(downloader.Calls) != 0 {
		t.Error("expected no download calls with missing url")
	}
	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}

// TestHandleSysupgrade_WritesSentinelBeforeExec verifies that the clean-start
// sentinel file is written to persistent storage before syscall.Exec is called,
// so the broker-queued QoS-1 re-delivery is discarded on the next connect.
func TestHandleSysupgrade_WritesSentinelBeforeExec(t *testing.T) {
	sentinel := t.TempDir() + "/clean-start"

	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	runner := &MockSysupgradeRunner{}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.cleanStartSentinelPath = sentinel

	a.handleSysupgrade(sysupgradeCmd("cmd-8", "http://host/fw.bin", "abc123", 5*1024*1024, true))

	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("expected sentinel file to exist after sysupgrade exec, got: %v", err)
	}
}

// TestHandleSysupgrade_SentinelRemovedOnExecFailure verifies that the sentinel
// is cleaned up when sysupgrade fails to exec (nothing was actually flashed).
func TestHandleSysupgrade_SentinelRemovedOnExecFailure(t *testing.T) {
	sentinel := t.TempDir() + "/clean-start"

	mock := mqttclient.NewMockMQTTClient()
	downloader := &MockFirmwareDownloader{}
	runner := &MockSysupgradeRunner{ExecErr: fmt.Errorf("exec failed")}
	checker := &MockDiskSpaceChecker{Free: 100 * 1024 * 1024}

	a := newTestAgentWithSysupgrade(mock, downloader, runner, checker)
	a.cleanStartSentinelPath = sentinel

	a.handleSysupgrade(sysupgradeCmd("cmd-9", "http://host/fw.bin", "abc123", 5*1024*1024, true))

	if _, err := os.Stat(sentinel); err == nil {
		t.Error("expected sentinel file to be removed when sysupgrade exec fails")
	}
	if got := lastAckStatus(mock); got != "error" {
		t.Errorf("expected ack status 'error', got %q", got)
	}
}
