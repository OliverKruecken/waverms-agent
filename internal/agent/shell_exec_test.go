package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func TestClampShellExecTimeout(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		want    time.Duration
	}{
		{"zero defaults to 30s", 0, shellExecDefaultTimeout},
		{"within bounds passes through", 45, 45 * time.Second},
		{"below min clamps up", -5, shellExecMinTimeout},
		{"above max clamps down", 9999, shellExecMaxTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampShellExecTimeout(tt.seconds)
			if got != tt.want {
				t.Errorf("clampShellExecTimeout(%d) = %v, want %v", tt.seconds, got, tt.want)
			}
		})
	}
}

func TestHandleShellExec_Success(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"shell echo hello": "hello",
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-shell-1",
		Type:    "shell_exec",
		Payload: []byte(`{"command":"echo hello"}`),
	}
	a.handleShellExec(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]

	var ack struct {
		CmdID    string `json:"cmd_id"`
		Status   string `json:"status"`
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.CmdID != "test-cmd-shell-1" {
		t.Errorf("cmd_id = %q, want %q", ack.CmdID, "test-cmd-shell-1")
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if ack.Output != "hello" {
		t.Errorf("output = %q, want %q", ack.Output, "hello")
	}
	if ack.ExitCode != 0 {
		t.Errorf("exit_code = %d, want 0", ack.ExitCode)
	}
	if len(mock.Calls) != 1 || mock.Calls[0] != "shell echo hello" {
		t.Errorf("unexpected calls recorded: %+v", mock.Calls)
	}
}

func TestHandleShellExec_NonZeroExitStillReturnsOutput(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"shell exit 3": "some output before failing",
		},
		ExitCodes: map[string]int{
			"shell exit 3": 3,
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-shell-2",
		Type:    "shell_exec",
		Payload: []byte(`{"command":"exit 3"}`),
	}
	a.handleShellExec(cmd)

	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status   string `json:"status"`
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("status = %q, want error", ack.Status)
	}
	if ack.ExitCode != 3 {
		t.Errorf("exit_code = %d, want 3", ack.ExitCode)
	}
	if ack.Output != "some output before failing" {
		t.Errorf("output = %q, want output preserved on non-zero exit", ack.Output)
	}
}

func TestHandleShellExec_EmptyCommandRejectedWithoutExec(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-shell-empty",
		Type:    "shell_exec",
		Payload: []byte(`{"command":""}`),
	}
	a.handleShellExec(cmd)

	if len(mock.Calls) != 0 {
		t.Errorf("expected no ExecShell calls for empty command, got %+v", mock.Calls)
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("status = %q, want error", ack.Status)
	}
}

func TestHandleShellExec_InvalidPayloadRejectedWithoutExec(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-shell-badjson",
		Type:    "shell_exec",
		Payload: []byte(`not-json`),
	}
	a.handleShellExec(cmd)

	if len(mock.Calls) != 0 {
		t.Errorf("expected no ExecShell calls for undecodable payload, got %+v", mock.Calls)
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("status = %q, want error", ack.Status)
	}
}

func TestHandleShellExec_ExecFailure(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"shell bogus-command": &mockExecError{"sh: bogus-command: not found"},
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-shell-execfail",
		Type:    "shell_exec",
		Payload: []byte(`{"command":"bogus-command"}`),
	}
	a.handleShellExec(cmd)

	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("status = %q, want error", ack.Status)
	}
	if ack.Output == "" {
		t.Error("expected non-empty output/error text on exec failure")
	}
}

func TestPublishInfo_CapabilitiesContainShellExec(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	if err := a.publishInfo(context.Background()); err != nil {
		t.Fatalf("publishInfo: %v", err)
	}

	var info InfoPayload
	if err := json.Unmarshal(mqttMock.Published[0].Payload, &info); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}
	found := false
	for _, c := range info.Capabilities {
		if c == "shell_exec" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capabilities to contain shell_exec, got %+v", info.Capabilities)
	}
}
