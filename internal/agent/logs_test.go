package agent

import (
	"encoding/json"
	"testing"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func TestParseUbusLogOutput(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []LogEntry
		wantErr bool
	}{
		{
			name: "well-formed entries",
			raw: `{"log":[
				{"msg":"boot complete","id":1,"priority":6,"source":0,"time":1690891234123},
				{"msg":"kernel panic averted","id":2,"priority":3,"source":1,"time":1690891235456}
			]}`,
			want: []LogEntry{
				{Time: 1690891234123, Priority: 6, Source: 0, Msg: "boot complete"},
				{Time: 1690891235456, Priority: 3, Source: 1, Msg: "kernel panic averted"},
			},
		},
		{
			name: "empty log array",
			raw:  `{"log":[]}`,
			want: nil,
		},
		{
			name:    "malformed json",
			raw:     `not-json`,
			wantErr: true,
		},
		{
			name: "missing time field defaults to zero",
			raw:  `{"log":[{"msg":"no timestamp","id":3,"priority":7,"source":0}]}`,
			want: []LogEntry{
				{Time: 0, Priority: 7, Source: 0, Msg: "no timestamp"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUbusLogOutput(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseUbusLogOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHandleLogsFetch(t *testing.T) {
	const logOutput = `{"log":[{"msg":"hello world","id":1,"priority":6,"source":0,"time":1690891234123}]}`

	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call log read {"lines":200,"stream":false}`: logOutput,
		},
	}

	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-logs-1",
		Type:    "logs_fetch",
		Payload: []byte(`{"lines":200}`),
	}
	a.handleLogsFetch(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]

	var ack struct {
		CmdID   string     `json:"cmd_id"`
		Status  string     `json:"status"`
		Entries []LogEntry `json:"log_entries"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.CmdID != "test-cmd-logs-1" {
		t.Errorf("cmd_id = %q, want %q", ack.CmdID, "test-cmd-logs-1")
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if len(ack.Entries) != 1 || ack.Entries[0].Msg != "hello world" {
		t.Errorf("expected one log entry with msg 'hello world', got %+v", ack.Entries)
	}
}

func TestHandleLogsFetch_DefaultsLinesWhenOmitted(t *testing.T) {
	const logOutput = `{"log":[]}`

	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call log read {"lines":200,"stream":false}`: logOutput,
		},
	}

	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-logs-2",
		Type:    "logs_fetch",
		Payload: []byte(`{}`),
	}
	a.handleLogsFetch(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok (default lines=200 should be used)", ack.Status)
	}
}

func TestHandleLogsFetch_InvalidLines(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-logs-3",
		Type:    "logs_fetch",
		Payload: []byte(`{"lines":5000}`),
	}
	a.handleLogsFetch(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("expected error status for out-of-range lines, got %q", ack.Status)
	}
}

func TestHandleLogsFetch_UbusFailure(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			`cmd ubus call log read {"lines":200,"stream":false}`: &mockExecError{"ubus: object not found"},
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-logs-4",
		Type:    "logs_fetch",
		Payload: []byte(`{}`),
	}
	a.handleLogsFetch(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("expected error status when ubus call fails, got %q", ack.Status)
	}
}

type mockExecError struct{ msg string }

func (e *mockExecError) Error() string { return e.msg }
