package agent

import (
	"context"
	"encoding/json"
	"testing"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func TestRunUbusCall_BuildsCorrectArgv(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call usteer.wlan0 client_list {"foo":"bar"}`: `{"clients":{}}`,
		},
	}

	out, err := runUbusCall(mock, "usteer.wlan0", "client_list", json.RawMessage(`{"foo":"bar"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != `{"clients":{}}` {
		t.Errorf("out = %q, want %q", out, `{"clients":{}}`)
	}
	if len(mock.Calls) != 1 || mock.Calls[0] != `cmd ubus call usteer.wlan0 client_list {"foo":"bar"}` {
		t.Errorf("unexpected calls recorded: %+v", mock.Calls)
	}
}

func TestRunUbusCall_DefaultsEmptyParamsToEmptyObject(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call system board {}`: `{"model":"generic"}`,
		},
	}

	out, err := runUbusCall(mock, "system", "board", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != `{"model":"generic"}` {
		t.Errorf("out = %q, want %q", out, `{"model":"generic"}`)
	}
	if len(mock.Calls) != 1 || mock.Calls[0] != `cmd ubus call system board {}` {
		t.Errorf("unexpected calls recorded: %+v", mock.Calls)
	}
}

func TestHandleUbusCall_Success(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call usteer.wlan0 client_list {}`: `{"clients":{"aa:bb":{}}}`,
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-ubus-1",
		Type:    "ubus_call",
		Payload: []byte(`{"object":"usteer.wlan0","method":"client_list"}`),
	}
	a.handleUbusCall(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]

	var ack struct {
		CmdID  string          `json:"cmd_id"`
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.CmdID != "test-cmd-ubus-1" {
		t.Errorf("cmd_id = %q, want %q", ack.CmdID, "test-cmd-ubus-1")
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if string(ack.Result) != `{"clients":{"aa:bb":{}}}` {
		t.Errorf("result = %q, want raw passthrough of ubus output", string(ack.Result))
	}
}

func TestHandleUbusCall_WithParams(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call usteer.wlan0 client_list {"address":"aa:bb:cc:dd:ee:ff"}`: `{"signal":-42}`,
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-ubus-2",
		Type:    "ubus_call",
		Payload: []byte(`{"object":"usteer.wlan0","method":"client_list","params":{"address":"aa:bb:cc:dd:ee:ff"}}`),
	}
	a.handleUbusCall(cmd)

	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string          `json:"status"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if string(ack.Result) != `{"signal":-42}` {
		t.Errorf("result = %q, want %q", string(ack.Result), `{"signal":-42}`)
	}
}

func TestHandleUbusCall_UbusFailure(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			`cmd ubus call bogus.object method {}`: &mockExecError{"ubus: object not found"},
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-ubus-3",
		Type:    "ubus_call",
		Payload: []byte(`{"object":"bogus.object","method":"method"}`),
	}
	a.handleUbusCall(cmd)

	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string          `json:"status"`
		Output string          `json:"output"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("status = %q, want error", ack.Status)
	}
	if ack.Output == "" {
		t.Error("expected non-empty output/error text on ubus failure")
	}
	if ack.Result != nil {
		t.Errorf("expected no result on failure, got %q", string(ack.Result))
	}
}

func TestHandleUbusCall_InvalidObjectRejectedWithoutExec(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"space in object", `{"object":"foo bar","method":"list"}`},
		{"semicolon in object", `{"object":"foo;rm -rf /","method":"list"}`},
		{"quote in object", `{"object":"foo\"bar","method":"list"}`},
		{"space in method", `{"object":"system","method":"bad method"}`},
		{"semicolon in method", `{"object":"system","method":"list;evil"}`},
		{"empty object", `{"object":"","method":"list"}`},
		{"empty method", `{"object":"system","method":""}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &uci.MockUCIRunner{}
			mqttMock := mqttclient.NewMockMQTTClient()
			a := newTestAgent(mqttMock, mock)

			cmd := Command{
				CmdID:   "test-cmd-ubus-invalid",
				Type:    "ubus_call",
				Payload: []byte(tt.payload),
			}
			a.handleUbusCall(cmd)

			if len(mock.Calls) != 0 {
				t.Errorf("expected no ExecCmd calls for invalid input, got %+v", mock.Calls)
			}

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
				t.Errorf("status = %q, want error", ack.Status)
			}
		})
	}
}

func TestHandleUbusCall_InvalidPayloadRejectedWithoutExec(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-ubus-badjson",
		Type:    "ubus_call",
		Payload: []byte(`not-json`),
	}
	a.handleUbusCall(cmd)

	if len(mock.Calls) != 0 {
		t.Errorf("expected no ExecCmd calls for undecodable payload, got %+v", mock.Calls)
	}
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
		t.Errorf("status = %q, want error", ack.Status)
	}
}

func TestPublishInfo_CapabilitiesContainUbusCall(t *testing.T) {
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
		if c == "ubus_call" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capabilities to contain ubus_call, got %+v", info.Capabilities)
	}
}
