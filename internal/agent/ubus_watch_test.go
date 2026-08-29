package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func TestHandleUbusWatch_StartsWatchAndAcksOk(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "watch-1",
		Type:    "ubus_watch",
		Payload: []byte(`{"object":"usteer","method":"connected_clients","interval_seconds":3600}`),
	}
	a.handleUbusWatch(cmd)
	t.Cleanup(func() { close(a.watches[makeWatchKey("", "usteer", "connected_clients")]) })

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}

	a.watchesMu.Lock()
	_, watching := a.watches[makeWatchKey("", "usteer", "connected_clients")]
	a.watchesMu.Unlock()
	if !watching {
		t.Error("expected a registered watch for (usteer, connected_clients)")
	}
}

func TestHandleUbusWatch_AlreadyWatchingIsNoOp(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{CmdID: "watch-1", Type: "ubus_watch", Payload: []byte(`{"object":"usteer","method":"connected_clients","interval_seconds":3600}`)}
	a.handleUbusWatch(cmd)
	a.watchesMu.Lock()
	firstStop := a.watches[makeWatchKey("", "usteer", "connected_clients")]
	a.watchesMu.Unlock()
	t.Cleanup(func() { close(firstStop) })

	// Re-sent for the same (object, method) — the backend does this every report cycle.
	cmd2 := Command{CmdID: "watch-2", Type: "ubus_watch", Payload: []byte(`{"object":"usteer","method":"connected_clients","interval_seconds":3600}`)}
	a.handleUbusWatch(cmd2)

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op)", status)
	}

	a.watchesMu.Lock()
	secondStop := a.watches[makeWatchKey("", "usteer", "connected_clients")]
	count := len(a.watches)
	a.watchesMu.Unlock()
	if count != 1 {
		t.Errorf("expected exactly one registered watch, got %d", count)
	}
	if secondStop != firstStop {
		t.Error("expected the second ubus_watch to reuse the first watch's stop channel, not start a new one")
	}
}

func TestHandleUbusWatch_InvalidObjectRejectedWithoutStartingWatch(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"space in object", `{"object":"foo bar","method":"list"}`},
		{"semicolon in method", `{"object":"usteer","method":"list;evil"}`},
		{"empty object", `{"object":"","method":"list"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &uci.MockUCIRunner{}
			mqttMock := mqttclient.NewMockMQTTClient()
			a := newTestAgent(mqttMock, mock)

			a.handleUbusWatch(Command{CmdID: "bad-watch", Type: "ubus_watch", Payload: []byte(tt.payload)})

			if status := lastAckStatus(mqttMock); status != "error" {
				t.Errorf("status = %q, want error", status)
			}
			a.watchesMu.Lock()
			count := len(a.watches)
			a.watchesMu.Unlock()
			if count != 0 {
				t.Errorf("expected no watch to be registered for invalid input, got %d", count)
			}
		})
	}
}

func TestHandleUbusUnwatch_StopsWatch(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	a.handleUbusWatch(Command{CmdID: "w1", Type: "ubus_watch", Payload: []byte(`{"object":"usteer","method":"connected_clients","interval_seconds":3600}`)})
	a.handleUbusUnwatch(Command{CmdID: "u1", Type: "ubus_unwatch", Payload: []byte(`{"object":"usteer","method":"connected_clients"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}

	a.watchesMu.Lock()
	_, watching := a.watches[makeWatchKey("", "usteer", "connected_clients")]
	a.watchesMu.Unlock()
	if watching {
		t.Error("expected the watch to be removed from the registry after ubus_unwatch")
	}
}

func TestHandleUbusUnwatch_NotWatchingIsNoOpNotError(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	a.handleUbusUnwatch(Command{CmdID: "u1", Type: "ubus_unwatch", Payload: []byte(`{"object":"usteer","method":"connected_clients"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op, not an error)", status)
	}
}

func TestRunUbusWatch_PublishesOnEachTick(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call usteer connected_clients {}`: `{"hostapd.wlan0":{}}`,
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	stop := make(chan struct{})
	go a.runUbusWatch(makeWatchKey("", "usteer", "connected_clients"), "", "usteer", "connected_clients", nil, 5*time.Millisecond, stop)
	time.Sleep(35 * time.Millisecond)
	close(stop)
	time.Sleep(5 * time.Millisecond) // let the deferred registry cleanup run

	msgs := mqttMock.PublishedSnapshot()
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 published ticks in 35ms at a 5ms interval, got %d", len(msgs))
	}
	for _, m := range msgs {
		if m.Topic != "device/test-device-uuid/ubus-status" {
			t.Errorf("topic = %q, want device/test-device-uuid/ubus-status", m.Topic)
		}
		var body struct {
			Object string          `json:"object"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(m.Payload, &body); err != nil {
			t.Fatalf("unmarshal published payload: %v", err)
		}
		if body.Object != "usteer" || body.Method != "connected_clients" {
			t.Errorf("object/method = %q/%q, want usteer/connected_clients", body.Object, body.Method)
		}
		if string(body.Result) != `{"hostapd.wlan0":{}}` {
			t.Errorf("result = %q, want raw passthrough of ubus output", string(body.Result))
		}
	}

	a.watchesMu.Lock()
	_, stillRegistered := a.watches[makeWatchKey("", "usteer", "connected_clients")]
	a.watchesMu.Unlock()
	if stillRegistered {
		t.Error("expected the watch to remove its own registry entry after stopping")
	}
}

func TestRunUbusWatch_SkipsFailedCallWithoutPublishing(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			`cmd ubus call usteer connected_clients {}`: &mockExecError{"ubus: object not found"},
		},
	}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	stop := make(chan struct{})
	go a.runUbusWatch(makeWatchKey("", "usteer", "connected_clients"), "", "usteer", "connected_clients", nil, 5*time.Millisecond, stop)
	time.Sleep(20 * time.Millisecond)
	close(stop)
	time.Sleep(5 * time.Millisecond)

	if msgs := mqttMock.PublishedSnapshot(); len(msgs) != 0 {
		t.Errorf("expected no published ticks when every ubus call fails, got %d", len(msgs))
	}
}

func TestPublishInfo_CapabilitiesContainUbusWatch(t *testing.T) {
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
		if c == "ubus_watch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capabilities to contain ubus_watch, got %+v", info.Capabilities)
	}
}
