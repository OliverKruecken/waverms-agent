package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/config"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func newUbusListenTestAgent(mqttMock *mqttclient.MockMQTTClient, starter *MockUbusListenStarter) *Agent {
	return New(&Options{
		Config:            &config.Config{BrokerHost: "broker.local", BrokerPort: 8883, HeartbeatInterval: 60},
		Creds:             &config.Credentials{DeviceID: "test-device-uuid", Secret: "test-secret"},
		MAC:               "aa:bb:cc:dd:ee:ff",
		MQTT:              mqttMock,
		UCI:               &uci.MockUCIRunner{},
		UbusListenStarter: starter,
		Version:           "1.0.0",
		SSHDaemon:         &daemonDropbear,
		AckRetryDelay:     time.Millisecond,
	})
}

func TestHandleUbusListen_StartsListenAndAcksOk(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	t.Cleanup(func() { a.listensMu.Lock(); close(a.listens[makeListenKey("", "assoc")]); a.listensMu.Unlock() })

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	waitForCondition(t, func() bool { return len(starter.StartCallsSnapshot()) == 1 })
	calls := starter.StartCallsSnapshot()
	if calls[0].EventType != "assoc" {
		t.Errorf("StartCalls = %v, want exactly one call for %q", calls, "assoc")
	}
}

func TestHandleUbusListen_AlreadyListeningIsNoOp(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	a.listensMu.Lock()
	firstStop := a.listens[makeListenKey("", "assoc")]
	a.listensMu.Unlock()
	t.Cleanup(func() { close(firstStop) })

	// Re-sent for the same event — the backend does this every /state report.
	a.handleUbusListen(Command{CmdID: "l2", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op)", status)
	}
	waitForCondition(t, func() bool { return len(starter.StartCallsSnapshot()) == 1 })
	time.Sleep(20 * time.Millisecond) // give a wrongly-started second goroutine a chance to show up
	if calls := starter.StartCallsSnapshot(); len(calls) != 1 {
		t.Errorf("expected exactly one Start call, got %d: %v", len(calls), calls)
	}
}

func TestHandleUbusListen_InvalidEventRejectedWithoutStarting(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "bad", Type: "ubus_listen", Payload: []byte(`{"event":"assoc; rm -rf /"}`)})

	if status := lastAckStatus(mqttMock); status != "error" {
		t.Errorf("status = %q, want error", status)
	}
	if calls := starter.StartCallsSnapshot(); len(calls) != 0 {
		t.Errorf("expected no Start call for invalid input, got %v", calls)
	}
}

func TestHandleUbusUnlisten_StopsListenAndProcess(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 1 })

	a.handleUbusUnlisten(Command{CmdID: "u1", Type: "ubus_unlisten", Payload: []byte(`{"event":"assoc"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	a.listensMu.Lock()
	_, listening := a.listens[makeListenKey("", "assoc")]
	a.listensMu.Unlock()
	if listening {
		t.Error("expected the listen to be removed from the registry after ubus_unlisten")
	}
	// Stop() is observed by runUbusListen's goroutine asynchronously (a select on the closed
	// stop channel), so a synchronous read right after close(stop) races it — poll instead.
	waitForCondition(t, func() bool { return starter.StartedProcessesSnapshot()[0].IsStopped() })
}

func TestHandleUbusUnlisten_NotListeningIsNoOpNotError(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, &MockUbusListenStarter{})

	a.handleUbusUnlisten(Command{CmdID: "u1", Type: "ubus_unlisten", Payload: []byte(`{"event":"assoc"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op, not an error)", status)
	}
}

func TestRunUbusListen_PublishesEachLineToUbusEventTopic(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 1 })
	proc := starter.StartedProcessesSnapshot()[0]

	proc.Push(`{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }`)

	var eventMsg *mqttclient.PublishedMsg
	waitForCondition(t, func() bool {
		for _, m := range mqttMock.PublishedSnapshot() {
			if m.Topic == "device/test-device-uuid/ubus-event" {
				msg := m
				eventMsg = &msg
				return true
			}
		}
		return false
	})

	var body struct {
		Event      string          `json:"event"`
		Data       json.RawMessage `json:"data"`
		ReceivedAt string          `json:"received_at"`
	}
	if err := json.Unmarshal(eventMsg.Payload, &body); err != nil {
		t.Fatalf("unmarshal published payload: %v", err)
	}
	if body.Event != "assoc" {
		t.Errorf("event = %q, want assoc", body.Event)
	}
	if body.ReceivedAt == "" {
		t.Error("expected a non-empty received_at timestamp")
	}
	var data struct {
		Assoc struct {
			Address string `json:"address"`
		} `json:"assoc"`
	}
	if err := json.Unmarshal(body.Data, &data); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if data.Assoc.Address != "aa:bb:cc:dd:ee:01" {
		t.Errorf("address = %q, want aa:bb:cc:dd:ee:01", data.Assoc.Address)
	}

	a.listensMu.Lock()
	close(a.listens[makeListenKey("", "assoc")])
	a.listensMu.Unlock()
}

func TestRunUbusListen_FiltersOutNonMatchingEventTypes(t *testing.T) {
	// RealUbusListenStarter's stream is unfiltered — a subscription to a
	// hostapd object also yields "auth"/"probe" lines interleaved with
	// "assoc" ones. A registration for "assoc" must drop those, not forward
	// them mislabeled as assoc.
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 1 })
	proc := starter.StartedProcessesSnapshot()[0]

	proc.Push(`{ "probe": {"address":"aa:bb:cc:dd:ee:99"} }`)
	proc.Push(`{ "auth": {"address":"aa:bb:cc:dd:ee:98"} }`)
	proc.Push(`{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }`)

	waitForCondition(t, func() bool {
		for _, m := range mqttMock.PublishedSnapshot() {
			if m.Topic == "device/test-device-uuid/ubus-event" {
				return true
			}
		}
		return false
	})
	// Give any wrongly-forwarded probe/auth line a chance to also land.
	time.Sleep(20 * time.Millisecond)

	var ubusEventMsgs []mqttclient.PublishedMsg
	for _, m := range mqttMock.PublishedSnapshot() {
		if m.Topic == "device/test-device-uuid/ubus-event" {
			ubusEventMsgs = append(ubusEventMsgs, m)
		}
	}
	if len(ubusEventMsgs) != 1 {
		t.Fatalf("published %d ubus-event messages, want exactly 1 (assoc only): %+v", len(ubusEventMsgs), ubusEventMsgs)
	}
	if !bytes.Contains(ubusEventMsgs[0].Payload, []byte("aa:bb:cc:dd:ee:01")) {
		t.Errorf("published message = %s, want the assoc line's address", ubusEventMsgs[0].Payload)
	}

	a.listensMu.Lock()
	close(a.listens[makeListenKey("", "assoc")])
	a.listensMu.Unlock()
}

func TestRunUbusListen_RestartsAfterUnexpectedExit(t *testing.T) {
	orig := ubusListenBaseBackoff
	ubusListenBaseBackoff = time.Millisecond
	t.Cleanup(func() { ubusListenBaseBackoff = orig })

	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 1 })

	starter.StartedProcessesSnapshot()[0].SimulateExit(errors.New("ubusd restarted"))

	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 2 })
	if calls := starter.StartCallsSnapshot(); calls[1].EventType != "assoc" {
		t.Errorf("restart StartCalls[1] = %+v, want EventType assoc", calls[1])
	}

	a.listensMu.Lock()
	close(a.listens[makeListenKey("", "assoc")])
	a.listensMu.Unlock()
}

func TestRunUbusListen_SessionDisconnectTearsDownAndStopsProcess(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	disconnCh := make(chan struct{})
	a.setSessionDisconnCh(disconnCh)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcessesSnapshot()) == 1 })

	close(disconnCh)

	waitForCondition(t, func() bool {
		a.listensMu.Lock()
		defer a.listensMu.Unlock()
		_, listening := a.listens[makeListenKey("", "assoc")]
		return !listening
	})
	if !starter.StartedProcessesSnapshot()[0].IsStopped() {
		t.Error("expected the subprocess to be stopped on session disconnect")
	}
}

func TestPublishInfo_CapabilitiesContainUbusListen(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, &MockUbusListenStarter{})

	if err := a.publishInfo(context.Background()); err != nil {
		t.Fatalf("publishInfo: %v", err)
	}

	var info InfoPayload
	if err := json.Unmarshal(mqttMock.Published[0].Payload, &info); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}
	found := false
	for _, c := range info.Capabilities {
		if c == "ubus_listen" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capabilities to contain ubus_listen, got %+v", info.Capabilities)
	}
}

func TestUbusLineMatchesType(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"matching type", `{ "assoc": {"address":"aa:bb:cc:dd:ee:01"} }`, true},
		{"non-matching type", `{ "probe": {"address":"aa:bb:cc:dd:ee:01"} }`, false},
		{"malformed json", `not json at all`, false},
		{"empty line", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ubusLineMatchesType(tc.line, "assoc"); got != tc.want {
				t.Errorf("ubusLineMatchesType(%q, \"assoc\") = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
