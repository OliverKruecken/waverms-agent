package agent

import (
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
	t.Cleanup(func() { a.listensMu.Lock(); close(a.listens["assoc"]); a.listensMu.Unlock() })

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	waitForCondition(t, func() bool { return len(starter.StartCalls) == 1 })
	if starter.StartCalls[0] != "assoc" {
		t.Errorf("StartCalls = %v, want exactly one call for %q", starter.StartCalls, "assoc")
	}
}

func TestHandleUbusListen_AlreadyListeningIsNoOp(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	a.listensMu.Lock()
	firstStop := a.listens["assoc"]
	a.listensMu.Unlock()
	t.Cleanup(func() { close(firstStop) })

	// Re-sent for the same event — the backend does this every /state report.
	a.handleUbusListen(Command{CmdID: "l2", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op)", status)
	}
	waitForCondition(t, func() bool { return len(starter.StartCalls) == 1 })
	time.Sleep(20 * time.Millisecond) // give a wrongly-started second goroutine a chance to show up
	if len(starter.StartCalls) != 1 {
		t.Errorf("expected exactly one Start call, got %d: %v", len(starter.StartCalls), starter.StartCalls)
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
	if len(starter.StartCalls) != 0 {
		t.Errorf("expected no Start call for invalid input, got %v", starter.StartCalls)
	}
}

func TestHandleUbusUnlisten_StopsListenAndProcess(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcesses) == 1 })

	a.handleUbusUnlisten(Command{CmdID: "u1", Type: "ubus_unlisten", Payload: []byte(`{"event":"assoc"}`)})

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	a.listensMu.Lock()
	_, listening := a.listens["assoc"]
	a.listensMu.Unlock()
	if listening {
		t.Error("expected the listen to be removed from the registry after ubus_unlisten")
	}
	if !starter.StartedProcesses[0].Stopped {
		t.Error("expected the subprocess to be stopped")
	}
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
	waitForCondition(t, func() bool { return len(starter.StartedProcesses) == 1 })
	proc := starter.StartedProcesses[0]

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
	close(a.listens["assoc"])
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
	waitForCondition(t, func() bool { return len(starter.StartedProcesses) == 1 })

	starter.StartedProcesses[0].SimulateExit(errors.New("ubusd restarted"))

	waitForCondition(t, func() bool { return len(starter.StartedProcesses) == 2 })
	if starter.StartCalls[1] != "assoc" {
		t.Errorf("restart StartCalls[1] = %q, want assoc", starter.StartCalls[1])
	}

	a.listensMu.Lock()
	close(a.listens["assoc"])
	a.listensMu.Unlock()
}

func TestRunUbusListen_SessionDisconnectTearsDownAndStopsProcess(t *testing.T) {
	starter := &MockUbusListenStarter{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newUbusListenTestAgent(mqttMock, starter)

	disconnCh := make(chan struct{})
	a.setSessionDisconnCh(disconnCh)

	a.handleUbusListen(Command{CmdID: "l1", Type: "ubus_listen", Payload: []byte(`{"event":"assoc"}`)})
	waitForCondition(t, func() bool { return len(starter.StartedProcesses) == 1 })

	close(disconnCh)

	waitForCondition(t, func() bool {
		a.listensMu.Lock()
		defer a.listensMu.Unlock()
		_, listening := a.listens["assoc"]
		return !listening
	})
	if !starter.StartedProcesses[0].Stopped {
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
