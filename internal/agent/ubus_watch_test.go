package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

const prefixWatchPayload = `{"object_prefix":"hostapd.","methods":["get_status","get_clients"],"interval_seconds":3600,"watch_id":"%s"}`

func prefixWatchCmd(cmdID, watchID string) Command {
	return Command{CmdID: cmdID, Type: "ubus_watch", Payload: []byte(fmt.Sprintf(prefixWatchPayload, watchID))}
}

func TestHandleUbusWatch_PrefixStartsWatchKeyedByWatchID(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(prefixWatchCmd("w1", "core:wifi-clients"))
	t.Cleanup(func() { close(a.watches[watchKey("core:wifi-clients")]) })

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	a.watchesMu.Lock()
	_, watching := a.watches[watchKey("core:wifi-clients")]
	a.watchesMu.Unlock()
	if !watching {
		t.Error("expected a registered watch keyed by the watch_id")
	}
}

func TestHandleUbusWatch_PrefixWithoutWatchIDUsesLegacyPrefixKey(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(Command{CmdID: "w1", Type: "ubus_watch", Payload: []byte(`{"object_prefix":"hostapd.","methods":["get_status"],"interval_seconds":3600}`)})
	t.Cleanup(func() { close(a.watches[makePrefixWatchKey("", "hostapd.")]) })

	a.watchesMu.Lock()
	_, watching := a.watches[watchKey("legacy:hostapd.*")]
	a.watchesMu.Unlock()
	if !watching {
		t.Error("expected the legacy fallback key legacy:hostapd.*")
	}
}

func TestHandleUbusWatch_PrefixAlreadyWatchingIsNoOp(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(prefixWatchCmd("w1", "core:wifi-clients"))
	a.watchesMu.Lock()
	firstStop := a.watches[watchKey("core:wifi-clients")]
	a.watchesMu.Unlock()
	t.Cleanup(func() { close(firstStop) })

	a.handleUbusWatch(prefixWatchCmd("w2", "core:wifi-clients"))

	if status := lastAckStatus(mqttMock); status != "ok" {
		t.Errorf("status = %q, want ok (idempotent no-op)", status)
	}
	a.watchesMu.Lock()
	secondStop := a.watches[watchKey("core:wifi-clients")]
	count := len(a.watches)
	a.watchesMu.Unlock()
	if count != 1 || secondStop != firstStop {
		t.Errorf("expected the re-dispatch to reuse the one watch, got %d watches / same stop = %v", count, secondStop == firstStop)
	}
}

func TestHandleUbusWatch_PrefixRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"prefix without methods", `{"object_prefix":"hostapd."}`},
		{"methods without prefix", `{"methods":["get_status"]}`},
		{"prefix mixed with object", `{"object":"usteer","object_prefix":"hostapd.","methods":["get_status"]}`},
		{"prefix mixed with method", `{"method":"list","object_prefix":"hostapd.","methods":["get_status"]}`},
		{"wildcard in prefix", `{"object_prefix":"hostapd.*","methods":["get_status"]}`},
		{"space in prefix", `{"object_prefix":"host apd.","methods":["get_status"]}`},
		{"semicolon in method", `{"object_prefix":"hostapd.","methods":["get_status;evil"]}`},
		{"empty method", `{"object_prefix":"hostapd.","methods":[""]}`},
		{"too many methods", `{"object_prefix":"hostapd.","methods":["a","b","c","d","e","f","g","h","i"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mqttMock := mqttclient.NewMockMQTTClient()
			a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

			a.handleUbusWatch(Command{CmdID: "bad", Type: "ubus_watch", Payload: []byte(tt.payload)})

			if status := lastAckStatus(mqttMock); status != "error" {
				t.Errorf("status = %q, want error", status)
			}
			a.watchesMu.Lock()
			count := len(a.watches)
			a.watchesMu.Unlock()
			if count != 0 {
				t.Errorf("expected no watch to be registered, got %d", count)
			}
		})
	}
}

func TestHandleUbusUnwatch_PrefixWatchesRunIndependentlyAndStopByWatchIDAlone(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(prefixWatchCmd("w1", "core:wifi-clients"))
	a.handleUbusWatch(prefixWatchCmd("w2", "core:wifi-clients:live"))
	a.watchesMu.Lock()
	baselineStop := a.watches[watchKey("core:wifi-clients")]
	count := len(a.watches)
	a.watchesMu.Unlock()
	t.Cleanup(func() { close(baselineStop) })
	if count != 2 {
		t.Fatalf("expected two independent watches for two watch ids, got %d", count)
	}

	// No object/method/object_prefix — the watch_id alone identifies the watch.
	a.handleUbusUnwatch(Command{CmdID: "u1", Type: "ubus_unwatch", Payload: []byte(`{"watch_id":"core:wifi-clients:live"}`)})

	a.watchesMu.Lock()
	_, liveWatching := a.watches[watchKey("core:wifi-clients:live")]
	_, baselineWatching := a.watches[watchKey("core:wifi-clients")]
	a.watchesMu.Unlock()
	if liveWatching {
		t.Error("expected the live watch to be stopped")
	}
	if !baselineWatching {
		t.Error("expected the baseline watch to keep running")
	}
}

func TestHandleUbusUnwatch_PrefixLegacyKeyStopsWatch(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(Command{CmdID: "w1", Type: "ubus_watch", Payload: []byte(`{"object_prefix":"hostapd.","methods":["get_status"],"interval_seconds":3600}`)})
	a.handleUbusUnwatch(Command{CmdID: "u1", Type: "ubus_unwatch", Payload: []byte(`{"object_prefix":"hostapd."}`)})

	a.watchesMu.Lock()
	count := len(a.watches)
	a.watchesMu.Unlock()
	if count != 0 {
		t.Errorf("expected the legacy-keyed prefix watch to be stopped, got %d watches", count)
	}
}

// runPrefixWatchFor runs a prefix watch at a 5ms interval for ~30ms and returns
// what it published.
func runPrefixWatchFor(t *testing.T, mock *uci.MockUCIRunner) []mqttclient.PublishedMsg {
	t.Helper()
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	key := makePrefixWatchKey("core:wifi-clients", "hostapd.")
	stop := make(chan struct{})
	go a.runUbusPrefixWatch(key, "core:wifi-clients", "hostapd.", []string{"get_status", "get_clients"}, nil, 5*time.Millisecond, stop)
	time.Sleep(30 * time.Millisecond)
	close(stop)
	time.Sleep(5 * time.Millisecond) // let the deferred registry cleanup run

	return mqttMock.PublishedSnapshot()
}

type prefixStatusBody struct {
	ObjectPrefix string                                `json:"object_prefix"`
	Results      map[string]map[string]json.RawMessage `json:"results"`
	WatchID      string                                `json:"watch_id"`
}

func decodePrefixStatus(t *testing.T, m mqttclient.PublishedMsg) prefixStatusBody {
	t.Helper()
	if m.Topic != "device/test-device-uuid/ubus-status" {
		t.Errorf("topic = %q, want device/test-device-uuid/ubus-status", m.Topic)
	}
	var body prefixStatusBody
	if err := json.Unmarshal(m.Payload, &body); err != nil {
		t.Fatalf("unmarshal published payload: %v", err)
	}
	return body
}

func TestRunUbusPrefixWatch_PublishesOneSnapshotWithEveryObjectAndMethod(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"cmd ubus list": "hostapd\nhostapd-auth\nhostapd.phy0-ap0\nhostapd.phy1-ap0\nnetwork.interface.lan\n",
			"cmd ubus call hostapd.phy0-ap0 get_status {}":      `{"ssid":"Home","freq":2412}`,
			"cmd ubus call hostapd.phy0-ap0 get_clients {}":     `{"freq":2412,"clients":{"aa:bb:cc:dd:ee:01":{"signal":-60}}}`,
			"cmd ubus call hostapd.phy1-ap0 get_status {}":      `{"ssid":"Home","freq":5180}`,
			"cmd ubus call hostapd.phy1-ap0 get_clients {}":     `{"freq":5180,"clients":{}}`,
			"cmd ubus call network.interface.lan get_status {}": `{"must":"not be called"}`,
		},
	}

	msgs := runPrefixWatchFor(t, mock)
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 published ticks, got %d", len(msgs))
	}
	body := decodePrefixStatus(t, msgs[0])
	if body.ObjectPrefix != "hostapd." || body.WatchID != "core:wifi-clients" {
		t.Errorf("object_prefix/watch_id = %q/%q, want hostapd./core:wifi-clients", body.ObjectPrefix, body.WatchID)
	}
	if len(body.Results) != 2 {
		t.Fatalf("expected exactly the two hostapd.* objects, got %v", body.Results)
	}
	if got := string(body.Results["hostapd.phy0-ap0"]["get_status"]); got != `{"ssid":"Home","freq":2412}` {
		t.Errorf("phy0-ap0 get_status = %q, want raw passthrough", got)
	}
	if got := string(body.Results["hostapd.phy0-ap0"]["get_clients"]); got != `{"freq":2412,"clients":{"aa:bb:cc:dd:ee:01":{"signal":-60}}}` {
		t.Errorf("phy0-ap0 get_clients = %q, want raw passthrough", got)
	}
	if _, ok := body.Results["hostapd.phy1-ap0"]["get_clients"]; !ok {
		t.Error("expected phy1-ap0 get_clients in the same snapshot")
	}
}

func TestRunUbusPrefixWatch_NoMatchingObjectStillPublishesEmptyResults(t *testing.T) {
	mock := &uci.MockUCIRunner{Results: map[string]string{"cmd ubus list": "network.interface.lan\nsystem\n"}}

	msgs := runPrefixWatchFor(t, mock)
	if len(msgs) == 0 {
		t.Fatal("expected a published tick even with no matching object")
	}
	if payload := string(msgs[0].Payload); !strings.Contains(payload, `"results":{}`) {
		t.Errorf("payload = %s, want an empty (not null/omitted) results map", payload)
	}
}

func TestRunUbusPrefixWatch_FailedCallLeavesOnlyThatMethodOut(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"cmd ubus list": "hostapd.phy0-ap0\nhostapd.phy1-ap0\n",
			"cmd ubus call hostapd.phy0-ap0 get_status {}":  `{"ssid":"Home"}`,
			"cmd ubus call hostapd.phy1-ap0 get_status {}":  "not json",
			"cmd ubus call hostapd.phy1-ap0 get_clients {}": `{"clients":{}}`,
		},
		Errors: map[string]error{
			"cmd ubus call hostapd.phy0-ap0 get_clients {}": &mockExecError{"ubus: command failed"},
		},
	}

	msgs := runPrefixWatchFor(t, mock)
	if len(msgs) == 0 {
		t.Fatal("expected published ticks")
	}
	body := decodePrefixStatus(t, msgs[0])
	if _, ok := body.Results["hostapd.phy0-ap0"]["get_status"]; !ok {
		t.Error("expected phy0-ap0 get_status to survive its sibling's failure")
	}
	if _, ok := body.Results["hostapd.phy0-ap0"]["get_clients"]; ok {
		t.Error("expected the failed phy0-ap0 get_clients to be left out")
	}
	if _, ok := body.Results["hostapd.phy1-ap0"]["get_status"]; ok {
		t.Error("expected phy1-ap0's non-JSON get_status to be left out")
	}
	if _, ok := body.Results["hostapd.phy1-ap0"]["get_clients"]; !ok {
		t.Error("expected phy1-ap0 get_clients to be kept")
	}
}

func TestRunUbusPrefixWatch_ObjectWithNoSuccessfulCallIsOmitted(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{"cmd ubus list": "hostapd.phy0-ap0\n"},
		Errors: map[string]error{
			"cmd ubus call hostapd.phy0-ap0 get_status {}":  &mockExecError{"gone"},
			"cmd ubus call hostapd.phy0-ap0 get_clients {}": &mockExecError{"gone"},
		},
	}

	msgs := runPrefixWatchFor(t, mock)
	if len(msgs) == 0 {
		t.Fatal("expected published ticks")
	}
	if body := decodePrefixStatus(t, msgs[0]); len(body.Results) != 0 {
		t.Errorf("results = %v, want the object left out entirely", body.Results)
	}
}

func TestRunUbusPrefixWatch_FailedListSkipsTickWithoutPublishing(t *testing.T) {
	mock := &uci.MockUCIRunner{Errors: map[string]error{"cmd ubus list": &mockExecError{"ubus: connection failed"}}}

	if msgs := runPrefixWatchFor(t, mock); len(msgs) != 0 {
		t.Errorf("expected no published ticks when object discovery fails, got %d", len(msgs))
	}
}

func TestRunUbusPrefixWatch_RemovesItsOwnRegistryEntryOnStop(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	a.handleUbusWatch(prefixWatchCmd("w1", "core:wifi-clients"))
	a.handleUbusUnwatch(Command{CmdID: "u1", Type: "ubus_unwatch", Payload: []byte(`{"watch_id":"core:wifi-clients"}`)})
	time.Sleep(5 * time.Millisecond) // let the goroutine's deferred cleanup run

	a.watchesMu.Lock()
	count := len(a.watches)
	a.watchesMu.Unlock()
	if count != 0 {
		t.Errorf("expected an empty registry after unwatch, got %d", count)
	}
}

func TestPublishInfo_CapabilitiesContainUbusWatchPrefix(t *testing.T) {
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, &uci.MockUCIRunner{})

	if err := a.publishInfo(context.Background()); err != nil {
		t.Fatalf("publishInfo: %v", err)
	}

	var info InfoPayload
	if err := json.Unmarshal(mqttMock.Published[0].Payload, &info); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}
	for _, c := range info.Capabilities {
		if c == "ubus_watch_prefix" {
			return
		}
	}
	t.Errorf("expected capabilities to contain ubus_watch_prefix, got %+v", info.Capabilities)
}
