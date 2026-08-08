package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// ubusWatchDefaultInterval is used when a ubus_watch payload omits (or sends a
// non-positive) interval_seconds.
const ubusWatchDefaultInterval = 30 * time.Second

// watchKey identifies one ubus object/method pair. A watch is deduped by this
// key alone — deliberately not by cmd_id or any backend-assigned identifier,
// so re-sending ubus_watch for the same pair (the backend does this every
// report cycle) is a cheap no-op rather than starting a redundant goroutine.
type watchKey struct{ object, method string }

// UbusWatchPayload is the inner payload for type "ubus_watch": start (or
// confirm) a standing watch that re-runs `ubus call <object> <method>
// <params>` every interval_seconds and publishes each result to
// device/{id}/ubus-status, until a matching ubus_unwatch arrives or the
// session ends.
type UbusWatchPayload struct {
	Object          string          `json:"object"`
	Method          string          `json:"method"`
	Params          json.RawMessage `json:"params,omitempty"`
	IntervalSeconds int             `json:"interval_seconds,omitempty"`
}

// UbusUnwatchPayload is the inner payload for type "ubus_unwatch".
type UbusUnwatchPayload struct {
	Object string `json:"object"`
	Method string `json:"method"`
}

// handleUbusWatch starts a standing ubus watch, or no-ops if one for the same
// (object, method) is already running — see watchKey's dedup contract.
func (a *Agent) handleUbusWatch(cmd Command) {
	var payload UbusWatchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !ubusObjectMethodRe.MatchString(payload.Object) || !ubusObjectMethodRe.MatchString(payload.Method) {
		slog.Error("ubus_watch rejected: invalid object/method", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
		a.publishAck(cmd.CmdID, "error", "invalid object or method")
		return
	}

	interval := time.Duration(payload.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = ubusWatchDefaultInterval
	}
	key := watchKey{object: payload.Object, method: payload.Method}

	a.watchesMu.Lock()
	_, alreadyWatching := a.watches[key]
	var stop chan struct{}
	if !alreadyWatching {
		stop = make(chan struct{})
		a.watches[key] = stop
	}
	a.watchesMu.Unlock()

	if alreadyWatching {
		slog.Debug("ubus_watch: already watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
		a.publishAck(cmd.CmdID, "ok", "")
		return
	}

	slog.Info("ubus_watch: starting", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "interval", interval)
	go a.runUbusWatch(key, payload.Params, interval, stop)
	a.publishAck(cmd.CmdID, "ok", "")
}

// handleUbusUnwatch stops a standing ubus watch. Idempotent — unwatching a
// key that isn't (or is no longer) being watched acks success, not an error.
func (a *Agent) handleUbusUnwatch(cmd Command) {
	var payload UbusUnwatchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}
	key := watchKey{object: payload.Object, method: payload.Method}

	a.watchesMu.Lock()
	stop, found := a.watches[key]
	if found {
		delete(a.watches, key)
	}
	a.watchesMu.Unlock()

	if found {
		close(stop)
		slog.Info("ubus_watch: stopped", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
	} else {
		slog.Debug("ubus_unwatch: not watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

// runUbusWatch re-runs `ubus call key.object key.method params` every
// interval — waiting for the PREVIOUS call to finish before scheduling the
// next (time.After, not a ticker), so a slow ubus call can never overlap
// with itself — and publishes each successful result to device/{id}/ubus-status.
// A failed call is skipped (logged, not published); the next tick retries.
// Exits when stop is closed (explicit ubus_unwatch) or the session ends,
// removing its own registry entry either way so a later ubus_watch for the
// same key starts fresh rather than seeing a stale no-op.
func (a *Agent) runUbusWatch(key watchKey, params json.RawMessage, interval time.Duration, stop chan struct{}) {
	defer func() {
		a.watchesMu.Lock()
		if a.watches[key] == stop {
			delete(a.watches, key)
		}
		a.watchesMu.Unlock()
	}()

	disconnCh := a.getSessionDisconnCh()
	for {
		select {
		case <-stop:
			return
		case <-disconnCh:
			return
		case <-time.After(interval):
		}

		result, err := runUbusCall(a.uci, key.object, key.method, params)
		if err != nil {
			slog.Debug("ubus_watch: call failed, skipping tick", "object", key.object, "method", key.method, "err", err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		payload := fmt.Appendf(nil, `{"object":%s,"method":%s,"result":%s}`, jsonString(key.object), jsonString(key.method), result)
		if err := a.mqtt.Publish(ctx, mqttclient.TopicUbusStatus(a.creds.DeviceID), payload, 1, false); err != nil {
			slog.Error("ubus_watch: publish failed", "object", key.object, "method", key.method, "err", err)
		}
		cancel()
	}
}

// jsonString marshals a Go string to its JSON string-literal form (quoting/escaping) for building the hand-assembled ubus-status payload above.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
