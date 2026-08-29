package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// ubusWatchDefaultInterval is used when a ubus_watch payload omits (or sends a
// non-positive) interval_seconds.
const ubusWatchDefaultInterval = 30 * time.Second

// watchKey identifies one standing ubus_watch goroutine in a.watches — see
// makeWatchKey for how it's resolved.
type watchKey string

// makeWatchKey resolves the registry key for one ubus_watch registration: the
// caller-supplied WatchID when present (stable across re-dispatch — the
// backend re-sends ubus_watch every report cycle for the life of the watch,
// so the id must stay the same across calls or the agent's dedup below would
// treat every re-dispatch as a brand-new watch), or a synthetic
// "legacy:<object>.<method>" key for callers (or already-in-flight commands)
// that don't supply one — preserving the original dedup-by-(object,method)
// contract exactly. Two distinct WatchIDs targeting the same (object,
// method) now run two independent polling goroutines rather than sharing
// one — a deliberate tradeoff (duplicate `ubus call` traffic, bounded by the
// number of distinct declared watches, not fleet size) in exchange for
// unwatch/push-correlation that's exact per registration instead of per ubus
// target — see docs/plugins.md "Watch/listen ids".
func makeWatchKey(watchID, object, method string) watchKey {
	if watchID != "" {
		return watchKey(watchID)
	}
	return watchKey("legacy:" + object + "." + method)
}

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
	// WatchID is a caller-assigned, stable-across-re-dispatch identifier —
	// see makeWatchKey. Optional: omitted, dedup falls back to (object,
	// method) exactly as before this field existed.
	WatchID string `json:"watch_id,omitempty"`
}

// UbusUnwatchPayload is the inner payload for type "ubus_unwatch".
type UbusUnwatchPayload struct {
	Object  string `json:"object"`
	Method  string `json:"method"`
	WatchID string `json:"watch_id,omitempty"`
}

// ubusStatusPayload is the wire shape published to device/{id}/ubus-status —
// see runUbusWatch.
type ubusStatusPayload struct {
	Object  string          `json:"object"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	WatchID string          `json:"watch_id,omitempty"`
}

// handleUbusWatch starts a standing ubus watch, or no-ops if one for the same
// key is already running — see makeWatchKey's dedup contract.
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
	key := makeWatchKey(payload.WatchID, payload.Object, payload.Method)

	stop, alreadyWatching := startOrNoop(&a.watchesMu, a.watches, key)
	if alreadyWatching {
		slog.Debug("ubus_watch: already watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "watch_id", payload.WatchID)
		a.publishAck(cmd.CmdID, "ok", "")
		return
	}

	slog.Info("ubus_watch: starting", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "interval", interval, "watch_id", payload.WatchID)
	go a.runUbusWatch(key, payload.WatchID, payload.Object, payload.Method, payload.Params, interval, stop)
	a.publishAck(cmd.CmdID, "ok", "")
}

// handleUbusUnwatch stops a standing ubus watch. Idempotent — unwatching a
// key that isn't (or is no longer) being watched acks success, not an error.
func (a *Agent) handleUbusUnwatch(cmd Command) {
	var payload UbusUnwatchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}
	key := makeWatchKey(payload.WatchID, payload.Object, payload.Method)

	stop, found := stopKey(&a.watchesMu, a.watches, key)
	if found {
		close(stop)
		slog.Info("ubus_watch: stopped", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "watch_id", payload.WatchID)
	} else {
		slog.Debug("ubus_unwatch: not watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "watch_id", payload.WatchID)
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

// runUbusWatch re-runs `ubus call object method params` every interval —
// waiting for the PREVIOUS call to finish before scheduling the next
// (time.After, not a ticker), so a slow ubus call can never overlap with
// itself — and publishes each successful result to device/{id}/ubus-status.
// A failed call is skipped (logged, not published); the next tick retries.
// Exits when stop is closed (explicit ubus_unwatch) or the session ends,
// removing its own registry entry either way so a later ubus_watch for the
// same key starts fresh rather than seeing a stale no-op.
func (a *Agent) runUbusWatch(key watchKey, watchID, object, method string, params json.RawMessage, interval time.Duration, stop chan struct{}) {
	defer cleanupOwnEntry(&a.watchesMu, a.watches, key, stop)

	disconnCh := a.getSessionDisconnCh()
	for {
		select {
		case <-stop:
			return
		case <-disconnCh:
			return
		case <-time.After(interval):
		}

		result, err := runUbusCall(a.uci, object, method, params)
		if err != nil {
			slog.Debug("ubus_watch: call failed, skipping tick", "object", object, "method", method, "err", err)
			continue
		}

		payload, err := json.Marshal(ubusStatusPayload{Object: object, Method: method, Result: json.RawMessage(result), WatchID: watchID})
		if err != nil {
			// A malformed ubus result (or, in principle, a marshal failure)
			// fails safely here rather than publishing broken JSON — the next
			// tick retries, same tolerance as a failed ubus call above.
			slog.Error("ubus_watch: marshal payload failed, skipping tick", "object", object, "method", method, "err", err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := a.mqtt.Publish(ctx, mqttclient.TopicUbusStatus(a.creds.DeviceID), payload, 1, false); err != nil {
			slog.Error("ubus_watch: publish failed", "object", object, "method", method, "err", err)
		}
		cancel()
	}
}
