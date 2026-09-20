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
	return resolveKey[watchKey](watchID, "legacy:"+object+"."+method)
}

// resolveKey resolves a standing-registration's registry key: watchID when
// present, or legacyKey (the caller's synthetic fallback) otherwise. Shared
// by makeWatchKey above and makeListenKey (ubus_listen.go) — the two differ
// only in their key type (watchKey vs plain string, both ~string) and in how
// they build their own legacyKey.
func resolveKey[K ~string](watchID, legacyKey string) K {
	if watchID != "" {
		return K(watchID)
	}
	return K(legacyKey)
}

// UbusWatchPayload is the inner payload for type "ubus_watch": start (or
// confirm) a standing watch that re-runs `ubus call <object> <method>
// <params>` every interval_seconds and publishes each result to
// device/{id}/ubus-status, until a matching ubus_unwatch arrives or the
// session ends.
//
// Two mutually exclusive shapes: object+method (one ubus call per tick), or
// object_prefix+methods (every ubus object whose name starts with the prefix,
// each called with every listed method, per tick — discovered afresh on each
// tick, so a radio interface added or removed is picked up without a
// re-dispatch). See prefixWatch.
type UbusWatchPayload struct {
	Object          string          `json:"object"`
	Method          string          `json:"method"`
	ObjectPrefix    string          `json:"object_prefix,omitempty"`
	Methods         []string        `json:"methods,omitempty"`
	Params          json.RawMessage `json:"params,omitempty"`
	IntervalSeconds int             `json:"interval_seconds,omitempty"`
	// WatchID is a caller-assigned, stable-across-re-dispatch identifier —
	// see makeWatchKey. Optional: omitted, dedup falls back to (object,
	// method) exactly as before this field existed.
	WatchID string `json:"watch_id,omitempty"`
}

// UbusUnwatchPayload is the inner payload for type "ubus_unwatch".
type UbusUnwatchPayload struct {
	Object       string `json:"object"`
	Method       string `json:"method"`
	ObjectPrefix string `json:"object_prefix,omitempty"`
	WatchID      string `json:"watch_id,omitempty"`
}

// ubusStatusPayload is the wire shape published to device/{id}/ubus-status —
// see runUbusWatch.
type ubusStatusPayload struct {
	Object  string          `json:"object"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	WatchID string          `json:"watch_id,omitempty"`
}

// ubusPrefixStatusPayload is the wire shape a prefix watch publishes to
// device/{id}/ubus-status — see runUbusPrefixWatch. Results maps each matched
// ubus object to its per-method raw ubus JSON; it is an empty (non-nil) map,
// not omitted, when no object matched, so the receiver can tell "nothing
// there" from "no report".
type ubusPrefixStatusPayload struct {
	ObjectPrefix string                                `json:"object_prefix"`
	Results      map[string]map[string]json.RawMessage `json:"results"`
	WatchID      string                                `json:"watch_id,omitempty"`
}

// maxUbusWatchMethods bounds a prefix watch's per-object method list — each
// tick spawns one `ubus call` per object per method.
const maxUbusWatchMethods = 8

// isPrefixWatch reports whether a ubus_watch payload is the object_prefix
// shape rather than the object+method one.
func (p UbusWatchPayload) isPrefixWatch() bool {
	return p.ObjectPrefix != "" || len(p.Methods) > 0
}

// validate checks the payload is exactly one of the two valid shapes, with
// every name inside ubus's own naming vocabulary (no shell involved either way,
// but a name outside it can never be a real ubus object or method).
func (p UbusWatchPayload) validate() bool {
	if !p.isPrefixWatch() {
		return ubusObjectMethodRe.MatchString(p.Object) && ubusObjectMethodRe.MatchString(p.Method)
	}
	if p.Object != "" || p.Method != "" {
		return false
	}
	if !ubusObjectMethodRe.MatchString(p.ObjectPrefix) || len(p.Methods) == 0 || len(p.Methods) > maxUbusWatchMethods {
		return false
	}
	for _, m := range p.Methods {
		if !ubusObjectMethodRe.MatchString(m) {
			return false
		}
	}
	return true
}

// makePrefixWatchKey resolves the registry key for a prefix watch: the
// caller-supplied WatchID when present, else a synthetic "legacy:<prefix>*"
// key — see makeWatchKey for why a stable id matters.
func makePrefixWatchKey(watchID, prefix string) watchKey {
	return resolveKey[watchKey](watchID, "legacy:"+prefix+"*")
}

// handleUbusWatch starts a standing ubus watch, or no-ops if one for the same
// key is already running — see makeWatchKey's dedup contract.
func (a *Agent) handleUbusWatch(cmd Command) {
	var payload UbusWatchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !payload.validate() {
		slog.Error("ubus_watch rejected: invalid object/method", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "object_prefix", payload.ObjectPrefix, "methods", payload.Methods)
		a.publishAck(cmd.CmdID, "error", "invalid object or method")
		return
	}

	interval := time.Duration(payload.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = ubusWatchDefaultInterval
	}
	prefix := payload.isPrefixWatch()
	key := makeWatchKey(payload.WatchID, payload.Object, payload.Method)
	if prefix {
		key = makePrefixWatchKey(payload.WatchID, payload.ObjectPrefix)
	}

	stop, alreadyWatching := startOrNoop(&a.watchesMu, a.watches, key)
	if alreadyWatching {
		slog.Debug("ubus_watch: already watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "object_prefix", payload.ObjectPrefix, "watch_id", payload.WatchID)
		a.publishAck(cmd.CmdID, "ok", "")
		return
	}

	slog.Info("ubus_watch: starting", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "object_prefix", payload.ObjectPrefix, "methods", payload.Methods, "interval", interval, "watch_id", payload.WatchID)
	if prefix {
		go a.runUbusPrefixWatch(key, payload.WatchID, payload.ObjectPrefix, payload.Methods, payload.Params, interval, stop)
	} else {
		go a.runUbusWatch(key, payload.WatchID, payload.Object, payload.Method, payload.Params, interval, stop)
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

// handleUbusUnwatch stops a standing ubus watch. Idempotent — unwatching a
// key that isn't (or is no longer) being watched acks success, not an error.
// A watch started with a watch_id is stopped by that id alone, whichever shape
// it has — object/method/object_prefix only matter for the legacy fallback key.
func (a *Agent) handleUbusUnwatch(cmd Command) {
	var payload UbusUnwatchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}
	key := makeWatchKey(payload.WatchID, payload.Object, payload.Method)
	if payload.ObjectPrefix != "" {
		key = makePrefixWatchKey(payload.WatchID, payload.ObjectPrefix)
	}

	stop, found := stopKey(&a.watchesMu, a.watches, key)
	if found {
		close(stop)
		slog.Info("ubus_watch: stopped", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "object_prefix", payload.ObjectPrefix, "watch_id", payload.WatchID)
	} else {
		slog.Debug("ubus_unwatch: not watching, no-op", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method, "object_prefix", payload.ObjectPrefix, "watch_id", payload.WatchID)
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

// watchLoop runs tick every interval — waiting for the PREVIOUS tick to finish
// before scheduling the next (time.After, not a ticker), so a slow ubus call
// can never overlap with itself. Exits when stop is closed (explicit
// ubus_unwatch) or the session ends, removing its own registry entry either
// way so a later ubus_watch for the same key starts fresh rather than seeing a
// stale no-op. The first tick fires one full interval after the start.
func (a *Agent) watchLoop(key watchKey, interval time.Duration, stop chan struct{}, tick func()) {
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
		tick()
	}
}

// publishUbusStatus publishes one marshalled watch result to
// device/{id}/ubus-status.
func (a *Agent) publishUbusStatus(payload []byte, what string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.mqtt.Publish(ctx, mqttclient.TopicUbusStatus(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("ubus_watch: publish failed", "watch", what, "err", err)
	}
}

// runUbusWatch re-runs `ubus call object method params` every interval and
// publishes each successful result to device/{id}/ubus-status. A failed call
// is skipped (logged, not published); the next tick retries. See watchLoop for
// the timing and exit contract.
func (a *Agent) runUbusWatch(key watchKey, watchID, object, method string, params json.RawMessage, interval time.Duration, stop chan struct{}) {
	a.watchLoop(key, interval, stop, func() {
		result, err := runUbusCall(a.uci, object, method, params)
		if err != nil {
			slog.Debug("ubus_watch: call failed, skipping tick", "object", object, "method", method, "err", err)
			return
		}

		payload, err := json.Marshal(ubusStatusPayload{Object: object, Method: method, Result: json.RawMessage(result), WatchID: watchID})
		if err != nil {
			// A malformed ubus result (or, in principle, a marshal failure)
			// fails safely here rather than publishing broken JSON — the next
			// tick retries, same tolerance as a failed ubus call above.
			slog.Error("ubus_watch: marshal payload failed, skipping tick", "object", object, "method", method, "err", err)
			return
		}

		a.publishUbusStatus(payload, object+"."+method)
	})
}

// runUbusPrefixWatch is runUbusWatch for the object_prefix shape: each tick
// discovers the ubus objects currently starting with prefix (so an interface
// that appears or disappears is followed without any re-dispatch), calls every
// method on each and publishes ONE message carrying all the results — an
// atomic snapshot, rather than one message per object that the receiver would
// have to reassemble.
//
// A failed (or non-JSON) call just leaves that method out of its object's
// entry; an object with no successful call is left out entirely; a failed
// `ubus list` skips the tick. A tick that matches no object still publishes,
// with an empty results map — see ubusPrefixStatusPayload.
func (a *Agent) runUbusPrefixWatch(key watchKey, watchID, prefix string, methods []string, params json.RawMessage, interval time.Duration, stop chan struct{}) {
	a.watchLoop(key, interval, stop, func() {
		objects, err := discoverUbusObjects(a.uci, prefix)
		if err != nil {
			slog.Debug("ubus_watch: object discovery failed, skipping tick", "object_prefix", prefix, "err", err)
			return
		}

		results := make(map[string]map[string]json.RawMessage, len(objects))
		for _, object := range objects {
			perMethod := make(map[string]json.RawMessage, len(methods))
			for _, method := range methods {
				out, err := runUbusCall(a.uci, object, method, params)
				if err != nil {
					slog.Debug("ubus_watch: call failed, leaving method out", "object", object, "method", method, "err", err)
					continue
				}
				if !json.Valid([]byte(out)) {
					slog.Debug("ubus_watch: non-JSON result, leaving method out", "object", object, "method", method)
					continue
				}
				perMethod[method] = json.RawMessage(out)
			}
			if len(perMethod) > 0 {
				results[object] = perMethod
			}
		}

		payload, err := json.Marshal(ubusPrefixStatusPayload{ObjectPrefix: prefix, Results: results, WatchID: watchID})
		if err != nil {
			slog.Error("ubus_watch: marshal prefix payload failed, skipping tick", "object_prefix", prefix, "err", err)
			return
		}

		a.publishUbusStatus(payload, prefix+"*")
	})
}
