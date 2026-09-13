package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// ubusListenBaseBackoff/ubusListenMaxBackoff/ubusListenStableAfter bound the
// restart-after-crash loop in runUbusListen. Unlike ubus_watch, a streaming
// subprocess has no "next tick" to fall back to if it dies (ubusd restart,
// OOM, transient fork failure) — nothing else will ever notice or retry it,
// so the retry loop is built in explicitly. var, not const, so tests can
// shrink them for fast, deterministic backoff assertions.
var (
	ubusListenBaseBackoff = 1 * time.Second
	ubusListenMaxBackoff  = 30 * time.Second
	ubusListenStableAfter = 30 * time.Second
)

// ubusEventPublishQueueSize bounds the hand-off between runUbusListen's line
// reader and its publisher (see runUbusListen). Matched (already
// type-filtered) events are rare compared to the probe spam
// UbusListenProcess.Lines() absorbs in its own 16-slot buffer — this only
// needs to smooth over a single slow/blocked MQTT publish (up to
// publishUbusEvent's own 10s context timeout during a degraded connection),
// not sustained load.
const ubusEventPublishQueueSize = 8

// makeListenKey resolves the registry key for one ubus_listen registration —
// same id-or-legacy-fallback contract as makeWatchKey (see its doc comment
// in ubus_watch.go): a caller-supplied WatchID when present, or a synthetic
// "legacy:<event>" key otherwise, preserving the original dedup-by-event
// contract exactly.
func makeListenKey(watchID, event string) string {
	return resolveKey[string](watchID, "legacy:"+event)
}

// UbusListenPayload is the inner payload for type "ubus_listen": start (or
// confirm) a standing subscription (see RealUbusListenStarter) whose lines
// matching Event are published (wrapped, see publishUbusEvent) to
// device/{id}/ubus-event, until a matching ubus_unlisten arrives or the
// session ends. Unlike ubus_watch, there is no interval — events are pushed
// the instant ubus emits them.
type UbusListenPayload struct {
	Event string `json:"event"`
	// ObjectPrefix selects which ubus objects to subscribe to (any object
	// name returned by `ubus list` that starts with this prefix) — see
	// RealUbusListenStarter/discoverUbusObjects. Optional: empty defaults to
	// defaultHostapdObjectPrefix, reproducing this primitive's original
	// hostapd-only behavior exactly.
	ObjectPrefix string `json:"object_prefix,omitempty"`
	// WatchID is a caller-assigned, stable-across-re-dispatch identifier —
	// see makeListenKey. Optional: omitted, dedup falls back to Event alone
	// exactly as before this field existed.
	WatchID string `json:"watch_id,omitempty"`
}

// UbusUnlistenPayload is the inner payload for type "ubus_unlisten".
type UbusUnlistenPayload struct {
	Event   string `json:"event"`
	WatchID string `json:"watch_id,omitempty"`
}

// ubusEventPayload is the wire shape published to device/{id}/ubus-event —
// see publishUbusEvent.
type ubusEventPayload struct {
	Event      string          `json:"event"`
	Data       json.RawMessage `json:"data"`
	ReceivedAt string          `json:"received_at"`
	WatchID    string          `json:"watch_id,omitempty"`
}

// handleUbusListen starts a standing ubus listen, or no-ops if one for the
// same key is already running — mirrors ubus_watch's dedup contract, see
// makeListenKey.
func (a *Agent) handleUbusListen(cmd Command) {
	var payload UbusListenPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !ubusObjectMethodRe.MatchString(payload.Event) {
		slog.Error("ubus_listen rejected: invalid event", "cmd_id", cmd.CmdID, "event", payload.Event)
		a.publishAck(cmd.CmdID, "error", "invalid event")
		return
	}
	if payload.ObjectPrefix != "" && !ubusObjectMethodRe.MatchString(payload.ObjectPrefix) {
		slog.Error("ubus_listen rejected: invalid object_prefix", "cmd_id", cmd.CmdID, "object_prefix", payload.ObjectPrefix)
		a.publishAck(cmd.CmdID, "error", "invalid object_prefix")
		return
	}

	objectPrefix := payload.ObjectPrefix
	if objectPrefix == "" {
		objectPrefix = defaultHostapdObjectPrefix
	}
	key := makeListenKey(payload.WatchID, payload.Event)

	stop, already := startOrNoop(&a.listensMu, a.listens, key)
	if already {
		slog.Debug("ubus_listen: already listening, no-op", "cmd_id", cmd.CmdID, "event", payload.Event, "watch_id", payload.WatchID)
		a.publishAck(cmd.CmdID, "ok", "")
		return
	}

	slog.Info("ubus_listen: starting", "cmd_id", cmd.CmdID, "event", payload.Event, "object_prefix", objectPrefix, "watch_id", payload.WatchID)
	go a.runUbusListen(key, payload.WatchID, payload.Event, objectPrefix, stop)
	a.publishAck(cmd.CmdID, "ok", "")
}

// handleUbusUnlisten stops a standing ubus listen. Idempotent — unlistening
// an event that isn't (or is no longer) being listened to acks success, not
// an error.
func (a *Agent) handleUbusUnlisten(cmd Command) {
	var payload UbusUnlistenPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}
	key := makeListenKey(payload.WatchID, payload.Event)

	stop, found := stopKey(&a.listensMu, a.listens, key)
	if found {
		close(stop)
		slog.Info("ubus_listen: stopped", "cmd_id", cmd.CmdID, "event", payload.Event, "watch_id", payload.WatchID)
	} else {
		slog.Debug("ubus_unlisten: not listening, no-op", "cmd_id", cmd.CmdID, "event", payload.Event, "watch_id", payload.WatchID)
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

// runUbusListen owns the whole subprocess lifecycle: start, forward every
// received line to MQTT, and — unlike ubus_watch, which just skips a failed
// tick — restart with exponential backoff on an unexpected exit, since there
// is no next tick for a streaming primitive to fall back to. Exits (killing
// the subprocess first) on explicit unlisten or session end, removing its
// own registry entry either way, same session-scoped-cleanup contract as
// runUbusWatch.
func (a *Agent) runUbusListen(key, watchID, event, objectPrefix string, stop chan struct{}) {
	defer cleanupOwnEntry(&a.listensMu, a.listens, key, stop)

	disconnCh := a.getSessionDisconnCh()
	backoff := ubusListenBaseBackoff

	for {
		select {
		case <-stop:
			return
		case <-disconnCh:
			return
		default:
		}

		ctx, cancel := context.WithCancel(context.Background())
		proc, err := a.ubusListenStarter.Start(ctx, objectPrefix, event)
		if err != nil {
			cancel()
			slog.Error("ubus_listen: start failed, retrying", "event", event, "err", err, "backoff", backoff)
			if !a.sleepOrStop(backoff, stop, disconnCh) {
				return
			}
			backoff = nextUbusListenBackoff(backoff)
			continue
		}

		startedAt := time.Now()
		lineDone := make(chan struct{})
		publishDone := make(chan struct{})
		// publishQueue hands matched lines off from the reader goroutine
		// (below) to the publisher goroutine, so a slow/blocked MQTT publish
		// (up to publishUbusEvent's own 10s timeout, worse during a degraded
		// connection) can never stall draining proc.Lines() — that stall is
		// exactly what let UbusListenProcess's own 16-slot buffer overflow
		// and silently drop probe *and* assoc lines alike on a real device.
		// See docs/roaming.md.
		publishQueue := make(chan string, ubusEventPublishQueueSize)

		go func() {
			defer close(publishDone)
			for line := range publishQueue {
				a.publishUbusEvent(event, watchID, line)
			}
		}()

		go func() {
			defer close(lineDone)
			defer close(publishQueue)
			for line := range proc.Lines() {
				// proc.Lines() is unfiltered — a subscription to a hostapd
				// object yields every notify type it sends (assoc/auth/probe
				// interleaved), not just the one this registration asked
				// for. See RealUbusListenStarter's doc comment.
				if !ubusLineMatchesType(line, event) {
					continue
				}
				select {
				case publishQueue <- line:
				default:
					// An already-type-matched event — unlike the line
					// buffer's probe/auth spam, this is presumably a real
					// event (e.g. a roam) — dropped only because the
					// publisher is still stuck on a prior slow publish.
					slog.Warn("ubus_listen: publish queue full, dropping event", "event", event)
				}
			}
		}()

		select {
		case <-stop:
			proc.Stop()
			cancel()
			<-lineDone
			<-publishDone
			return
		case <-disconnCh:
			proc.Stop()
			cancel()
			<-lineDone
			<-publishDone
			return
		case <-lineDone:
			// subprocess exited on its own (crash, ubus restarted, etc.) —
			// still wait for the publisher to drain whatever was already
			// queued before restarting.
			<-publishDone
		}
		cancel()
		exitErr := proc.Wait()
		slog.Warn("ubus_listen: subprocess exited, restarting", "event", event, "err", exitErr)

		if time.Since(startedAt) >= ubusListenStableAfter {
			backoff = ubusListenBaseBackoff // ran long enough — treat the next attempt as fresh
		}
		if !a.sleepOrStop(backoff, stop, disconnCh) {
			return
		}
		backoff = nextUbusListenBackoff(backoff)
	}
}

// ubusLineMatchesType reports whether a raw `{ "<type>": {...} }` ubus notify
// line's own type key equals eventType — used to filter
// RealUbusListenStarter's unfiltered per-object stream (assoc/auth/probe all
// interleaved on one subscription) down to the single type this listen
// registration asked for. Malformed lines never match (dropped, not
// published) — the agent still doesn't interpret ubus output, this only
// peeks at the outer key.
func ubusLineMatchesType(line, eventType string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return false
	}
	_, ok := m[eventType]
	return ok
}

// publishUbusEvent wraps one raw ubus JSON line — deliberately not
// reinterpreted, same "the agent never interprets ubus output" philosophy as
// ubus_call/ubus_watch — with the requested event name, the resolved
// watch_id (if any), and the agent's local receipt timestamp (hostapd's own
// event payload carries no timestamp), and publishes it to
// device/{id}/ubus-event.
func (a *Agent) publishUbusEvent(event, watchID, rawLine string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(ubusEventPayload{
		Event:      event,
		Data:       json.RawMessage(rawLine),
		ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
		WatchID:    watchID,
	})
	if err != nil {
		slog.Error("ubus_listen: marshal payload failed, dropping event", "event", event, "err", err)
		return
	}
	if err := a.mqtt.Publish(ctx, mqttclient.TopicUbusEvent(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("ubus_listen: publish failed", "event", event, "err", err)
	}
}

func nextUbusListenBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > ubusListenMaxBackoff {
		return ubusListenMaxBackoff
	}
	return next
}

// sleepOrStop waits for backoff, or returns false early if stop/disconnCh fire.
func (a *Agent) sleepOrStop(backoff time.Duration, stop chan struct{}, disconnCh <-chan struct{}) bool {
	select {
	case <-time.After(backoff):
		return true
	case <-stop:
		return false
	case <-disconnCh:
		return false
	}
}
