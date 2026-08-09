package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
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

// ubusEventNameRe restricts Event to ubus's own notify-type vocabulary
// (alphanumeric, underscore, dot, dash). It's compared for an exact match
// against each received line's own type key (see ubusLineMatchesType) —
// unlike a literal `ubus listen <event>` argument, it is never passed to a
// ubus command line (see RealUbusListenStarter).
var ubusEventNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// UbusListenPayload is the inner payload for type "ubus_listen": start (or
// confirm) a standing subscription (see RealUbusListenStarter) whose lines
// matching Event are published (wrapped, see publishUbusEvent) to
// device/{id}/ubus-event, until a matching ubus_unlisten arrives or the
// session ends. Unlike ubus_watch, there is no interval — events are pushed
// the instant ubus emits them.
type UbusListenPayload struct {
	Event string `json:"event"`
}

// UbusUnlistenPayload is the inner payload for type "ubus_unlisten".
type UbusUnlistenPayload struct {
	Event string `json:"event"`
}

// handleUbusListen starts a standing ubus listen, or no-ops if one for the
// same event is already running — mirrors ubus_watch's dedup contract, keyed
// by event name alone.
func (a *Agent) handleUbusListen(cmd Command) {
	var payload UbusListenPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !ubusEventNameRe.MatchString(payload.Event) {
		slog.Error("ubus_listen rejected: invalid event", "cmd_id", cmd.CmdID, "event", payload.Event)
		a.publishAck(cmd.CmdID, "error", "invalid event")
		return
	}

	a.listensMu.Lock()
	_, already := a.listens[payload.Event]
	var stop chan struct{}
	if !already {
		stop = make(chan struct{})
		a.listens[payload.Event] = stop
	}
	a.listensMu.Unlock()

	if already {
		slog.Debug("ubus_listen: already listening, no-op", "cmd_id", cmd.CmdID, "event", payload.Event)
		a.publishAck(cmd.CmdID, "ok", "")
		return
	}

	slog.Info("ubus_listen: starting", "cmd_id", cmd.CmdID, "event", payload.Event)
	go a.runUbusListen(payload.Event, stop)
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

	a.listensMu.Lock()
	stop, found := a.listens[payload.Event]
	if found {
		delete(a.listens, payload.Event)
	}
	a.listensMu.Unlock()

	if found {
		close(stop)
		slog.Info("ubus_listen: stopped", "cmd_id", cmd.CmdID, "event", payload.Event)
	} else {
		slog.Debug("ubus_unlisten: not listening, no-op", "cmd_id", cmd.CmdID, "event", payload.Event)
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
func (a *Agent) runUbusListen(event string, stop chan struct{}) {
	defer func() {
		a.listensMu.Lock()
		if a.listens[event] == stop {
			delete(a.listens, event)
		}
		a.listensMu.Unlock()
	}()

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
		proc, err := a.ubusListenStarter.Start(ctx, event)
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
		done := make(chan struct{})
		go func() {
			for line := range proc.Lines() {
				// proc.Lines() is unfiltered — a subscription to a hostapd
				// object yields every notify type it sends (assoc/auth/probe
				// interleaved), not just the one this registration asked
				// for. See RealUbusListenStarter's doc comment.
				if !ubusLineMatchesType(line, event) {
					continue
				}
				a.publishUbusEvent(event, line)
			}
			close(done)
		}()

		select {
		case <-stop:
			proc.Stop()
			cancel()
			<-done
			return
		case <-disconnCh:
			proc.Stop()
			cancel()
			<-done
			return
		case <-done:
			// subprocess exited on its own (crash, ubus restarted, etc.)
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
// ubus_call/ubus_watch — with the requested event name and the agent's local
// receipt timestamp (hostapd's own event payload carries no timestamp), and
// publishes it to device/{id}/ubus-event.
func (a *Agent) publishUbusEvent(event, rawLine string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := fmt.Appendf(nil, `{"event":%s,"data":%s,"received_at":%s}`,
		jsonString(event), rawLine, jsonString(time.Now().UTC().Format(time.RFC3339Nano)))
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
