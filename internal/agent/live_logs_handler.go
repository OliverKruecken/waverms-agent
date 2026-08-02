package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// maxLiveLogsPublishes is the maximum number of MQTT live-log publishes that may
// be in flight simultaneously. Excess records are dropped rather than spawning
// unbounded goroutines, which would grow RSS significantly on slow connections.
const maxLiveLogsPublishes = 8

// liveLogsState holds the runtime toggle flag, shared across all WithAttrs/WithGroup clones.
type liveLogsState struct {
	mu      sync.RWMutex
	enabled bool
}

// mqttLiveLogsHandler is a slog.Handler that:
//   - always delegates to the wrapped text handler for local syslog output
//   - when enabled, additionally publishes every log record to device/{id}/live-logs/log via MQTT
type mqttLiveLogsHandler struct {
	text     slog.Handler
	mqtt     mqttclient.MQTTClient
	deviceID string
	state    *liveLogsState
	// sem is a semaphore that caps concurrent MQTT publishes to maxLiveLogsPublishes.
	// All clones share the same semaphore so the cap is per-handler-tree, not per-clone.
	sem chan struct{}
}

func newMQTTLiveLogsHandler(text slog.Handler, mqtt mqttclient.MQTTClient, deviceID string) *mqttLiveLogsHandler {
	return &mqttLiveLogsHandler{
		text:     text,
		mqtt:     mqtt,
		deviceID: deviceID,
		state:    &liveLogsState{},
		sem:      make(chan struct{}, maxLiveLogsPublishes),
	}
}

// SetEnabled toggles MQTT log publishing at runtime without restarting the agent.
func (h *mqttLiveLogsHandler) SetEnabled(enabled bool) {
	h.state.mu.Lock()
	h.state.enabled = enabled
	h.state.mu.Unlock()
	if enabled {
		slog.Info("live log streaming enabled")
	} else {
		slog.Info("live log streaming disabled")
	}
}

func (h *mqttLiveLogsHandler) mqttEnabled() bool {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()
	return h.state.enabled
}

// Enabled returns true if the text handler would log the level, OR if MQTT live-log
// streaming is active (so that Debug records reach Handle even when the local text level is Info).
func (h *mqttLiveLogsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.text.Enabled(ctx, level) || h.mqttEnabled()
}

// Handle writes the record locally (if the text handler accepts the level) and, when MQTT
// live-log streaming is enabled, publishes it to device/{id}/live-logs/log (QoS 0, no retain, fire-and-forget).
func (h *mqttLiveLogsHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.text.Enabled(ctx, r.Level) {
		_ = h.text.Handle(ctx, r)
	}

	if !h.mqttEnabled() {
		return nil
	}

	payload := h.marshalRecord(r)
	topic := mqttclient.TopicLiveLogsLog(h.deviceID)

	select {
	case h.sem <- struct{}{}:
		go func() {
			defer func() { <-h.sem }()
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = h.mqtt.Publish(ctx2, topic, payload, 0, false)
		}()
	default:
		// semaphore full – drop this live-log record rather than accumulating goroutines
	}

	return nil
}

func (h *mqttLiveLogsHandler) marshalRecord(r slog.Record) []byte {
	m := map[string]any{
		"ts":    r.Time.UTC().Format(time.RFC3339Nano),
		"level": r.Level.String(),
		"msg":   r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = resolveValue(a.Value)
		return true
	})
	b, _ := json.Marshal(m)
	return b
}

// resolveValue converts a slog.Value to a JSON-serialisable Go value.
// KindAny is the tricky case: the raw interface may be an error, a Stringer,
// or an arbitrary struct with unexported fields — all of which json.Marshal
// would either fail on or produce "{}".  We convert those to strings.
func resolveValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindAny:
		raw := v.Any()
		if err, ok := raw.(error); ok {
			return err.Error()
		}
		if s, ok := raw.(fmt.Stringer); ok {
			return s.String()
		}
		return fmt.Sprintf("%v", raw)
	default:
		return v.String()
	}
}

// WithAttrs returns a clone sharing the same toggle state but with additional attributes
// pre-applied to the wrapped text handler.
func (h *mqttLiveLogsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &mqttLiveLogsHandler{
		text:     h.text.WithAttrs(attrs),
		mqtt:     h.mqtt,
		deviceID: h.deviceID,
		state:    h.state,
		sem:      h.sem,
	}
}

// WithGroup returns a clone with the given group applied to the wrapped text handler.
func (h *mqttLiveLogsHandler) WithGroup(name string) slog.Handler {
	return &mqttLiveLogsHandler{
		text:     h.text.WithGroup(name),
		mqtt:     h.mqtt,
		deviceID: h.deviceID,
		state:    h.state,
		sem:      h.sem,
	}
}
