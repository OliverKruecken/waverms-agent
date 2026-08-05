package agent

import (
	"bytes"
	"context"
	"log/slog"
	"log/syslog"
	"strings"
	"sync"
)

// syslogNetwork/syslogAddress name the local syslog socket to dial. Package-level
// vars (like activityLogPath in activitylog.go) so tests can point them at a
// throwaway unixgram socket instead of the real /dev/log.
var (
	syslogNetwork = "unixgram"
	syslogAddress = "/dev/log"
)

// syslogState is the shared, mutex-guarded scratch buffer every clone of a
// SyslogHandler formats records into before handing the text to the syslog
// writer. Shared by pointer across WithAttrs/WithGroup clones (mirroring
// ActivityLogHandler's enabled *atomic.Bool) so the underlying slog.TextHandler
// chain — and the attrs/group state accumulated on it — is the single one doing
// the formatting, whichever clone Handle is called on.
type syslogState struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// SyslogHandler is a slog.Handler that writes each record directly to the local
// syslog socket (/dev/log) with a priority derived from the record's own level.
//
// This exists because OpenWrt's procd, when a service's stdout/stderr are
// captured (procd_set_param stdout/stderr 1 in the init script), tags every
// line it captures with one fixed severity per stream — stderr always as
// LOG_ERR — rather than parsing the line's content. Routing normal application
// logging through stderr therefore made every record, including plain INFO
// lines, show up in logd (and so the live-logs snapshot's "priority" field) as
// an error. Writing straight to /dev/log with real syslog(3) semantics is the
// only way logd sees the record's actual severity. procd's stderr capture stays
// enabled at the init-script level, but now only ever sees uncaught Go panics
// (which bypass slog entirely) — and those genuinely are LOG_ERR-worthy.
type SyslogHandler struct {
	writer *syslog.Writer
	text   slog.Handler
	state  *syslogState
}

// NewSyslogHandler dials the local syslog socket under the daemon facility and
// returns a handler ready to use. Fails if no syslog socket is present (a
// devcontainer, CI runner, or any non-OpenWrt host) — callers should fall back
// to a plain stderr handler in that case, matching NewActivityLogHandler's
// fail-open convention.
func NewSyslogHandler(level slog.Leveler) (*SyslogHandler, error) {
	w, err := syslog.Dial(syslogNetwork, syslogAddress, syslog.LOG_DAEMON, "waverms-agent")
	if err != nil {
		return nil, err
	}
	state := &syslogState{}
	return &SyslogHandler{
		writer: w,
		text:   slog.NewTextHandler(&state.buf, &slog.HandlerOptions{Level: level}),
		state:  state,
	}, nil
}

func (h *SyslogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.text.Enabled(ctx, level)
}

// Handle formats the record the same way the rest of this codebase's local text
// output does (time=... level=... msg=... key=val), then publishes it at the
// syslog severity matching the record's own level, so logd's priority field —
// and therefore the frontend's priorityToLevel() classification — reflects the
// record's real severity instead of a stream-wide constant.
func (h *SyslogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.state.mu.Lock()
	h.state.buf.Reset()
	err := h.text.Handle(ctx, r)
	msg := strings.TrimRight(h.state.buf.String(), "\n")
	h.state.mu.Unlock()
	if err != nil {
		return err
	}
	switch {
	case r.Level >= slog.LevelError:
		return h.writer.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.writer.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.writer.Info(msg)
	default:
		return h.writer.Debug(msg)
	}
}

// WithAttrs returns a clone sharing the same writer and formatting state but
// with additional attributes pre-applied to the wrapped text handler.
func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SyslogHandler{writer: h.writer, text: h.text.WithAttrs(attrs), state: h.state}
}

// WithGroup returns a clone with the given group applied to the wrapped text handler.
func (h *SyslogHandler) WithGroup(name string) slog.Handler {
	return &SyslogHandler{writer: h.writer, text: h.text.WithGroup(name), state: h.state}
}
