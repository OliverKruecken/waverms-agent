package agent

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

// activityLogPath is where the persistent activity log lives. It sits under
// /etc/waverms/, which is part of OpenWrt's writable overlay and survives
// reboot (unlike /tmp, which is tmpfs). Overridden in tests to a temp path.
var activityLogPath = "/etc/waverms/agent.log"

// activityLogMaxSize is the size cap for the activity log file. Once a
// pending append would exceed this, the file is trimmed to its most recent
// half. Overridden in tests to a small value.
var activityLogMaxSize int64 = 256 * 1024

// ActivityLogHandler is a slog.Handler that wraps another handler (normally
// the stderr TextHandler) and additionally persists every record to a
// size-capped local file, so that agent activity survives a device reboot —
// the syslog ring buffer (stderr → procd → logd) does not.
//
// It never changes what gets logged: Enabled() is a pure passthrough to the
// wrapped handler. Logging can be suspended at runtime via SetEnabled without
// affecting the wrapped handler's output.
type ActivityLogHandler struct {
	inner slog.Handler
	// enabled is a pointer shared across all WithAttrs/WithGroup clones, so
	// SetEnabled on any one of them (or on the top-level handler stored on
	// Agent) affects the whole handler tree.
	enabled *atomic.Bool
}

// NewActivityLogHandler wraps inner and opens (creating if necessary) the
// file at activityLogPath. Opening once at construction means a permissions
// problem fails fast and visibly at startup rather than silently on the
// first log line.
func NewActivityLogHandler(inner slog.Handler) (*ActivityLogHandler, error) {
	f, err := os.OpenFile(activityLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	_ = f.Close()

	enabled := &atomic.Bool{}
	enabled.Store(true)
	return &ActivityLogHandler{inner: inner, enabled: enabled}, nil
}

// SetEnabled toggles persistent file logging at runtime. The wrapped handler
// (e.g. stderr) keeps logging regardless.
func (h *ActivityLogHandler) SetEnabled(enabled bool) {
	h.enabled.Store(enabled)
}

func (h *ActivityLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle always delegates to the wrapped handler first, then — if enabled —
// formats the record via a throwaway TextHandler and appends it to the
// activity log file.
func (h *ActivityLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.inner.Enabled(ctx, r.Level) {
		if err := h.inner.Handle(ctx, r); err != nil {
			return err
		}
	}

	if !h.enabled.Load() {
		return nil
	}

	var buf bytes.Buffer
	if err := slog.NewTextHandler(&buf, nil).Handle(ctx, r); err != nil {
		return nil //nolint:nilerr // formatting failure must not break the wrapped handler's success
	}

	appendToActivityLog(buf.Bytes())
	return nil
}

// appendToActivityLog opens activityLogPath fresh for each call (rather than
// holding a long-lived fd) so that the rename-based trim below can never
// leave the handler writing through a stale fd to an unlinked inode.
// Given the log volume here (Info/Warn/Error on a router, not a firehose),
// the extra open/close per line is a non-issue.
func appendToActivityLog(line []byte) {
	if info, err := os.Stat(activityLogPath); err == nil && info.Size()+int64(len(line)) > activityLogMaxSize {
		trimActivityLog()
	}

	f, err := os.OpenFile(activityLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// trimActivityLog keeps the most recent ~half of the file (aligned to the
// next newline, so no line is split) and writes it via a temp file + rename.
//
// This is crash-safe: an in-place truncate-and-rewrite was considered and
// rejected, because a partial write during a power loss would splice
// unrelated leftover bytes from the file's old front region into the
// rewritten area at an arbitrary, non-newline-aligned byte offset — exactly
// the corruption newline-alignment is trying to avoid. Renaming a fully
// written, fsynced temp file over the original is atomic at the
// directory-entry level, so a crash leaves either the complete pre-trim or
// complete post-trim file, never a torn one.
func trimActivityLog() {
	data, err := os.ReadFile(activityLogPath)
	if err != nil {
		return
	}

	keep := activityLogMaxSize / 2
	if int64(len(data)) > keep {
		data = data[int64(len(data))-keep:]
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		}
	}

	tmpPath := activityLogPath + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpPath, activityLogPath)
}

// WithAttrs returns a clone sharing the same enabled state but with
// additional attributes pre-applied to the wrapped handler.
func (h *ActivityLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ActivityLogHandler{inner: h.inner.WithAttrs(attrs), enabled: h.enabled}
}

// WithGroup returns a clone with the given group applied to the wrapped handler.
func (h *ActivityLogHandler) WithGroup(name string) slog.Handler {
	return &ActivityLogHandler{inner: h.inner.WithGroup(name), enabled: h.enabled}
}
