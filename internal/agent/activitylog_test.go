package agent

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withActivityLogPath points the package-level path/size-cap vars at a temp
// file for the duration of the test, mirroring the uciConfigDir override
// pattern in rollback_test.go.
func withActivityLogPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	origPath, origSize := activityLogPath, activityLogMaxSize
	activityLogPath = path
	t.Cleanup(func() {
		activityLogPath = origPath
		activityLogMaxSize = origSize
	})
	return path
}

func TestNewActivityLogHandler_AppendsAndReadsBack(t *testing.T) {
	path := withActivityLogPath(t)

	var stderrBuf bytes.Buffer
	inner := slog.NewTextHandler(&stderrBuf, &slog.HandlerOptions{Level: slog.LevelInfo})
	h, err := NewActivityLogHandler(inner)
	require.NoError(t, err)

	logger := slog.New(h)
	logger.Info("hello from wrt-garden", "cmd_id", "abc123")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "hello from wrt-garden")
	assert.Contains(t, string(data), "cmd_id=abc123")

	// Stderr passthrough must still happen alongside the file write.
	assert.Contains(t, stderrBuf.String(), "hello from wrt-garden")
}

func TestActivityLogHandler_SetEnabledFalse_SuppressesFileButNotInner(t *testing.T) {
	path := withActivityLogPath(t)

	var stderrBuf bytes.Buffer
	inner := slog.NewTextHandler(&stderrBuf, &slog.HandlerOptions{Level: slog.LevelInfo})
	h, err := NewActivityLogHandler(inner)
	require.NoError(t, err)

	h.SetEnabled(false)
	logger := slog.New(h)
	logger.Info("should not be persisted")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, data, "file must stay empty while disabled")
	assert.Contains(t, stderrBuf.String(), "should not be persisted", "inner handler must keep logging regardless of the toggle")

	h.SetEnabled(true)
	logger.Info("resumed")
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "resumed")
}

func TestActivityLogHandler_OverflowTrimsToRecentContent(t *testing.T) {
	withActivityLogPath(t)
	activityLogMaxSize = 2048 // small cap so the test writes a manageable number of lines

	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	h, err := NewActivityLogHandler(inner)
	require.NoError(t, err)
	logger := slog.New(h)

	for i := 0; i < 200; i++ {
		logger.Info("line", "n", i, "padding", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	}

	data, err := os.ReadFile(activityLogPath)
	require.NoError(t, err)

	assert.LessOrEqual(t, int64(len(data)), activityLogMaxSize, "file must stay bounded by the cap after trimming")
	assert.Contains(t, string(data), "n=199", "most recent record must survive the trim")
	assert.NotContains(t, string(data), "n=0\n", "oldest records must be dropped once the cap is exceeded")

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "time="), "no partial/split line should remain at the trim boundary: %q", line)
	}
}

func TestNewActivityLogHandler_UnwritablePath_ReturnsError(t *testing.T) {
	origPath := activityLogPath
	// A path whose parent directory does not exist cannot be opened/created.
	activityLogPath = filepath.Join(t.TempDir(), "no-such-dir", "agent.log")
	t.Cleanup(func() { activityLogPath = origPath })

	inner := slog.NewTextHandler(&bytes.Buffer{}, nil)
	_, err := NewActivityLogHandler(inner)
	assert.Error(t, err)
}

func TestActivityLogHandler_Enabled_DelegatesToInner(t *testing.T) {
	withActivityLogPath(t)

	inner := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	h, err := NewActivityLogHandler(inner)
	require.NoError(t, err)

	assert.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, h.Enabled(context.Background(), slog.LevelWarn))
}

func TestActivityLogHandler_WithAttrs_SharesEnabledState(t *testing.T) {
	path := withActivityLogPath(t)

	var stderrBuf bytes.Buffer
	inner := slog.NewTextHandler(&stderrBuf, &slog.HandlerOptions{Level: slog.LevelInfo})
	h, err := NewActivityLogHandler(inner)
	require.NoError(t, err)

	clone := h.WithAttrs([]slog.Attr{slog.String("component", "test")})
	h.SetEnabled(false)

	slog.New(clone).Info("via clone")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, data, "SetEnabled on the parent handler must also suppress writes made through a WithAttrs clone")
}
