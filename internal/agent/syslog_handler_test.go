package agent

import (
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// withSyslogSocket points syslogNetwork/syslogAddress at a throwaway unixgram
// socket for the duration of the test, mirroring the withActivityLogPath
// pattern in activitylog_test.go, and returns the listening end so the test
// can read back exactly what NewSyslogHandler wrote to the wire.
func withSyslogSocket(t *testing.T) *net.UnixConn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	origNetwork, origAddress := syslogNetwork, syslogAddress
	syslogNetwork, syslogAddress = "unixgram", path
	t.Cleanup(func() { syslogNetwork, syslogAddress = origNetwork, origAddress })

	return conn
}

// readPacket reads one datagram and splits it into its numeric PRI and the
// rest of the line, failing the test if none arrives promptly.
func readPacket(t *testing.T, conn *net.UnixConn) (pri int, line string) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	raw := string(buf[:n])

	require.True(t, strings.HasPrefix(raw, "<"), "expected a <PRI> prefix, got %q", raw)
	end := strings.IndexByte(raw, '>')
	require.Greater(t, end, 0, "malformed syslog packet %q", raw)
	pri, err = strconv.Atoi(raw[1:end])
	require.NoError(t, err)
	return pri, raw[end+1:]
}

func TestNewSyslogHandler_NoSocket(t *testing.T) {
	origNetwork, origAddress := syslogNetwork, syslogAddress
	t.Cleanup(func() { syslogNetwork, syslogAddress = origNetwork, origAddress })
	syslogNetwork, syslogAddress = "unixgram", filepath.Join(t.TempDir(), "no-such-socket")

	_, err := NewSyslogHandler(slog.LevelInfo)
	require.Error(t, err)
}

// Facility daemon = 3 (syslog.LOG_DAEMON); PRI = facility*8 + severity.
const daemonFacility = 3 * 8

func TestSyslogHandler_EachLevelGetsItsOwnPriority(t *testing.T) {
	conn := withSyslogSocket(t)
	h, err := NewSyslogHandler(slog.LevelDebug)
	require.NoError(t, err)
	logger := slog.New(h)

	logger.Debug("d")
	logger.Info("i")
	logger.Warn("w")
	logger.Error("e")

	wantPRI := []int{daemonFacility + 7, daemonFacility + 6, daemonFacility + 4, daemonFacility + 3} // debug, info, warn, err
	wantLevel := []string{"level=DEBUG", "level=INFO", "level=WARN", "level=ERROR"}
	for i := range wantPRI {
		pri, line := readPacket(t, conn)
		require.Equalf(t, wantPRI[i], pri, "packet %d priority", i)
		require.Containsf(t, line, wantLevel[i], "packet %d body", i)
	}
}

func TestSyslogHandler_WithAttrsAppearsInFormattedBody(t *testing.T) {
	conn := withSyslogSocket(t)
	h, err := NewSyslogHandler(slog.LevelDebug)
	require.NoError(t, err)
	logger := slog.New(h).With("cmd_id", "abc123")

	logger.Info("logs_fetch: complete", "entries", 200)

	pri, line := readPacket(t, conn)
	require.Equal(t, daemonFacility+6, pri) // info
	require.Contains(t, line, "cmd_id=abc123")
	require.Contains(t, line, "entries=200")
	require.Contains(t, line, "logs_fetch: complete")
}

func TestSyslogHandler_RespectsLevelThreshold(t *testing.T) {
	conn := withSyslogSocket(t)
	h, err := NewSyslogHandler(slog.LevelWarn)
	require.NoError(t, err)
	logger := slog.New(h)

	logger.Debug("dropped")
	logger.Info("dropped too")
	logger.Warn("kept")

	pri, line := readPacket(t, conn)
	require.Equal(t, daemonFacility+4, pri)
	require.Contains(t, line, "kept")
}
