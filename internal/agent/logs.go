package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// LogEntry is one parsed ubus logd record. Field names/types match logd's
// log_fill_msg() (openwrt/ubox log/logd.c): msg is a string, id/priority/source
// are uint32, and time is always milliseconds since epoch (tv_sec*1000 + tv_nsec/1e6) —
// never seconds, so no unit-detection fallback is needed here.
type LogEntry struct {
	Time     int64  `json:"time"`
	Priority int    `json:"priority"`
	Source   int    `json:"source"`
	Msg      string `json:"msg"`
}

// LogsFetchPayload is the inner payload for logs_fetch commands.
type LogsFetchPayload struct {
	Lines int `json:"lines"`
}

const (
	logsFetchDefaultLines = 200
	logsFetchMinLines     = 1
	logsFetchMaxLines     = 1000
)

// ubusLogReadResponse mirrors the JSON shape of `ubus call log read` when invoked
// with "stream":false — a single object with a "log" array, not a bare array.
type ubusLogReadResponse struct {
	Log []LogEntry `json:"log"`
}

// parseUbusLogOutput parses the raw stdout of `ubus call log read` into entries.
func parseUbusLogOutput(raw string) ([]LogEntry, error) {
	var resp ubusLogReadResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("parse ubus log read output: %w", err)
	}
	return resp.Log, nil
}

// runUbusLogRead executes `ubus call log read '{"lines":N,"stream":false}'` and
// returns the raw JSON output. "stream":false is required — logd's read method
// defaults to streaming (delivered over a pipe fd, never a synchronous reply)
// unless explicitly disabled.
func (a *Agent) runUbusLogRead(lines int) (string, error) {
	arg := fmt.Sprintf(`{"lines":%d,"stream":false}`, lines)
	out, err := a.uci.ExecCmd("ubus", "call", "log", "read", arg)
	return out, err
}

// handleLogsFetch runs `ubus call log read` for an on-demand snapshot of the
// device's current logd buffer and ACKs with the parsed entries.
func (a *Agent) handleLogsFetch(cmd Command) {
	var payload LogsFetchPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	lines := payload.Lines
	if lines == 0 {
		lines = logsFetchDefaultLines
	}
	if lines < logsFetchMinLines || lines > logsFetchMaxLines {
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("lines must be between %d and %d", logsFetchMinLines, logsFetchMaxLines))
		return
	}

	slog.Debug("logs_fetch: reading device logs", "cmd_id", cmd.CmdID, "lines", lines)

	out, err := a.runUbusLogRead(lines)
	if err != nil {
		a.publishAckLogsFetch(cmd.CmdID, "error", "ubus call log read failed: "+err.Error(), nil)
		return
	}

	entries, err := parseUbusLogOutput(out)
	if err != nil {
		a.publishAckLogsFetch(cmd.CmdID, "error", err.Error(), nil)
		return
	}

	a.publishAckLogsFetch(cmd.CmdID, "ok", "", entries)
	slog.Info("logs_fetch: complete", "cmd_id", cmd.CmdID, "entries", len(entries))
}

// publishAckLogsFetch publishes an ACK carrying the fetched log entries.
func (a *Agent) publishAckLogsFetch(cmdID, status, output string, entries []LogEntry) {
	slog.Debug("publishing logs_fetch ack", "cmd_id", cmdID, "status", status)
	type logsFetchAckPayload struct {
		CmdID      string     `json:"cmd_id"`
		Status     string     `json:"status"`
		Output     string     `json:"output,omitempty"`
		Timestamp  string     `json:"timestamp"`
		LogEntries []LogEntry `json:"log_entries,omitempty"`
	}
	ack := logsFetchAckPayload{
		CmdID:      cmdID,
		Status:     status,
		Output:     output,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		LogEntries: entries,
	}
	payload, err := json.Marshal(ack)
	if err != nil {
		slog.Error("marshal logs_fetch ack", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.mqtt.Publish(ctx, mqttclient.TopicAck(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("publish logs_fetch ack", "cmd_id", cmdID, "err", err)
	}
}
