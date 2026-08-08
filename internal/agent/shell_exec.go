package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// ShellExecPayload is the inner payload for type "shell_exec" — a generic, one-shot arbitrary
// shell script execution, added specifically for backend-side "shell command templates" (a
// concept this agent has no other knowledge of, same posture as ubus_call for plugins). Unlike
// every other command handler, this genuinely invokes a shell (/bin/sh -c) rather than a fixed
// argv — the backend is responsible for whatever validation/redaction the script's content needs
// before it ever reaches the agent.
type ShellExecPayload struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

const (
	shellExecDefaultTimeout = 30 * time.Second
	shellExecMinTimeout     = 1 * time.Second
	// shellExecMaxTimeout deliberately stays under the backend's CommandTimeoutScheduler default
	// 5-minute PENDING/PUBLISHED sweep, so a legitimately-slow-but-still-running script never gets
	// marked TIMEOUT server-side while the agent is still faithfully executing it.
	shellExecMaxTimeout = 240 * time.Second
)

// clampShellExecTimeout resolves a requested timeout_seconds into a bounded time.Duration,
// defaulting to shellExecDefaultTimeout when unset (0) and clamping anything outside
// [shellExecMinTimeout, shellExecMaxTimeout] rather than rejecting the command outright.
func clampShellExecTimeout(seconds int) time.Duration {
	if seconds == 0 {
		return shellExecDefaultTimeout
	}
	d := time.Duration(seconds) * time.Second
	if d < shellExecMinTimeout {
		return shellExecMinTimeout
	}
	if d > shellExecMaxTimeout {
		return shellExecMaxTimeout
	}
	return d
}

// handleShellExec runs an ad-hoc shell script requested by the backend and ACKs with its
// combined stdout+stderr and exit code. This is the one generic widening of the agent's command
// surface added for shell command templates — the agent otherwise has no concept of what a
// "template" is, and never interprets the script's content.
func (a *Agent) handleShellExec(cmd Command) {
	var payload ShellExecPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if payload.Command == "" {
		slog.Error("shell_exec rejected: empty command", "cmd_id", cmd.CmdID)
		a.publishAckShellExec(cmd.CmdID, "error", "command must not be empty", 0)
		return
	}

	timeout := clampShellExecTimeout(payload.TimeoutSeconds)
	slog.Debug("shell_exec: executing", "cmd_id", cmd.CmdID, "timeout", timeout)

	output, exitCode, err := a.uci.ExecShell(payload.Command, timeout)
	if err != nil {
		slog.Error("shell_exec: exec failed", "cmd_id", cmd.CmdID, "err", err)
		a.publishAckShellExec(cmd.CmdID, "error", output+"\nerror: "+err.Error(), exitCode)
		return
	}

	status := "ok"
	if exitCode != 0 {
		status = "error"
	}
	a.publishAckShellExec(cmd.CmdID, status, output, exitCode)
	slog.Info("shell_exec: complete", "cmd_id", cmd.CmdID, "exit_code", exitCode)
}

// publishAckShellExec publishes an ACK carrying combined stdout+stderr and the exit code — the
// generic AckPayload has no exit_code field, so this mirrors ubus.go's publishAckUbusCall pattern
// of a dedicated ack shape for a command type that needs one.
func (a *Agent) publishAckShellExec(cmdID, status, output string, exitCode int) {
	slog.Debug("publishing shell_exec ack", "cmd_id", cmdID, "status", status)
	type shellExecAckPayload struct {
		CmdID     string `json:"cmd_id"`
		Status    string `json:"status"`
		Output    string `json:"output"`
		ExitCode  int    `json:"exit_code"`
		Timestamp string `json:"timestamp"`
	}
	ack := shellExecAckPayload{
		CmdID:     cmdID,
		Status:    status,
		Output:    output,
		ExitCode:  exitCode,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	payload, err := json.Marshal(ack)
	if err != nil {
		slog.Error("marshal shell_exec ack", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.mqtt.Publish(ctx, mqttclient.TopicAck(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("publish shell_exec ack", "cmd_id", cmdID, "err", err)
	}
}
