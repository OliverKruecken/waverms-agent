package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// UbusCallPayload is the inner payload for type "ubus_call" — a single
// generic, package-agnostic command that lets backend-side "plugins" (a
// concept this agent has no other knowledge of) query live ubus runtime data
// on demand, e.g. usteer client-steering stats. Params is passed through to
// `ubus call` verbatim; the agent never interprets it.
type UbusCallPayload struct {
	Object string          `json:"object"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// ubusObjectMethodRe restricts Object/Method to ubus's own naming vocabulary
// (alphanumeric, underscore, dot, dash). exec.CommandContext never invokes a
// shell so this isn't strictly an injection vector, but ubus object/method
// names are a controlled, well-known vocabulary and malformed input should
// fail cleanly here rather than reach ubus and produce a confusing error.
// Also used to validate ubus_listen's Event and ObjectPrefix (ubus_listen.go)
// — object names, method names, notify-type/event keys, and object-name
// prefixes are all drawn from the identical ubus naming vocabulary, so one
// shared pattern covers all of them rather than each having its own copy.
var ubusObjectMethodRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// UbusListPayload is the inner payload for type "ubus_list" — the
// introspection counterpart to ubus_call: `ubus [-v] list [path]`, one-shot,
// ack'd with ubus's raw text output (not JSON — `ubus list`'s own output
// isn't JSON either, so unlike ubus_call this rides the standard AckPayload's
// plain-string Output field rather than a dedicated result field). Lets a
// caller discover what ubus objects exist on a device (Path empty or a glob
// like "network.interface.*") and, with Verbose, what methods and argument
// signatures a specific object exposes (`ubus -v list <path>`) — without
// already knowing the answer, the one capability ubus_call/ubus_watch/
// ubus_listen all still require the caller to have upfront.
type UbusListPayload struct {
	Path    string `json:"path,omitempty"`
	Verbose bool   `json:"verbose,omitempty"`
}

// ubusListPathRe restricts Path to ubus's own list-argument vocabulary —
// ubusObjectMethodRe plus '*', since `ubus list` (unlike ubus_call's exact
// object/method names) accepts a glob path like "network.interface.*". Empty
// is valid too (list everything).
var ubusListPathRe = regexp.MustCompile(`^[a-zA-Z0-9_.*-]*$`)

// runUbusList executes `ubus [-v] list [path]` via runner and returns its raw
// text stdout, unparsed — same "the agent never interprets ubus output"
// philosophy as runUbusCall.
func runUbusList(runner uci.UCIRunner, path string, verbose bool) (string, error) {
	args := []string{"list"}
	if verbose {
		args = []string{"-v", "list"}
	}
	if path != "" {
		args = append(args, path)
	}
	return runner.ExecCmd("ubus", args...)
}

// handleUbusList runs an ad-hoc `ubus list` requested by the backend and ACKs
// with the raw text output.
func (a *Agent) handleUbusList(cmd Command) {
	var payload UbusListPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !ubusListPathRe.MatchString(payload.Path) {
		slog.Error("ubus_list rejected: invalid path", "cmd_id", cmd.CmdID, "path", payload.Path)
		a.publishAck(cmd.CmdID, "error", "invalid path")
		return
	}

	slog.Debug("ubus_list: executing", "cmd_id", cmd.CmdID, "path", payload.Path, "verbose", payload.Verbose)

	out, err := runUbusList(a.uci, payload.Path, payload.Verbose)
	if err != nil {
		a.publishAck(cmd.CmdID, "error", "ubus list failed: "+err.Error())
		return
	}

	a.publishAck(cmd.CmdID, "ok", out)
	slog.Info("ubus_list: complete", "cmd_id", cmd.CmdID, "path", payload.Path)
}

// runUbusCall executes `ubus call <object> <method> <params>` via runner and
// returns ubus's raw JSON stdout, unparsed — the agent never interprets ubus
// output, it is only a pass-through to whatever requested it. An empty/nil
// params defaults to "{}", matching ubus's own convention for "no arguments".
func runUbusCall(runner uci.UCIRunner, object, method string, params json.RawMessage) (string, error) {
	arg := "{}"
	if len(params) > 0 {
		arg = string(params)
	}
	return runner.ExecCmd("ubus", "call", object, method, arg)
}

// handleUbusCall runs an ad-hoc `ubus call` requested by the backend and ACKs
// with the raw JSON result. This is the one generic widening of the agent's
// command surface added for plugin support — the agent otherwise has no
// concept of what a "plugin" is.
func (a *Agent) handleUbusCall(cmd Command) {
	var payload UbusCallPayload
	if !a.decodeOrAck(cmd, &payload) {
		return
	}

	if !ubusObjectMethodRe.MatchString(payload.Object) || !ubusObjectMethodRe.MatchString(payload.Method) {
		slog.Error("ubus_call rejected: invalid object/method", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
		a.publishAckUbusCall(cmd.CmdID, "error", "invalid object or method", nil)
		return
	}

	slog.Debug("ubus_call: executing", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)

	out, err := runUbusCall(a.uci, payload.Object, payload.Method, payload.Params)
	if err != nil {
		a.publishAckUbusCall(cmd.CmdID, "error", "ubus call failed: "+err.Error(), nil)
		return
	}

	a.publishAckUbusCall(cmd.CmdID, "ok", "", json.RawMessage(out))
	slog.Info("ubus_call: complete", "cmd_id", cmd.CmdID, "object", payload.Object, "method", payload.Method)
}

// publishAckUbusCall publishes an ACK carrying the raw, unparsed ubus JSON
// result in the "result" field.
func (a *Agent) publishAckUbusCall(cmdID, status, output string, result json.RawMessage) {
	slog.Debug("publishing ubus_call ack", "cmd_id", cmdID, "status", status)
	type ubusCallAckPayload struct {
		CmdID     string          `json:"cmd_id"`
		Status    string          `json:"status"`
		Output    string          `json:"output,omitempty"`
		Timestamp string          `json:"timestamp"`
		Result    json.RawMessage `json:"result,omitempty"`
	}
	ack := ubusCallAckPayload{
		CmdID:     cmdID,
		Status:    status,
		Output:    output,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Result:    result,
	}
	payload, err := json.Marshal(ack)
	if err != nil {
		slog.Error("marshal ubus_call ack", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.mqtt.Publish(ctx, mqttclient.TopicAck(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("publish ubus_call ack", "cmd_id", cmdID, "err", err)
	}
}
