package apply

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ubusTimeout bounds a single `ubus call` invocation. Local IPC to procd, not a
// network op, so this is much shorter than uci.uciTimeout.
const ubusTimeout = 10 * time.Second

// ReloadDiscoverer abstracts the OS-level lookups used to find a reload command
// for a UCI package with no static override entry (see serviceMap in reload.go).
// The real implementation shells out to ubus and reads the filesystem;
// FakeReloadDiscoverer lets tests inject fixture data with no device present.
type ReloadDiscoverer interface {
	// UbusServiceList runs `ubus call service list '{"verbose":true}'` and returns
	// its raw JSON output.
	UbusServiceList() ([]byte, error)
	// ReadUCITrack returns the raw contents of /etc/config/ucitrack.json.
	ReadUCITrack() ([]byte, error)
	// InitScriptExists reports whether /etc/init.d/<name> exists.
	InitScriptExists(name string) bool
}

// OSReloadDiscoverer is the real ReloadDiscoverer, talking to ubus and the filesystem.
type OSReloadDiscoverer struct{}

func (OSReloadDiscoverer) UbusServiceList() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ubusTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "ubus", "call", "service", "list", `{"verbose":true}`).Output() //nolint:gosec
}

func (OSReloadDiscoverer) ReadUCITrack() ([]byte, error) {
	return os.ReadFile("/etc/config/ucitrack.json")
}

func (OSReloadDiscoverer) InitScriptExists(name string) bool {
	_, err := os.Stat("/etc/init.d/" + name)
	return err == nil
}

// FakeReloadDiscoverer is a test double for ReloadDiscoverer with no OS access.
type FakeReloadDiscoverer struct {
	UbusOutput     []byte
	UbusErr        error
	UCITrackOutput []byte
	UCITrackErr    error
	InitScripts    map[string]bool

	// UbusCalls/UCITrackCalls count invocations, so tests can assert the
	// per-Apply() caching in newReloadDiscovery only reads each source once.
	UbusCalls     int
	UCITrackCalls int
}

func (f *FakeReloadDiscoverer) UbusServiceList() ([]byte, error) {
	f.UbusCalls++
	return f.UbusOutput, f.UbusErr
}

func (f *FakeReloadDiscoverer) ReadUCITrack() ([]byte, error) {
	f.UCITrackCalls++
	return f.UCITrackOutput, f.UCITrackErr
}

func (f *FakeReloadDiscoverer) InitScriptExists(name string) bool {
	return f.InitScripts[name]
}

// ucitrackEntry is one package's entry in /etc/config/ucitrack.json: the init.d
// script that owns it, and an optional literal command overriding the default
// "/etc/init.d/<Init> reload".
type ucitrackEntry struct {
	Init string
	Exec string
}

// parseUCITrack extracts pkg -> ucitrackEntry from /etc/config/ucitrack.json,
// e.g. {"network": {"init": "network"}, "dhcp": {"init": "dnsmasq"}}. Malformed
// JSON yields an empty map rather than an error — a missing/unreadable file is a
// normal "tier empty" outcome, not a failure.
func parseUCITrack(raw []byte) map[string]ucitrackEntry {
	result := make(map[string]ucitrackEntry)
	var parsed map[string]struct {
		Init string `json:"init"`
		Exec string `json:"exec"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return result
	}
	for pkg, e := range parsed {
		if e.Init == "" && e.Exec == "" {
			continue
		}
		result[pkg] = ucitrackEntry{Init: e.Init, Exec: e.Exec}
	}
	return result
}

// parseUbusTriggers extracts pkg -> reload command from `ubus call service list
// '{"verbose":true}'` output, by walking each running instance's registered procd
// reload triggers (procd_add_reload_trigger in the package's own init script).
//
// Procd's trigger-rule nesting isn't parsed into a fixed struct because its exact
// shape has varied across OpenWrt releases; this walks generically
// ([]interface{}/map[string]interface{}) and skips anything unrecognized instead
// of erroring. The assumed rule shape is
// ["config.change", "<pkg>", ["run_command", ["/etc/init.d/<pkg>", "reload"]]] —
// verify against a real device capture (see reload_discovery_test.go) before
// relying on this for a new OpenWrt release.
func parseUbusTriggers(raw []byte) map[string]string {
	result := make(map[string]string)
	var services map[string]interface{}
	if err := json.Unmarshal(raw, &services); err != nil {
		return result
	}
	for _, svc := range services {
		svcMap, ok := svc.(map[string]interface{})
		if !ok {
			continue
		}
		instances, ok := svcMap["instances"].(map[string]interface{})
		if !ok {
			continue
		}
		for _, inst := range instances {
			instMap, ok := inst.(map[string]interface{})
			if !ok {
				continue
			}
			triggers, ok := instMap["triggers"].([]interface{})
			if !ok {
				continue
			}
			for _, t := range triggers {
				if pkg, cmd, ok := parseTriggerRule(t); ok {
					result[pkg] = cmd
				}
			}
		}
	}
	return result
}

// parseTriggerRule extracts (package name, reload command) from one procd trigger
// rule, e.g. ["config.change", "usteer", ["run_command", ["/etc/init.d/usteer", "reload"]]].
func parseTriggerRule(rule interface{}) (pkg string, cmd string, ok bool) {
	arr, isArr := rule.([]interface{})
	if !isArr || len(arr) < 3 {
		return "", "", false
	}
	event, _ := arr[0].(string)
	if event != "config.change" {
		return "", "", false
	}
	pkg, isStr := arr[1].(string)
	if !isStr {
		return "", "", false
	}
	argv := findRunCommand(arr[2:])
	if len(argv) == 0 {
		return "", "", false
	}
	return pkg, strings.Join(argv, " "), true
}

// findRunCommand searches (possibly nested) trigger action elements for a
// "run_command" action and returns its argv, flattening any nested arrays.
func findRunCommand(elems []interface{}) []string {
	for i, e := range elems {
		if s, ok := e.(string); ok && s == "run_command" {
			return flattenStrings(elems[i+1:])
		}
		if nested, ok := e.([]interface{}); ok {
			if argv := findRunCommand(nested); len(argv) > 0 {
				return argv
			}
		}
	}
	return nil
}

func flattenStrings(elems []interface{}) []string {
	var out []string
	for _, e := range elems {
		switch v := e.(type) {
		case string:
			out = append(out, v)
		case []interface{}:
			out = append(out, flattenStrings(v)...)
		}
	}
	return out
}
