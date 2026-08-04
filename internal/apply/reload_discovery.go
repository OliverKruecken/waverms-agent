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
// '{"verbose":true}'` output, by walking each service's registered procd
// "config.change" reload triggers (procd_add_reload_trigger in the package's own
// init script). "triggers" is a top-level field of the service object itself, not
// nested under "instances" — a service with no running instance (or no instances
// key at all, e.g. "cron") can still declare triggers.
//
// Rule shape, confirmed against a live device capture (23.05-era procd):
//
//	["config.change", ["if", ["eq","package","usteer"], ["run_script","/etc/init.d/usteer","reload"]], 1000]
//
// Anything not matching this shape (other event types like "interface.*", more
// complex conditions than a single "eq package" check) is skipped, not erroring —
// procd's exact expression grammar isn't parsed in full, just this one pattern.
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
		triggers, ok := svcMap["triggers"].([]interface{})
		if !ok {
			continue
		}
		for _, t := range triggers {
			if pkg, cmd, ok := parseTriggerRule(t); ok {
				result[pkg] = cmd
			}
		}
	}
	return result
}

// parseTriggerRule extracts (package name, reload command) from one procd
// "config.change" trigger rule of the form
// ["config.change", ["if", ["eq","package","<pkg>"], ["run_script", ...argv]], <priority>].
func parseTriggerRule(rule interface{}) (pkg string, cmd string, ok bool) {
	arr, isArr := rule.([]interface{})
	if !isArr || len(arr) < 2 {
		return "", "", false
	}
	if event, _ := arr[0].(string); event != "config.change" {
		return "", "", false
	}
	expr, isArr := arr[1].([]interface{})
	if !isArr || len(expr) != 3 {
		return "", "", false
	}
	if verb, _ := expr[0].(string); verb != "if" {
		return "", "", false
	}
	pkg, ok = matchPackageCondition(expr[1])
	if !ok {
		return "", "", false
	}
	action, isArr := expr[2].([]interface{})
	if !isArr {
		return "", "", false
	}
	argv := flattenStrings(action)
	if len(argv) < 2 {
		return "", "", false
	}
	if argv[0] != "run_script" && argv[0] != "run_command" {
		return "", "", false
	}
	// Some services (notably the built-in "ucitrack" shim) register indirection
	// rules that just re-publish `ubus call service event` for a DIFFERENT
	// package rather than actually reloading anything for this one — e.g.
	// firewall changing gets echoed as a synthetic "luci-splash" package change
	// for whatever else might be listening. That's not a usable reload command.
	if argv[1] == "ubus" {
		return "", "", false
	}
	return pkg, strings.Join(argv[1:], " "), true
}

// matchPackageCondition extracts the package name from an ["eq", "package", "<pkg>"]
// condition. Any other condition shape (e.g. multiple ANDed checks) isn't
// resolvable to a single package name and is skipped.
func matchPackageCondition(cond interface{}) (string, bool) {
	arr, isArr := cond.([]interface{})
	if !isArr || len(arr) != 3 {
		return "", false
	}
	op, _ := arr[0].(string)
	field, _ := arr[1].(string)
	pkg, isStr := arr[2].(string)
	if op != "eq" || field != "package" || !isStr {
		return "", false
	}
	return pkg, true
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
