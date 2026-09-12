package agent

import (
	"encoding/json"
	"log/slog"
	"regexp"

	"github.com/OliverKruecken/waverms-agent/internal/filewriter"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// rcdDir is where OpenWrt's rc.common tracks boot-time service enablement as
// S<NN><name> (started) / K<NN><name> (killed) symlinks into /etc/init.d —
// a plain filesystem convention with no ubus/procd equivalent.
const rcdDir = "/etc/rc.d"

// rcdSymlinkRe splits an /etc/rc.d entry into its S/K kind and service name,
// stripping the two-digit ordering prefix. Anchored so e.g. "S50dnsmasq-full"
// captures the full "dnsmasq-full" suffix rather than letting a substring
// match against the shorter service name "dnsmasq".
var rcdSymlinkRe = regexp.MustCompile(`^([SK])[0-9]+(.+)$`)

// ubusServiceListEntry is one service's entry in `ubus call service list
// '{"verbose":true}'`'s response — a JSON object keyed by service name, each
// carrying zero or more named instances. Only the "running" field of each
// instance is needed here.
type ubusServiceListEntry struct {
	Instances map[string]struct {
		Running bool `json:"running"`
	} `json:"instances"`
}

// runUbusServiceList asks procd for the live state of every registered
// service, mirroring the same `ubus call service list` used by
// internal/apply's UCI-reload-trigger discovery — one call covering every
// service instead of an exec per service.
func runUbusServiceList(runner uci.UCIRunner) (string, error) {
	return runner.ExecCmd("ubus", "call", "service", "list", `{"verbose":true}`)
}

// parseUbusServiceRunning decodes a `ubus call service list` response into a
// name -> running map. A service is "running" if any of its instances report
// running:true. Malformed JSON yields an empty map rather than an error,
// matching this package's best-effort discovery philosophy.
func parseUbusServiceRunning(raw []byte) map[string]bool {
	result := make(map[string]bool)
	var services map[string]ubusServiceListEntry
	if err := json.Unmarshal(raw, &services); err != nil {
		return result
	}
	for name, svc := range services {
		running := false
		for _, inst := range svc.Instances {
			if inst.Running {
				running = true
				break
			}
		}
		result[name] = running
	}
	return result
}

// rcdEnabledSet decodes a listing of rcdDir into a name -> enabled map, using
// an exact match on the symlink's suffix (after its S/K + ordering-number
// prefix) so e.g. a "dnsmasq-full" symlink can never mark "dnsmasq" enabled.
func rcdEnabledSet(entries []filewriter.DirEntry) map[string]bool {
	enabled := make(map[string]bool)
	for _, e := range entries {
		if !e.IsRegular && !e.IsSymlink {
			continue
		}
		m := rcdSymlinkRe.FindStringSubmatch(e.Name)
		if m == nil {
			continue
		}
		if m[1] == "S" {
			enabled[m[2]] = true
		}
	}
	return enabled
}

// discoverServices scans initdDir for service scripts and reports their
// enabled/running state. initdDir's listing stays the master list of known
// service names (unchanged from before); "enabled" and "running" are each
// resolved from one batched read instead of a shell exec per service:
// enabled from rcdEnabledSet(rcdDir), running from a single ubus service
// list call. The two sources fail independently and best-effort — a failure
// in one degrades only that dimension to false for every service, it never
// blocks the other or drops a service from the list.
func discoverServices(fw filewriter.FileAccess, runner uci.UCIRunner, initdDir string) []ServiceInfo {
	entries, err := fw.ListDir(initdDir)
	if err != nil {
		slog.Debug("discoverServices: cannot read initd dir", "dir", initdDir, "err", err)
		return nil
	}

	running := make(map[string]bool)
	if out, err := runUbusServiceList(runner); err != nil {
		slog.Debug("discoverServices: ubus service list failed", "err", err)
	} else {
		running = parseUbusServiceRunning([]byte(out))
	}

	enabled := make(map[string]bool)
	if rcdEntries, err := fw.ListDir(rcdDir); err != nil {
		slog.Debug("discoverServices: cannot read rc.d dir", "dir", rcdDir, "err", err)
	} else {
		enabled = rcdEnabledSet(rcdEntries)
	}

	var services []ServiceInfo
	for _, e := range entries {
		if !e.IsRegular && !e.IsSymlink {
			continue
		}
		name := e.Name
		if !safeIdentifierRe.MatchString(name) {
			continue
		}
		services = append(services, ServiceInfo{Name: name, Enabled: enabled[name], Running: running[name]})
	}
	return services
}
