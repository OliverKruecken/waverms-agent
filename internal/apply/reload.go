package apply

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// serviceEntry holds the reload command and the init.d service name used to
// check whether the service is enabled before reloading.
type serviceEntry struct {
	reloadCmd   string
	initService string // name passed to /etc/init.d/<name> enabled
}

// serviceMap is the top-priority reload tier: OpenWrt-core packages whose reload
// semantics aren't expressible via the generic ubus/ucitrack/init.d discovery
// tiers below (e.g. "wifi reload" is a netifd command, not a
// "/etc/init.d/wireless" script — no such script exists). For "wireless", netifd
// (managed by the "network" init.d service) controls the wifi stack, so its
// enabled state is checked via "network". Checking this tier first also
// guarantees zero behavior change for the packages it already covered before
// generic discovery existed.
var serviceMap = map[string]serviceEntry{
	"wireless": {reloadCmd: "wifi reload", initService: "network"},
	"network":  {reloadCmd: "/etc/init.d/network reload", initService: "network"},
	"system":   {reloadCmd: "/etc/init.d/system reload", initService: "system"},
	"firewall": {reloadCmd: "/etc/init.d/firewall reload", initService: "firewall"},
	"dhcp":     {reloadCmd: "/etc/init.d/dnsmasq reload", initService: "dnsmasq"},
}

// CheckServiceEnabled reports whether the named init.d service is enabled.
// It is a package-level variable so tests can replace it without hitting the OS.
var CheckServiceEnabled = func(name string) bool {
	return exec.Command("/etc/init.d/"+name, "enabled").Run() == nil //nolint:gosec
}

// Discoverer is the OS-facing dependency for the ubus/ucitrack/init.d discovery
// tiers below the static serviceMap override. Package-level var, swappable in
// tests exactly like CheckServiceEnabled.
var Discoverer ReloadDiscoverer = &OSReloadDiscoverer{}

// reloadDiscovery caches one round of ubus + ucitrack.json reads so that
// ServiceReloads/RunReloads invoke each external command/file read at most once
// per call, regardless of how many packages are in pkgNames.
type reloadDiscovery struct {
	ubusTriggers map[string]string        // pkg -> reload cmd, discovered live via ubus
	trackEntries map[string]ucitrackEntry // pkg -> init/exec, from ucitrack.json
}

func newReloadDiscovery(d ReloadDiscoverer) reloadDiscovery {
	var rd reloadDiscovery
	if out, err := d.UbusServiceList(); err != nil {
		slog.Debug("reload discovery: ubus service list unavailable", "err", err)
	} else {
		rd.ubusTriggers = parseUbusTriggers(out)
		slog.Debug("reload discovery: ubus service list parsed", "packages", mapKeys(rd.ubusTriggers))
	}
	if out, err := d.ReadUCITrack(); err != nil {
		slog.Debug("reload discovery: ucitrack.json unavailable", "err", err)
	} else {
		rd.trackEntries = parseUCITrack(out)
		slog.Debug("reload discovery: ucitrack.json parsed", "packages", mapKeys(rd.trackEntries))
	}
	return rd
}

// mapKeys is a small debug-logging helper — slog can't usefully print a raw
// map[string]T group value, so trigger/track tables are logged as a sorted key
// list instead (the discovered commands themselves show up per-package in the
// resolve() debug line below).
func mapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// resolve finds the reload command for pkg by walking the precedence chain:
// static override (OpenWrt-core specials) -> live ubus procd reload trigger ->
// legacy ucitrack.json entry -> package-name-matches-init-script heuristic.
// checkEnabled reports whether CheckServiceEnabled(initService) must gate the
// reload; ubus-discovered commands are not gated, since a service present in
// `ubus service list` already has a live instance — stronger evidence than an
// init.d "enabled" symlink (some procd instances start via hotplug or a
// dependency without ever being explicitly enabled). ok is false if no tier matched.
func (rd reloadDiscovery) resolve(pkg string, d ReloadDiscoverer) (cmd string, checkEnabled bool, initService, tier string, ok bool) {
	if entry, found := serviceMap[pkg]; found {
		return entry.reloadCmd, true, entry.initService, "static", true
	}
	if cmd, found := rd.ubusTriggers[pkg]; found {
		return cmd, false, "", "ubus", true
	}
	if entry, found := rd.trackEntries[pkg]; found {
		reloadCmd := entry.Exec
		init := entry.Init
		if reloadCmd == "" {
			reloadCmd = fmt.Sprintf("/etc/init.d/%s reload", init)
		}
		if init == "" {
			init = pkg
		}
		return reloadCmd, true, init, "ucitrack", true
	}
	if d.InitScriptExists(pkg) {
		return fmt.Sprintf("/etc/init.d/%s reload", pkg), true, pkg, "initd-heuristic", true
	}
	return "", false, "", "none", false
}

// ServiceReloads returns the ordered list of reload commands discovered for the
// given package names, across all discovery tiers. Duplicates are suppressed.
// It does NOT check whether services are enabled; use RunReloads for production
// use where disabled services must be skipped.
func ServiceReloads(pkgNames []string) []string {
	rd := newReloadDiscovery(Discoverer)
	seen := make(map[string]bool)
	var cmds []string
	for _, pkg := range pkgNames {
		cmd, _, _, tier, ok := rd.resolve(pkg, Discoverer)
		slog.Debug("reload discovery: resolved package", "package", pkg, "tier", tier, "command", cmd, "found", ok)
		if ok && !seen[cmd] {
			cmds = append(cmds, cmd)
			seen[cmd] = true
		}
	}
	return cmds
}

// RunReloads executes the discovered reload command for each given package. A
// package with no reload path found in any discovery tier is logged and
// skipped, not treated as an error. Returns a slice of error strings for any
// reload that failed; other reloads continue.
func RunReloads(pkgNames []string) []string {
	rd := newReloadDiscovery(Discoverer)
	seenCmd := make(map[string]bool)
	var errs []string
	for _, pkg := range pkgNames {
		cmd, checkEnabled, initService, tier, ok := rd.resolve(pkg, Discoverer)
		slog.Debug("reload discovery: resolved package", "package", pkg, "tier", tier, "command", cmd, "found", ok, "gated", checkEnabled)
		if !ok {
			slog.Warn("config_apply: no reload path found for package", "package", pkg)
			continue
		}
		if seenCmd[cmd] {
			slog.Debug("config_apply: reload command already run this cycle, skipping", "package", pkg, "command", cmd)
			continue
		}
		seenCmd[cmd] = true

		if checkEnabled && !CheckServiceEnabled(initService) {
			slog.Debug("config_apply: service disabled, skipping reload", "package", pkg, "command", cmd, "init_service", initService)
			continue
		}

		parts := strings.Fields(cmd)
		if len(parts) == 0 {
			continue
		}
		start := time.Now()
		out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput() //nolint:gosec
		slog.Debug("config_apply: reload command finished",
			"package", pkg, "tier", tier, "command", cmd,
			"duration", time.Since(start), "err", err, "output", strings.TrimSpace(string(out)))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s (%s): %v: %s", cmd, tier, err, strings.TrimSpace(string(out))))
		}
	}
	return errs
}
