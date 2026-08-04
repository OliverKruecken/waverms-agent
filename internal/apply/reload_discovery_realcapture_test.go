package apply

import "testing"

// realUbusServiceListCapture is `ubus call service list '{"verbose":true}'`
// captured live from an OpenWrt 23.05 test device (wrt-test, 2026-08-04),
// trimmed of "validate" blocks and long instance command/jail/mount details
// that don't affect trigger parsing — every "triggers" array is verbatim.
// This is the fixture the plan for this feature called for capturing before
// trusting parseUbusTriggers; an earlier version of the parser (built from
// general knowledge of procd's schema rather than a real sample) didn't match
// this shape at all and silently discovered nothing.
const realUbusServiceListCapture = `{
	"cron": { "triggers": [] },
	"dropbear": {
		"instances": { "instance1": { "running": true, "pid": 1615 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "dropbear"], ["run_script", "/etc/init.d/dropbear", "reload"]], 1000]
		]
	},
	"firewall": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "firewall"], ["run_script", "/etc/init.d/firewall", "reload"]], 1000],
			["service.data.update", ["if", ["eq", "name", "firewall"], ["run_script", "/etc/init.d/firewall", "reload"]], 1000]
		]
	},
	"gpio_switch": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/gpio_switch", "reload"]], 1000]
		]
	},
	"log": {
		"instances": { "logd": { "running": true }, "logremote": { "running": true } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/log", "reload"]], 1000]
		]
	},
	"network": {
		"instances": { "instance1": { "running": true, "pid": 1786 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "network"], ["run_script", "/etc/init.d/network", "reload"]], 1000],
			["config.change", ["if", ["eq", "package", "wireless"], ["run_script", "/etc/init.d/network", "reload"]], 1000]
		]
	},
	"odhcpd": {
		"instances": { "instance1": { "running": true, "pid": 1963 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "dhcp"], ["run_script", "/etc/init.d/odhcpd", "reload"]], 1000],
			["config.change", ["if", ["eq", "package", "network"], ["run_script", "/etc/init.d/odhcpd", "reload"]], 1000],
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/odhcpd", "reload"]], 1000]
		]
	},
	"packet_steering": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "network"], ["run_script", "/etc/init.d/packet_steering", "reload"]], 1000],
			["config.change", ["if", ["eq", "package", "firewall"], ["run_script", "/etc/init.d/packet_steering", "reload"]], 1000],
			["interface.*", [["run_script", "/etc/init.d/packet_steering", "reload"]], 1000]
		]
	},
	"radius": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "radius"], ["run_script", "/etc/init.d/radius", "reload"]], 1000]
		]
	},
	"rpcd": {
		"instances": { "instance1": { "running": true, "pid": 1474 } },
		"triggers": []
	},
	"sysntpd": {
		"instances": { "instance1": { "running": true, "pid": 2808 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/sysntpd", "reload"]], 1000],
			["interface.*", [["run_script", "/etc/init.d/sysntpd", "reload"]], 1000]
		]
	},
	"system": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/system", "reload"]], 1000]
		]
	},
	"ubihealthd": { "instances": { "instance1": { "running": true, "pid": 2886 } }, "triggers": [] },
	"ubus": { "instances": { "instance1": { "running": true, "pid": 921 } } },
	"ucitrack": {
		"triggers": [
			["config.change", ["if", ["eq", "package", "firewall"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"luci-splash\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "firewall"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"qos\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "firewall"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"miniupnpd\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "dhcp"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"odhcpd\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "network"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"dhcp\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "wireless"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"network\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "fstab"], ["run_script", "/sbin/block", "mount"]], 1000],
			["config.change", ["if", ["eq", "package", "system"], ["run_script", "/etc/init.d/led", "reload"]], 1000],
			["config.change", ["if", ["eq", "package", "system"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"luci_statistics\"}}"]
			], 1000],
			["config.change", ["if", ["eq", "package", "system"],
				["run_script", "ubus", "call", "service", "event", "{\"type\":\"config.change\",\"data\":{\"package\":\"dhcp\"}}"]
			], 1000]
		]
	},
	"uhttpd": {
		"instances": { "instance1": { "running": true, "pid": 2081 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "uhttpd"], ["run_script", "/etc/init.d/uhttpd", "reload"]], 1000],
			["acme.renew", [["run_script", "/etc/init.d/uhttpd", "reload"]], 5000]
		]
	},
	"urandom_seed": { "instances": { "urandom_seed": { "running": false } }, "triggers": [] },
	"urngd": { "instances": { "instance1": { "running": true, "pid": 958 } }, "triggers": [] },
	"usteer": {
		"instances": { "instance1": { "running": true, "pid": 2132 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "usteer"], ["run_script", "/etc/init.d/usteer", "reload"]], 1000],
			["interface.*", [["run_script", "/etc/init.d/usteer", "reload"]], 2000]
		]
	},
	"waverms-agent": {
		"instances": { "instance1": { "running": true, "pid": 3005 } },
		"triggers": [
			["config.change", ["if", ["eq", "package", "network"], ["run_script", "/etc/init.d/waverms-agent", "reload"]], 1000]
		]
	},
	"wpad": {
		"instances": { "hostapd": { "running": true, "pid": 1721 }, "supplicant": { "running": true, "pid": 1722 } },
		"triggers": []
	}
}`

func TestParseUbusTriggers_RealDeviceCapture(t *testing.T) {
	result := parseUbusTriggers([]byte(realUbusServiceListCapture))

	// Packages with exactly one direct, non-forwarding reload trigger — the
	// case this feature exists for (a package with no static override entry,
	// discovered purely from what's already running on the device).
	for pkg, want := range map[string]string{
		"dropbear": "/etc/init.d/dropbear reload",
		"radius":   "/etc/init.d/radius reload",
		"uhttpd":   "/etc/init.d/uhttpd reload",
		"usteer":   "/etc/init.d/usteer reload",
		"fstab":    "/sbin/block mount",
	} {
		if got := result[pkg]; got != want {
			t.Errorf("result[%q] = %q, want %q", pkg, got, want)
		}
	}

	// "ubus" declares no triggers key, "cron"/"rpcd"/etc. declare an empty
	// triggers array, "waverms-agent" only triggers on package "network" (not
	// its own package name) — none of these should produce a "ubus"/"cron"/
	// "waverms-agent" map entry.
	for _, pkg := range []string{"ubus", "cron", "rpcd", "waverms-agent"} {
		if _, ok := result[pkg]; ok {
			t.Errorf("result[%q] unexpectedly present: %q", pkg, result[pkg])
		}
	}

	// "luci-splash", "qos", "miniupnpd", "luci_statistics" only ever appear as
	// the *target* package name inside a ucitrack forwarding echo's embedded
	// JSON string — never as an actual condition's package check — so they
	// must never surface as map keys regardless of the forwarding-echo filter.
	for _, pkg := range []string{"luci-splash", "qos", "miniupnpd", "luci_statistics"} {
		if _, ok := result[pkg]; ok {
			t.Errorf("result[%q] unexpectedly present — should never be a trigger condition target", pkg)
		}
	}
}
