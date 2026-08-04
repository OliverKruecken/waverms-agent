package apply

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ubusUsteerFixture is a trimmed excerpt of a real `ubus call service list
// '{"verbose":true}'` capture from an OpenWrt 23.05 device running usteer —
// confirmed live (2026-08-04) rather than hand-written from memory of procd's
// trigger-rule schema. "triggers" sits directly on the service object, not
// nested under "instances"; the "config.change" rule wraps its package check
// in an ["if", ["eq","package",pkg], action] expression, and the action verb is
// "run_script" with flat argv, not "run_command" with nested argv.
const ubusUsteerFixture = `{
	"usteer": {
		"instances": {
			"instance1": { "running": true, "pid": 2132, "command": ["/sbin/usteerd"] }
		},
		"triggers": [
			["config.change", ["if", ["eq", "package", "usteer"], ["run_script", "/etc/init.d/usteer", "reload"]], 1000],
			["interface.*", [["run_script", "/etc/init.d/usteer", "reload"]], 2000]
		]
	}
}`

func TestParseUbusTriggers_ValidTrigger(t *testing.T) {
	result := parseUbusTriggers([]byte(ubusUsteerFixture))
	assert.Equal(t, "/etc/init.d/usteer reload", result["usteer"])
}

func TestParseUbusTriggers_NonConfigChangeEventSkipped(t *testing.T) {
	// usteer's second trigger fires on "interface.*", not "config.change" — it
	// has no package name to key on and must not produce a map entry.
	result := parseUbusTriggers([]byte(ubusUsteerFixture))
	assert.Len(t, result, 1, "only the config.change trigger should be captured")
}

func TestParseUbusTriggers_ForwardingEchoSkipped(t *testing.T) {
	// Real capture: the built-in "ucitrack" service re-publishes a firewall
	// change as a synthetic "luci-splash" package-change event via
	// `ubus call service event ...` rather than reloading anything itself.
	// That's not a usable reload command and must be skipped.
	raw := []byte(`{
		"ucitrack": {
			"triggers": [
				["config.change", ["if", ["eq", "package", "firewall"],
					["run_script", "ubus", "call", "service", "event",
						"{\"type\":\"config.change\",\"data\":{\"package\":\"luci-splash\"}}"]
				], 1000]
			]
		}
	}`)
	result := parseUbusTriggers(raw)
	assert.Empty(t, result, "a ubus-forwarding echo must not be treated as a reload command")
}

func TestParseUbusTriggers_ServiceWithNoInstancesKey(t *testing.T) {
	// Real capture: "cron" has triggers but no "instances" key at all (not just
	// an empty one) — triggers must not require an instances key to be present.
	raw := []byte(`{
		"cron": {
			"triggers": [
				["config.change", ["if", ["eq", "package", "cron"], ["run_script", "/etc/init.d/cron", "reload"]], 1000]
			]
		}
	}`)
	result := parseUbusTriggers(raw)
	assert.Equal(t, "/etc/init.d/cron reload", result["cron"])
}

func TestParseUbusTriggers_MissingTriggersKey(t *testing.T) {
	// Real capture: "ubus" service has no "triggers" field at all.
	raw := []byte(`{"ubus": {"instances": {"instance1": {"running": true}}}}`)
	result := parseUbusTriggers(raw)
	assert.Empty(t, result)
}

func TestParseUbusTriggers_MalformedTriggerRule(t *testing.T) {
	raw := []byte(`{
		"pkg": {
			"triggers": [
				["config.change"],
				"not-an-array",
				["config.change", "not-an-array-condition", 1000],
				["config.change", ["if", ["eq", "package", 123], ["run_script", "reload"]], 1000],
				["config.change", ["if", ["and", ["eq","package","a"],["eq","package","b"]], ["run_script","/etc/init.d/a","reload"]], 1000],
				["config.change", ["if", ["eq", "package", "pkg"], ["not_run_script"]], 1000]
			]
		}
	}`)
	assert.NotPanics(t, func() {
		result := parseUbusTriggers(raw)
		assert.Empty(t, result)
	})
}

func TestParseUbusTriggers_GarbageInput(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.Empty(t, parseUbusTriggers([]byte(`not json`)))
		assert.Empty(t, parseUbusTriggers(nil))
		assert.Empty(t, parseUbusTriggers([]byte(``)))
	})
}

func TestParseUCITrack_InitOnly(t *testing.T) {
	raw := []byte(`{"network": {"init": "network"}, "dhcp": {"init": "dnsmasq"}}`)
	result := parseUCITrack(raw)
	assert.Equal(t, ucitrackEntry{Init: "network"}, result["network"])
	assert.Equal(t, ucitrackEntry{Init: "dnsmasq"}, result["dhcp"])
}

func TestParseUCITrack_ExecOverride(t *testing.T) {
	raw := []byte(`{"somepkg": {"init": "somedaemon", "exec": "/usr/bin/somedaemon-reload"}}`)
	result := parseUCITrack(raw)
	assert.Equal(t, ucitrackEntry{Init: "somedaemon", Exec: "/usr/bin/somedaemon-reload"}, result["somepkg"])
}

func TestParseUCITrack_MalformedJSON(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.Empty(t, parseUCITrack([]byte(`not json`)))
		assert.Empty(t, parseUCITrack(nil))
	})
}

func TestParseUCITrack_EmptyEntrySkipped(t *testing.T) {
	raw := []byte(`{"pkg": {}}`)
	result := parseUCITrack(raw)
	assert.Empty(t, result)
}

func TestOSReloadDiscoverer_InitScriptExists_NonexistentScript(t *testing.T) {
	d := OSReloadDiscoverer{}
	assert.False(t, d.InitScriptExists("definitely-does-not-exist-on-this-machine"))
}

func TestFakeReloadDiscoverer_CountsCalls(t *testing.T) {
	f := &FakeReloadDiscoverer{
		UbusOutput:     []byte(`{}`),
		UCITrackOutput: []byte(`{}`),
	}
	_, _ = f.UbusServiceList()
	_, _ = f.UbusServiceList()
	_, _ = f.ReadUCITrack()

	assert.Equal(t, 2, f.UbusCalls)
	assert.Equal(t, 1, f.UCITrackCalls)
}
