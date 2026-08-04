package apply

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUbusTriggers_ValidTrigger(t *testing.T) {
	raw := []byte(`{
		"usteer": {
			"instances": {
				"instance1": {
					"running": true,
					"triggers": [
						["config.change", "usteer", ["run_command", ["/etc/init.d/usteer", "reload"]]]
					]
				}
			}
		}
	}`)
	result := parseUbusTriggers(raw)
	assert.Equal(t, "/etc/init.d/usteer reload", result["usteer"])
}

func TestParseUbusTriggers_FlatRunCommandArgs(t *testing.T) {
	// Some procd builds emit run_command args flat rather than nested in a
	// sub-array; the parser must handle both shapes.
	raw := []byte(`{
		"usteer": {
			"instances": {
				"instance1": {
					"triggers": [
						["config.change", "usteer", ["run_command", "/etc/init.d/usteer", "reload"]]
					]
				}
			}
		}
	}`)
	result := parseUbusTriggers(raw)
	assert.Equal(t, "/etc/init.d/usteer reload", result["usteer"])
}

func TestParseUbusTriggers_MissingTriggersKey(t *testing.T) {
	raw := []byte(`{"usteer": {"instances": {"instance1": {"running": true}}}}`)
	result := parseUbusTriggers(raw)
	assert.Empty(t, result)
}

func TestParseUbusTriggers_MissingInstancesKey(t *testing.T) {
	raw := []byte(`{"usteer": {"running": true}}`)
	result := parseUbusTriggers(raw)
	assert.Empty(t, result)
}

func TestParseUbusTriggers_MalformedTriggerRule(t *testing.T) {
	raw := []byte(`{
		"usteer": {
			"instances": {
				"instance1": {
					"triggers": [
						["config.change"],
						"not-an-array",
						["config.change", 123, ["run_command", ["reload"]]],
						["config.change", "usteer", ["not_run_command"]]
					]
				}
			}
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
