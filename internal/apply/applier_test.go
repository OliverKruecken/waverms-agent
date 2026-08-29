package apply_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/apply"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wirelessMergeConfig = `{
  "wireless": {
    ".mode": "merge",
    "wifi-iface": [
      { ".name": "default_radio0", "ssid": "MyNetwork", "encryption": "psk2" }
    ]
  }
}`

// setValuesFor finds the SetValuesCall for pkg.section, if any.
func setValuesFor(mock *uci.MockUCIRunner, pkg, section string) (map[string]interface{}, bool) {
	for _, c := range mock.SetValuesCalls {
		if c.Pkg == pkg && c.Section == section {
			return c.Values, true
		}
	}
	return nil, false
}

func TestApply_NamedSection_AddsAndSetsValues(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	_, err := a.Apply(json.RawMessage(wirelessMergeConfig))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "add wireless wifi-iface default_radio0")
	values, ok := setValuesFor(mock, "wireless", "default_radio0")
	require.True(t, ok, "expected a SetValues call for wireless.default_radio0")
	assert.Equal(t, "MyNetwork", values["ssid"])
	assert.Equal(t, "psk2", values["encryption"])
	assert.Contains(t, mock.Calls, "commit wireless")
}

func TestApply_ListOption_SetsWholeListInOneCall(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "network": {
    ".mode": "merge",
    "interface": [
      { ".name": "lan", "proto": "static", "dns": ["8.8.8.8", "8.8.4.4"] }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	values, ok := setValuesFor(mock, "network", "lan")
	require.True(t, ok)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, values["dns"])
	assert.Contains(t, mock.Calls, "commit network")
}

func TestApply_ReplaceMode_DeletesUnwantedSections(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			// extra_iface is in current config but absent from desired config.
			"wireless": {
				{ID: "default_radio0", Type: "wifi-iface", Name: "default_radio0"},
				{ID: "extra_iface", Type: "wifi-iface", Name: "extra_iface"},
			},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "wireless": {
    ".mode": "replace",
    "wifi-iface": [
      { ".name": "default_radio0", "ssid": "NewSSID" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "delete wireless.extra_iface")
	assert.NotContains(t, mock.Calls, "delete wireless.default_radio0")
	values, ok := setValuesFor(mock, "wireless", "default_radio0")
	require.True(t, ok)
	assert.Equal(t, "NewSSID", values["ssid"])
}

func TestApply_ReplaceMode_KeepsDesiredNamedSection(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"wireless": {{ID: "default_radio0", Type: "wifi-iface", Name: "default_radio0"}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "wireless": {
    ".mode": "replace",
    "wifi-iface": [
      { ".name": "default_radio0", "ssid": "MySSID" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.NotContains(t, mock.Calls, "delete wireless.default_radio0")
	values, ok := setValuesFor(mock, "wireless", "default_radio0")
	require.True(t, ok)
	assert.Equal(t, "MySSID", values["ssid"])
}

func TestApply_AnonymousSection_UsesAdd(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "firewall": {
    ".mode": "merge",
    "rule": [
      { "name": "Allow-SSH", "src": "wan", "dest_port": "22", "proto": "tcp", "target": "ACCEPT" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	// Anonymous section: should call Add with no name, not RetypeExisting.
	assert.Contains(t, mock.Calls, "add firewall rule")
	assert.Contains(t, mock.Calls, "commit firewall")
}

func TestApply_StagingError_RevertsAllStagedPackages(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"setvalues wireless.default_radio0": assert.AnError,
		},
	}
	a := apply.New(mock)

	_, err := a.Apply(json.RawMessage(wirelessMergeConfig))
	require.Error(t, err)

	assert.Contains(t, mock.Calls, "revert wireless")
	assert.NotContains(t, mock.Calls, "commit wireless")
}

func TestApply_SkipsMetaKeys(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "packages": { "install": ["kmod-batman-adv"] },
  "reboot": false,
  "system": {
    ".mode": "merge",
    "system": [{ ".name": "system", "hostname": "router-01" }]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "commit system")
	for _, call := range mock.Calls {
		assert.NotContains(t, call, "packages")
		assert.NotContains(t, call, "reboot")
	}
}

func TestApply_MultiplePackages_ReturnsAllCommitted(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "system": {
    ".mode": "merge",
    "system": [{ ".name": "system", "hostname": "r1" }]
  },
  "network": {
    ".mode": "merge",
    "interface": [{ ".name": "wan", "proto": "dhcp" }]
  }
}`
	committed, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"system", "network"}, committed)
}

func TestApply_Phase2CommitError_RevertsRemainingPackages(t *testing.T) {
	// Two-package apply (network < system alphabetically).
	// network commits first; system commit fails.
	// system must be reverted; network (already committed) must NOT be reverted.
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"commit system": assert.AnError,
		},
	}
	a := apply.New(mock)

	cfg := `{
  "system": {
    ".mode": "merge",
    "system": [{ ".name": "system", "hostname": "r1" }]
  },
  "network": {
    ".mode": "merge",
    "interface": [{ ".name": "wan", "proto": "dhcp" }]
  }
}`
	committed, err := a.Apply(json.RawMessage(cfg))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit system")

	// network (alphabetically first) committed successfully.
	assert.Equal(t, []string{"network"}, committed)

	// system must have been reverted after its commit failed.
	assert.Contains(t, mock.Calls, "revert system")

	// network must NOT be reverted — it was already committed.
	assert.NotContains(t, mock.Calls, "revert network")
}

func TestApply_Phase2CommitError_RevertsAllRemainingWhenFirstFails(t *testing.T) {
	// Three packages; the first commit fails → the other two must be reverted.
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"commit dhcp": assert.AnError,
		},
	}
	a := apply.New(mock)

	cfg := `{
  "dhcp":    { ".mode": "merge", "dnsmasq": [{ ".name": "cfg01", "domain": "lan" }] },
  "network": { ".mode": "merge", "interface": [{ ".name": "wan", "proto": "dhcp" }] },
  "system":  { ".mode": "merge", "system": [{ ".name": "system", "hostname": "r1" }] }
}`
	committed, err := a.Apply(json.RawMessage(cfg))
	require.Error(t, err)
	assert.Empty(t, committed)

	// dhcp commit failed — dhcp itself, network, and system must all be reverted.
	assert.Contains(t, mock.Calls, "revert dhcp")
	assert.Contains(t, mock.Calls, "revert network")
	assert.Contains(t, mock.Calls, "revert system")
}

func TestApply_SectionTypesAppliedInDeterministicOrder(t *testing.T) {
	// A package with two section types must always stage them in sorted
	// (alphabetical) order, regardless of JSON key insertion order.
	// We run Apply 10 times and verify the UCI call sequence is identical
	// every time — a random map iteration would produce different orderings.
	const cfg = `{
  "firewall": {
    ".mode": "merge",
    "rule":      [{ ".name": "ssh",  "dest_port": "22" }],
    "redirect":  [{ ".name": "nat1", "dest_port": "80" }]
  }
}`
	var firstRun []string
	for i := 0; i < 10; i++ {
		mock := &uci.MockUCIRunner{}
		a := apply.New(mock)
		_, err := a.Apply(json.RawMessage(cfg))
		require.NoError(t, err)

		if i == 0 {
			firstRun = mock.Calls
		} else {
			assert.Equal(t, firstRun, mock.Calls,
				"UCI call order must be identical across Apply invocations (run %d differs)", i+1)
		}
	}

	// Additionally verify "redirect" (r) comes before "rule" (ru) — sorted order.
	redirectIdx, ruleIdx := -1, -1
	for j, c := range firstRun {
		if strings.Contains(c, "nat1") {
			redirectIdx = j
		}
		if strings.Contains(c, "ssh") {
			ruleIdx = j
		}
	}
	assert.Less(t, redirectIdx, ruleIdx,
		"'redirect' section type (r) must be staged before 'rule' (ru) in alphabetical order")
}

func TestApply_EmptyConfig_ReturnsNoPackages(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	committed, err := a.Apply(json.RawMessage(`{}`))
	require.NoError(t, err)
	assert.Empty(t, committed)
	assert.Empty(t, mock.Calls)
}

func TestApply_MergeMode_RemovesStaleOption(t *testing.T) {
	// Device has "disabled='1'" on wifinet0 but desired config does not include it.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"wireless": {{
				ID: "wifinet0", Type: "wifi-iface", Name: "wifinet0",
				Options: map[string]interface{}{"mode": "mesh", "disabled": "1"},
			}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "wireless": {
    ".mode": "merge",
    "wifi-iface": [
      { ".name": "wifinet0", "mode": "mesh" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "deleteoptions wireless.wifinet0 [disabled]",
		"stale option 'disabled' should be removed")
	for _, c := range mock.Calls {
		if strings.HasPrefix(c, "deleteoptions") {
			assert.NotContains(t, c, "mode", "desired option 'mode' must not be deleted")
		}
	}
}

func TestApply_AnonymousSection_NewSection_SkipsStaleClean(t *testing.T) {
	// No existing anonymous sections → Add() is called and there are no prior
	// options to clean. cleanStaleOptions must NOT run (nothing to clean).
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "firewall": {
    ".mode": "merge",
    "rule": [
      { "name": "Allow-SSH", "dest_port": "22" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	for _, c := range mock.Calls {
		assert.NotContains(t, c, "deleteoptions",
			"cleanStaleOptions must not run for newly-created anonymous sections")
	}
}

func TestApply_AnonymousSection_ReuseExisting_CleansStaleOptions(t *testing.T) {
	// Device has @dnsmasq[0] (real id cfg-dnsmasq0) with "authoritative" and
	// "boguspriv" set. Desired config only specifies "authoritative"; "boguspriv"
	// must be removed so the deploy resolves drift instead of leaving extra
	// options on the device.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"dhcp": {{
				ID: "cfg-dnsmasq0", Type: "dnsmasq", Anonymous: true,
				Options: map[string]interface{}{"authoritative": "1", "boguspriv": "1"},
			}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "dhcp": {
    ".mode": "merge",
    "dnsmasq": [
      { "authoritative": "1" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "deleteoptions dhcp.cfg-dnsmasq0 [boguspriv]",
		"stale option 'boguspriv' should be removed from reused anonymous section")
	assert.Contains(t, mock.Calls, "commit dhcp")
}

func TestApply_AnonymousSection_MergeReuseExisting(t *testing.T) {
	// Device already has an anonymous @system[0] (real id cfg-system0); applying
	// desired config must update it in place (no Add call, no duplicate section).
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": {{
				ID: "cfg-system0", Type: "system", Anonymous: true,
				Options: map[string]interface{}{"hostname": "OpenWrt", "timezone": "GMT0"},
			}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "system": {
    ".mode": "merge",
    "system": [
      { "hostname": "wrt-test", "timezone": "GMT0" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	// Must reuse cfg-system0, not add a new section.
	assert.NotContains(t, mock.Calls, "add system system",
		"Add must not be called when an existing anonymous section can be reused")
	values, ok := setValuesFor(mock, "system", "cfg-system0")
	require.True(t, ok)
	assert.Equal(t, "wrt-test", values["hostname"])
	assert.Contains(t, mock.Calls, "commit system")
}

func TestApply_AnonymousSection_MergeAddsWhenNoneExist(t *testing.T) {
	// No existing anonymous sections → Add() must still be called.
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	cfg := `{
  "system": {
    ".mode": "merge",
    "system": [
      { "hostname": "wrt-test" }
    ]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "add system system")
}

func TestApply_ReplaceMode_DeletesEntireUnlistedSectionType(t *testing.T) {
	// Regression (waverms.moortwiete.de, wrt-roof): a firewall template with
	// ".mode":"replace" that only lists "defaults" left "rule" and "zone" sections
	// untouched on the device, because stagePackage()'s per-type loop only ever
	// visited section types present in the payload — even in replace mode. Docs
	// say ".mode":"replace" means "wipe + rewrite" the whole package; the fix makes
	// replace mode delete every existing section of ANY type not kept by the payload.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"firewall": {
				{ID: "cfg-defaults0", Type: "defaults", Anonymous: true},
				{ID: "cfg-rule0", Type: "rule", Anonymous: true, Options: map[string]interface{}{"name": "Allow-Ping"}},
				{ID: "cfg-zone0", Type: "zone", Anonymous: true, Options: map[string]interface{}{"name": "lan"}},
			},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "firewall": {
    ".mode": "replace",
    "defaults": { "input": "ACCEPT", "output": "ACCEPT", "forward": "ACCEPT" }
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "delete firewall.cfg-rule0",
		"rule section must be deleted even though the template never mentions the rule type")
	assert.Contains(t, mock.Calls, "delete firewall.cfg-zone0",
		"zone section must be deleted even though the template never mentions the zone type")
	assert.Contains(t, mock.Calls, "delete firewall.cfg-defaults0",
		"old anonymous defaults section must be deleted before the new one is added")
	assert.Contains(t, mock.Calls, "add firewall defaults")
}

func TestApply_ReplaceMode_UnlistedTypeKeepsNamedSectionFromListedType(t *testing.T) {
	// A named section kept by one listed section type must survive the whole-package
	// sweep even though it's discovered via a different existingSectionTypes() entry.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"firewall": {
				{ID: "lan", Type: "zone", Name: "lan"},
				{ID: "cfg-rule0", Type: "rule", Anonymous: true, Options: map[string]interface{}{"name": "Allow-Ping"}},
			},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "firewall": {
    ".mode": "replace",
    "zone": [{ ".name": "lan", "input": "ACCEPT" }]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.NotContains(t, mock.Calls, "delete firewall.lan",
		"named zone section listed in the template must be kept")
	assert.Contains(t, mock.Calls, "delete firewall.cfg-rule0",
		"rule section must still be deleted — it's not in the template at all")
	values, ok := setValuesFor(mock, "firewall", "lan")
	require.True(t, ok)
	assert.Equal(t, "ACCEPT", values["input"])
}

func TestApply_ReplaceMode_DeletesEachAnonSectionByItsStableID(t *testing.T) {
	// Simulates the production scenario that used to require reverse-order
	// deletion under the CLI's positional @type[N] addressing: network has three
	// anonymous bridge-vlan sections and none survive in the desired config.
	// With real, stable ids there's no index-shift hazard — deletion order no
	// longer matters, unlike the old @type[N] scheme.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"network": {
				{ID: "cfg-bv0", Type: "bridge-vlan", Anonymous: true, Options: map[string]interface{}{"device": "br-lan"}},
				{ID: "cfg-bv1", Type: "bridge-vlan", Anonymous: true, Options: map[string]interface{}{"device": "br-lan"}},
				{ID: "cfg-bv2", Type: "bridge-vlan", Anonymous: true, Options: map[string]interface{}{"device": "br-lan"}},
			},
		},
	}
	a := apply.New(mock)

	// bridge-vlan is in the desired config as an empty list so replace mode
	// calls deleteUnwantedSections for that type and removes all three sections.
	cfg := `{
  "network": {
    ".mode": "replace",
    "bridge-vlan": [],
    "interface": [{ ".name": "loopback", "proto": "static" }]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "delete network.cfg-bv0")
	assert.Contains(t, mock.Calls, "delete network.cfg-bv1")
	assert.Contains(t, mock.Calls, "delete network.cfg-bv2")
}

func TestApply_NamedSection_RetypesWhenExistingTypeDiffers(t *testing.T) {
	// A named section already exists on the device but under the wrong type —
	// the one case that still goes through the CLI (RetypeExisting), since
	// rpcd's uci "set" method has no parameter to change an existing section's type.
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"network": {{ID: "wan", Type: "interface", Name: "wan"}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "network": {
    ".mode": "merge",
    "alias": [{ ".name": "wan", "interface": "wan_dev" }]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "set-type network.wan=alias")
	assert.NotContains(t, mock.Calls, "add network alias wan",
		"must not Add a section that already exists on the device")
}

func TestApply_NamedSection_NoRetypeWhenExistingTypeMatches(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"network": {{ID: "wan", Type: "interface", Name: "wan", Options: map[string]interface{}{"proto": "static"}}},
		},
	}
	a := apply.New(mock)

	cfg := `{
  "network": {
    ".mode": "merge",
    "interface": [{ ".name": "wan", "proto": "dhcp" }]
  }
}`
	_, err := a.Apply(json.RawMessage(cfg))
	require.NoError(t, err)

	for _, c := range mock.Calls {
		assert.NotContains(t, c, "set-type", "type already matches — no retype call expected")
	}
	assert.NotContains(t, mock.Calls, "add network interface wan")
}
