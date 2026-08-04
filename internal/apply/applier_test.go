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

func TestApply_NamedSection_SetsTypeAndOptions(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	a := apply.New(mock)

	_, err := a.Apply(json.RawMessage(wirelessMergeConfig))
	require.NoError(t, err)

	assert.Contains(t, mock.Calls, "set-type wireless.default_radio0=wifi-iface")
	assert.Contains(t, mock.Calls, "set wireless.default_radio0.ssid=MyNetwork")
	assert.Contains(t, mock.Calls, "set wireless.default_radio0.encryption=psk2")
	assert.Contains(t, mock.Calls, "commit wireless")
}

func TestApply_ListOption_DeletesThenAdds(t *testing.T) {
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

	assert.Contains(t, mock.Calls, "delete-option network.lan.dns")
	assert.Contains(t, mock.Calls, "add_list network.lan.dns=8.8.8.8")
	assert.Contains(t, mock.Calls, "add_list network.lan.dns=8.8.4.4")
	assert.Contains(t, mock.Calls, "commit network")
}

func TestApply_ReplaceMode_DeletesUnwantedSections(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			// extra_iface is in current config but absent from desired config.
			"show wireless": "wireless.default_radio0=wifi-iface\nwireless.extra_iface=wifi-iface\n",
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
	assert.Contains(t, mock.Calls, "set wireless.default_radio0.ssid=NewSSID")
}

func TestApply_ReplaceMode_KeepsDesiredNamedSection(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"show wireless": "wireless.default_radio0=wifi-iface\n",
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
	assert.Contains(t, mock.Calls, "set wireless.default_radio0.ssid=MySSID")
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

	// Anonymous section: should call Add, not SetType.
	found := false
	for _, c := range mock.Calls {
		if c == "add firewall rule" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected 'add firewall rule' call for anonymous section")
	assert.Contains(t, mock.Calls, "commit firewall")
}

func TestApply_StagingError_RevertsAllStagedPackages(t *testing.T) {
	mock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"set wireless.default_radio0.ssid=MyNetwork": assert.AnError,
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
		Results: map[string]string{
			"show wireless": "wireless.wifinet0=wifi-iface\nwireless.wifinet0.mode='mesh'\nwireless.wifinet0.disabled='1'\n",
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

	assert.Contains(t, mock.Calls, "delete-option wireless.wifinet0.disabled",
		"stale option 'disabled' should be removed")
	assert.NotContains(t, mock.Calls, "delete-option wireless.wifinet0.mode",
		"desired option 'mode' must not be deleted")
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
		assert.NotContains(t, c, "delete-option",
			"cleanStaleOptions must not run for newly-created anonymous sections")
	}
}

func TestApply_AnonymousSection_ReuseExisting_CleansStaleOptions(t *testing.T) {
	// Device has @dnsmasq[0] with "authoritative" and "boguspriv" set.
	// Desired config only specifies "authoritative". "boguspriv" must be removed
	// so the deploy resolves drift instead of leaving extra options on the device.
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"show dhcp": strings.Join([]string{
				"dhcp.@dnsmasq[0]=dnsmasq",
				"dhcp.@dnsmasq[0].authoritative='1'",
				"dhcp.@dnsmasq[0].boguspriv='1'",
			}, "\n"),
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

	assert.Contains(t, mock.Calls, "delete-option dhcp.@dnsmasq[0].boguspriv",
		"stale option 'boguspriv' should be removed from reused anonymous section")
	assert.NotContains(t, mock.Calls, "delete-option dhcp.@dnsmasq[0].authoritative",
		"desired option 'authoritative' must not be deleted")
	assert.Contains(t, mock.Calls, "commit dhcp")
}

func TestApply_AnonymousSection_MergeReuseExisting(t *testing.T) {
	// Device already has @system[0]; applying desired config must update it in
	// place (no Add call, no duplicate section).
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"show system": "system.@system[0]=system\nsystem.@system[0].hostname=OpenWrt\nsystem.@system[0].timezone=GMT0\n",
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

	// Must reuse @system[0], not add a new section.
	for _, c := range mock.Calls {
		assert.NotEqual(t, "add system system", c,
			"Add must not be called when an existing anonymous section can be reused")
	}
	assert.Contains(t, mock.Calls, "set system.@system[0].hostname=wrt-test")
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
		Results: map[string]string{
			"show firewall": strings.Join([]string{
				"firewall.@defaults[0]=defaults",
				"firewall.@rule[0]=rule",
				"firewall.@rule[0].name='Allow-Ping'",
				"firewall.@zone[0]=zone",
				"firewall.@zone[0].name='lan'",
			}, "\n"),
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

	assert.Contains(t, mock.Calls, "delete firewall.@rule[0]",
		"rule section must be deleted even though the template never mentions the rule type")
	assert.Contains(t, mock.Calls, "delete firewall.@zone[0]",
		"zone section must be deleted even though the template never mentions the zone type")
	assert.Contains(t, mock.Calls, "delete firewall.@defaults[0]",
		"old anonymous defaults section must be deleted before the new one is added")
	assert.Contains(t, mock.Calls, "add firewall defaults")
}

func TestApply_ReplaceMode_UnlistedTypeKeepsNamedSectionFromListedType(t *testing.T) {
	// A named section kept by one listed section type must survive the whole-package
	// sweep even though it's discovered via a different existingSectionTypes() entry.
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"show firewall": strings.Join([]string{
				"firewall.lan=zone",
				"firewall.@rule[0]=rule",
				"firewall.@rule[0].name='Allow-Ping'",
			}, "\n"),
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
	assert.Contains(t, mock.Calls, "delete firewall.@rule[0]",
		"rule section must still be deleted — it's not in the template at all")
	assert.Contains(t, mock.Calls, "set firewall.lan.input=ACCEPT")
}

func TestApply_ReplaceMode_DeletesAnonSectionsInReverseOrder(t *testing.T) {
	// Simulates the production failure: network has @bridge-vlan[0..2] but
	// desired config has no bridge-vlan sections. Without reverse-order deletion,
	// removing @bridge-vlan[0] shifts [1]→[0] and [2]→[1], so the subsequent
	// delete of @bridge-vlan[2] fails because the index no longer exists.
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"show network": strings.Join([]string{
				"network.@bridge-vlan[0]=bridge-vlan",
				"network.@bridge-vlan[0].device='br-lan'",
				"network.@bridge-vlan[1]=bridge-vlan",
				"network.@bridge-vlan[1].device='br-lan'",
				"network.@bridge-vlan[2]=bridge-vlan",
				"network.@bridge-vlan[2].device='br-lan'",
			}, "\n"),
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

	// Extract only the bridge-vlan delete calls in the order they were issued.
	var deleteCalls []string
	for _, c := range mock.Calls {
		if strings.HasPrefix(c, "delete network.@bridge-vlan") {
			deleteCalls = append(deleteCalls, c)
		}
	}

	// Deletions must be issued highest-index-first to avoid index shifting.
	require.Equal(t, []string{
		"delete network.@bridge-vlan[2]",
		"delete network.@bridge-vlan[1]",
		"delete network.@bridge-vlan[0]",
	}, deleteCalls)
}
