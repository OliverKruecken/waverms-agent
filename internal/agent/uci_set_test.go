package agent

import (
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── parseUCIAddress ─────────────────────────────────────────────────────────

func TestParseUCIAddress_TwoParts(t *testing.T) {
	addr, err := parseUCIAddress("network.lan")
	require.NoError(t, err)
	assert.Equal(t, uciAddress{Config: "network", Section: "lan"}, addr)
}

func TestParseUCIAddress_ThreeParts(t *testing.T) {
	addr, err := parseUCIAddress("network.lan.proto")
	require.NoError(t, err)
	assert.Equal(t, uciAddress{Config: "network", Section: "lan", Option: "proto"}, addr)
}

func TestParseUCIAddress_PositionalSection(t *testing.T) {
	addr, err := parseUCIAddress("system.@system[0].hostname")
	require.NoError(t, err)
	assert.Equal(t, uciAddress{Config: "system", Section: "@system[0]", Option: "hostname"}, addr)
}

func TestParseUCIAddress_Invalid(t *testing.T) {
	for _, s := range []string{"", "network", ".lan", "network."} {
		_, err := parseUCIAddress(s)
		assert.Error(t, err, "expected error for %q", s)
	}
}

// ── resolveUCISection ───────────────────────────────────────────────────────

func TestResolveUCISection_LiteralNameUnchanged(t *testing.T) {
	id, err := resolveUCISection(nil, uciAddress{Config: "network", Section: "lan"})
	require.NoError(t, err)
	assert.Equal(t, "lan", id)
}

func TestResolveUCISection_PositionalResolvesToID(t *testing.T) {
	sections := []uci.Section{
		{ID: "cfg01", Type: "system", Anonymous: true},
		{ID: "cfg02", Type: "system", Anonymous: true},
	}
	id, err := resolveUCISection(sections, uciAddress{Config: "system", Section: "@system[1]"})
	require.NoError(t, err)
	assert.Equal(t, "cfg02", id)
}

func TestResolveUCISection_NegativeIndexResolvesFromEnd(t *testing.T) {
	sections := []uci.Section{
		{ID: "cfg01", Type: "system", Anonymous: true},
		{ID: "cfg02", Type: "system", Anonymous: true},
	}
	id, err := resolveUCISection(sections, uciAddress{Config: "system", Section: "@system[-1]"})
	require.NoError(t, err)
	assert.Equal(t, "cfg02", id)
}

func TestResolveUCISection_OnlyMatchesAnonymousOfType(t *testing.T) {
	sections := []uci.Section{
		{ID: "lan", Type: "interface", Anonymous: false, Name: "lan"},
		{ID: "cfg01", Type: "interface", Anonymous: true},
	}
	id, err := resolveUCISection(sections, uciAddress{Config: "network", Section: "@interface[0]"})
	require.NoError(t, err)
	assert.Equal(t, "cfg01", id)
}

func TestResolveUCISection_OutOfRangeErrors(t *testing.T) {
	sections := []uci.Section{{ID: "cfg01", Type: "system", Anonymous: true}}
	_, err := resolveUCISection(sections, uciAddress{Config: "system", Section: "@system[5]"})
	assert.Error(t, err)
}

func TestResolveUCISection_EmptyErrors(t *testing.T) {
	_, err := resolveUCISection(nil, uciAddress{Config: "system", Section: "@system[0]"})
	assert.Error(t, err)
}

// ── runUCIGet ────────────────────────────────────────────────────────────────

func TestRunUCIGet_SectionOnlyReturnsType(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan"}},
	}}
	out, err := runUCIGet(m, []string{"network.lan"})
	require.NoError(t, err)
	assert.Equal(t, "interface", out)
}

func TestRunUCIGet_ScalarOption(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"proto": "static"}}},
	}}
	out, err := runUCIGet(m, []string{"network.lan.proto"})
	require.NoError(t, err)
	assert.Equal(t, "static", out)
}

func TestRunUCIGet_ListOptionJoinedByNewline(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"dns": []string{"1.1.1.1", "8.8.8.8"}}}},
	}}
	out, err := runUCIGet(m, []string{"network.lan.dns"})
	require.NoError(t, err)
	assert.Equal(t, "1.1.1.1\n8.8.8.8", out)
}

func TestRunUCIGet_UnknownSectionErrors(t *testing.T) {
	m := &uci.MockUCIRunner{}
	_, err := runUCIGet(m, []string{"network.lan"})
	assert.Error(t, err)
}

func TestRunUCIGet_UnknownOptionErrors(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan"}},
	}}
	_, err := runUCIGet(m, []string{"network.lan.missing"})
	assert.Error(t, err)
}

// ── runUCISet ────────────────────────────────────────────────────────────────

func TestRunUCISet_CreatesMissingNamedSection(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := runUCISet(m, []string{"network.guest=interface"})
	require.NoError(t, err)
	require.Len(t, m.AddCalls, 1)
	assert.Equal(t, uci.AddCall{Pkg: "network", SectionType: "interface", Name: "guest"}, m.AddCalls[0])
}

func TestRunUCISet_RetypesExistingSectionWithDifferentType(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "wan", Type: "interface", Name: "wan"}},
	}}
	err := runUCISet(m, []string{"network.wan=alias"})
	require.NoError(t, err)
	assert.Contains(t, m.Calls, "set-type network.wan=alias")
}

func TestRunUCISet_NoopWhenTypeAlreadyMatches(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "wan", Type: "interface", Name: "wan"}},
	}}
	err := runUCISet(m, []string{"network.wan=interface"})
	require.NoError(t, err)
	assert.Empty(t, m.AddCalls)
	assert.NotContains(t, m.Calls, "set-type network.wan=interface")
}

func TestRunUCISet_OptionSetsValue(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := runUCISet(m, []string{"network.lan.proto=static"})
	require.NoError(t, err)
	require.Len(t, m.SetValuesCalls, 1)
	assert.Equal(t, map[string]interface{}{"proto": "static"}, m.SetValuesCalls[0].Values)
}

// ── runUCIDelete ─────────────────────────────────────────────────────────────

func TestRunUCIDelete_WholeSection(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := runUCIDelete(m, []string{"network.lan"})
	require.NoError(t, err)
	assert.Contains(t, m.Calls, "delete network.lan")
}

func TestRunUCIDelete_SingleOption(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := runUCIDelete(m, []string{"network.lan.proto"})
	require.NoError(t, err)
	assert.Contains(t, m.Calls, "deleteoptions network.lan [proto]")
}

// ── modifyUCIList (add_list/del_list) ───────────────────────────────────────

func TestModifyUCIList_AddToAbsentOptionCreatesSingleElementList(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := modifyUCIList(m, []string{"network.lan.dns=1.1.1.1"}, "add_list", func(cur []string, v string) []string {
		return append(cur, v)
	})
	require.NoError(t, err)
	require.Len(t, m.SetValuesCalls, 1)
	assert.Equal(t, map[string]interface{}{"dns": []string{"1.1.1.1"}}, m.SetValuesCalls[0].Values)
}

func TestModifyUCIList_AddAppendsToExistingListAllowingDuplicates(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"dns": []string{"1.1.1.1"}}}},
	}}
	err := modifyUCIList(m, []string{"network.lan.dns=1.1.1.1"}, "add_list", func(cur []string, v string) []string {
		return append(cur, v)
	})
	require.NoError(t, err)
	require.Len(t, m.SetValuesCalls, 1)
	assert.Equal(t, map[string]interface{}{"dns": []string{"1.1.1.1", "1.1.1.1"}}, m.SetValuesCalls[0].Values)
}

func TestModifyUCIList_DelRemovesMatchingEntries(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"dns": []string{"1.1.1.1", "8.8.8.8"}}}},
	}}
	err := modifyUCIList(m, []string{"network.lan.dns=1.1.1.1"}, "del_list", func(cur []string, v string) []string {
		out := make([]string, 0, len(cur))
		for _, c := range cur {
			if c != v {
				out = append(out, c)
			}
		}
		return out
	})
	require.NoError(t, err)
	require.Len(t, m.SetValuesCalls, 1)
	assert.Equal(t, map[string]interface{}{"dns": []string{"8.8.8.8"}}, m.SetValuesCalls[0].Values)
}

func TestModifyUCIList_DelEmptyingListDeletesOptionInstead(t *testing.T) {
	m := &uci.MockUCIRunner{Sections: map[string][]uci.Section{
		"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"dns": []string{"1.1.1.1"}}}},
	}}
	err := modifyUCIList(m, []string{"network.lan.dns=1.1.1.1"}, "del_list", func(cur []string, v string) []string {
		out := make([]string, 0, len(cur))
		for _, c := range cur {
			if c != v {
				out = append(out, c)
			}
		}
		return out
	})
	require.NoError(t, err)
	assert.Empty(t, m.SetValuesCalls)
	assert.Contains(t, m.Calls, "deleteoptions network.lan [dns]")
}

func TestModifyUCIList_MissingOptionErrors(t *testing.T) {
	m := &uci.MockUCIRunner{}
	err := modifyUCIList(m, []string{"network.lan=interface"}, "add_list", func(cur []string, v string) []string { return cur })
	assert.Error(t, err)
}
