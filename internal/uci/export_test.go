package uci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUCIExport_EmptyInput(t *testing.T) {
	result, err := ParseUCIExport("")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestParseUCIExport_WhitespaceOnlyInput(t *testing.T) {
	result, err := ParseUCIExport("   \n\n\t  \n")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestParseUCIExport_PackageLineIsIgnored(t *testing.T) {
	input := `package network

config interface 'loopback'
	option proto 'static'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	// Package line must not appear as a section type.
	_, hasPackage := result["network"]
	assert.False(t, hasPackage, "package line should not produce a section type")
	require.Contains(t, result, "interface")
}

func TestParseUCIExport_AnonymousSection(t *testing.T) {
	input := `config route
	option interface 'wan'
	option target '0.0.0.0'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	require.Len(t, result["route"], 1)
	sec := result["route"][0]
	_, hasName := sec[".name"]
	assert.False(t, hasName, "anonymous section must not carry .name")
	assert.Equal(t, "wan", sec["interface"])
	assert.Equal(t, "0.0.0.0", sec["target"])
}

func TestParseUCIExport_NamedSection(t *testing.T) {
	input := `config interface 'wan'
	option device 'eth0'
	option proto 'dhcp'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	require.Len(t, result["interface"], 1)
	sec := result["interface"][0]
	assert.Equal(t, "wan", sec[".name"])
	assert.Equal(t, "eth0", sec["device"])
	assert.Equal(t, "dhcp", sec["proto"])
}

func TestParseUCIExport_ListOption(t *testing.T) {
	input := `config route
	option interface 'wan'
	list dns '8.8.8.8'
	list dns '8.8.4.4'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	require.Len(t, result["route"], 1)
	sec := result["route"][0]
	dns, ok := sec["dns"].([]string)
	require.True(t, ok, "list option should be []string")
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, dns)
}

func TestParseUCIExport_MultipleSectionsOfSameType(t *testing.T) {
	input := `config interface 'loopback'
	option proto 'static'

config interface 'wan'
	option proto 'dhcp'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	require.Len(t, result["interface"], 2)
	assert.Equal(t, "loopback", result["interface"][0][".name"])
	assert.Equal(t, "wan", result["interface"][1][".name"])
}

func TestParseUCIExport_MultipleSectionTypes(t *testing.T) {
	input := `config interface 'loopback'
	option proto 'static'

config route
	option interface 'wan'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	assert.Len(t, result["interface"], 1)
	assert.Len(t, result["route"], 1)
}

func TestParseUCIExport_BlankLinesBetweenSections(t *testing.T) {
	input := `config interface 'lo'
	option proto 'static'



config interface 'wan'
	option proto 'dhcp'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)
	assert.Len(t, result["interface"], 2)
}

func TestParseUCIExport_FullNetworkPackage(t *testing.T) {
	input := `package network

config interface 'loopback'
	option ifname 'lo'
	option proto 'static'

config interface 'wan'
	option device 'eth0'
	option proto 'dhcp'

config route
	option interface 'wan'
	option target '0.0.0.0'
	list dns '8.8.8.8'
	list dns '8.8.4.4'
`
	result, err := ParseUCIExport(input)
	require.NoError(t, err)

	require.Len(t, result["interface"], 2)
	assert.Equal(t, "loopback", result["interface"][0][".name"])
	assert.Equal(t, "lo", result["interface"][0]["ifname"])
	assert.Equal(t, "static", result["interface"][0]["proto"])

	assert.Equal(t, "wan", result["interface"][1][".name"])
	assert.Equal(t, "eth0", result["interface"][1]["device"])

	require.Len(t, result["route"], 1)
	dns, ok := result["route"][0]["dns"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, dns)
}
