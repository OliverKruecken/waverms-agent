package uci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeUbusUCIGet_NamedAndAnonymousSections(t *testing.T) {
	out := `{
  "values": {
    "lan": {".anonymous": false, ".type": "interface", ".name": "lan", ".index": 1, "proto": "static", "ipaddr": "192.168.1.1"},
    "cfg01ecad": {".anonymous": true, ".type": "device", ".name": "cfg01ecad", ".index": 0, "name": "br-lan"}
  }
}`
	sections, err := decodeUbusUCIGet(out)
	require.NoError(t, err)
	require.Len(t, sections, 2)

	// Ordered by ".index": the anonymous device section (index 0) comes first.
	assert.Equal(t, "cfg01ecad", sections[0].ID)
	assert.True(t, sections[0].Anonymous)
	assert.Equal(t, "device", sections[0].Type)
	assert.Equal(t, "br-lan", sections[0].Options["name"])

	assert.Equal(t, "lan", sections[1].ID)
	assert.False(t, sections[1].Anonymous)
	assert.Equal(t, "interface", sections[1].Type)
	assert.Equal(t, "lan", sections[1].Name)
	assert.Equal(t, "static", sections[1].Options["proto"])
	assert.Equal(t, "192.168.1.1", sections[1].Options["ipaddr"])
}

func TestDecodeUbusUCIGet_ListOption(t *testing.T) {
	out := `{
  "values": {
    "lan": {".anonymous": false, ".type": "interface", ".name": "lan", ".index": 0, "dns": ["8.8.8.8", "8.8.4.4"]}
  }
}`
	sections, err := decodeUbusUCIGet(out)
	require.NoError(t, err)
	require.Len(t, sections, 1)
	dns, ok := sections[0].Options["dns"].([]string)
	require.True(t, ok, "list option should decode to []string")
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, dns)
}

func TestDecodeUbusUCIGet_EmptyPackage(t *testing.T) {
	sections, err := decodeUbusUCIGet(`{"values": {}}`)
	require.NoError(t, err)
	assert.Empty(t, sections)
}

func TestDecodeUbusUCIGet_MalformedJSON(t *testing.T) {
	_, err := decodeUbusUCIGet(`not json`)
	assert.Error(t, err)
}

func TestGroupByType_NamedSectionCarriesName(t *testing.T) {
	sections := []Section{
		{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"proto": "static"}},
	}
	grouped := GroupByType(sections)
	require.Len(t, grouped["interface"], 1)
	assert.Equal(t, "lan", grouped["interface"][0][".name"])
	assert.Equal(t, "static", grouped["interface"][0]["proto"])
}

func TestGroupByType_AnonymousSectionHasNoName(t *testing.T) {
	sections := []Section{
		{ID: "cfg01ecad", Type: "device", Anonymous: true, Options: map[string]interface{}{"name": "br-lan"}},
	}
	grouped := GroupByType(sections)
	require.Len(t, grouped["device"], 1)
	_, hasName := grouped["device"][0][".name"]
	assert.False(t, hasName, "anonymous section must not carry .name")
}

func TestGroupByType_MultipleSectionsSameType(t *testing.T) {
	sections := []Section{
		{ID: "loopback", Type: "interface", Name: "loopback", Options: map[string]interface{}{"proto": "static"}},
		{ID: "wan", Type: "interface", Name: "wan", Options: map[string]interface{}{"proto": "dhcp"}},
	}
	grouped := GroupByType(sections)
	require.Len(t, grouped["interface"], 2)
	assert.Equal(t, "loopback", grouped["interface"][0][".name"])
	assert.Equal(t, "wan", grouped["interface"][1][".name"])
}

func TestGroupByType_Empty(t *testing.T) {
	grouped := GroupByType(nil)
	assert.Empty(t, grouped)
}
