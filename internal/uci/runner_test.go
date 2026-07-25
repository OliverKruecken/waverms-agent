package uci

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockUCIRunner_Set(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.Set("network", "wan", "proto", "dhcp")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "set network.wan.proto=dhcp")
}

func TestMockUCIRunner_Commit(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.Commit("network")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "commit network")
}

func TestMockUCIRunner_Revert(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.Revert("network")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "revert network")
}

func TestMockUCIRunner_ErrorInjection(t *testing.T) {
	injected := errors.New("commit failed")
	m := &MockUCIRunner{
		Errors: map[string]error{
			"commit network": injected,
		},
	}
	err := m.Commit("network")
	assert.ErrorIs(t, err, injected)
}

func TestMockUCIRunner_Add(t *testing.T) {
	m := &MockUCIRunner{}
	ref, err := m.Add("network", "rule")
	assert.NoError(t, err)
	assert.NotEmpty(t, ref)
	assert.Contains(t, m.Calls, "add network rule")
}

func TestMockUCIRunner_AddList(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.AddList("network", "lan", "dns", "8.8.8.8")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "add_list network.lan.dns=8.8.8.8")
}

func TestMockUCIRunner_SetType(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.SetType("network", "wan", "interface")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "set-type network.wan=interface")
}

func TestMockUCIRunner_Delete(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.Delete("network", "wan")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "delete network.wan")
}

func TestMockUCIRunner_DeleteOption(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.DeleteOption("network", "wan", "proto")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "delete-option network.wan.proto")
}

func TestMockUCIRunner_ExecRaw(t *testing.T) {
	m := &MockUCIRunner{}
	_, err := m.ExecRaw("set", "system.@system[0].hostname=router-01")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "raw set system.@system[0].hostname=router-01")
}

func TestMockUCIRunner_ExecRaw_ErrorInjection(t *testing.T) {
	injected := errors.New("exec failed")
	m := &MockUCIRunner{
		Errors: map[string]error{
			"raw set system.@system[0].hostname=router-01": injected,
		},
	}
	_, err := m.ExecRaw("set", "system.@system[0].hostname=router-01")
	assert.ErrorIs(t, err, injected)
}

func TestMockUCIRunner_RecordsMultipleCalls(t *testing.T) {
	m := &MockUCIRunner{}
	_ = m.Set("network", "wan", "proto", "dhcp")
	_ = m.Set("network", "wan", "ipaddr", "192.168.1.1")
	_ = m.Commit("network")

	assert.Len(t, m.Calls, 3)
	assert.Equal(t, "set network.wan.proto=dhcp", m.Calls[0])
	assert.Equal(t, "set network.wan.ipaddr=192.168.1.1", m.Calls[1])
	assert.Equal(t, "commit network", m.Calls[2])
}

func TestMockUCIRunner_NoErrorsMap(t *testing.T) {
	m := &MockUCIRunner{} // Errors is nil
	err := m.Commit("network")
	assert.NoError(t, err)
}
