package uci

import (
	"errors"
	"testing"
	"time"

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

func TestMockUCIRunner_ExecShell(t *testing.T) {
	m := &MockUCIRunner{
		Results: map[string]string{
			"shell echo hi": "hi",
		},
	}
	out, exitCode, err := m.ExecShell("echo hi", time.Second)
	assert.NoError(t, err)
	assert.Equal(t, "hi", out)
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, m.Calls, "shell echo hi")
}

func TestMockUCIRunner_ExecShell_ExitCodeInjection(t *testing.T) {
	m := &MockUCIRunner{
		ExitCodes: map[string]int{
			"shell exit 7": 7,
		},
	}
	_, exitCode, err := m.ExecShell("exit 7", time.Second)
	assert.NoError(t, err)
	assert.Equal(t, 7, exitCode)
}

func TestMockUCIRunner_ExecShell_ErrorInjection(t *testing.T) {
	injected := errors.New("shell failed")
	m := &MockUCIRunner{
		Errors: map[string]error{
			"shell boom": injected,
		},
	}
	_, _, err := m.ExecShell("boom", time.Second)
	assert.ErrorIs(t, err, injected)
}

// RealUCIRunner.ExecShell only invokes /bin/sh (not the uci CLI), so — unlike every other
// RealUCIRunner method — it's safe to exercise directly in CI without a device/UCI binary present.
func TestRealUCIRunner_ExecShell_Success(t *testing.T) {
	r := &RealUCIRunner{}
	out, exitCode, err := r.ExecShell("echo -n hello", 5*time.Second)
	assert.NoError(t, err)
	assert.Equal(t, "hello", out)
	assert.Equal(t, 0, exitCode)
}

func TestRealUCIRunner_ExecShell_NonZeroExit(t *testing.T) {
	r := &RealUCIRunner{}
	out, exitCode, err := r.ExecShell("echo partial; exit 7", 5*time.Second)
	assert.NoError(t, err) // a non-zero exit is a legitimate result, not a Go-level error
	assert.Equal(t, "partial", out)
	assert.Equal(t, 7, exitCode)
}

func TestRealUCIRunner_ExecShell_Timeout(t *testing.T) {
	r := &RealUCIRunner{}
	_, exitCode, err := r.ExecShell("sleep 5", 50*time.Millisecond)
	assert.Error(t, err)
	assert.Equal(t, -1, exitCode)
}

func TestMockUCIRunner_NoErrorsMap(t *testing.T) {
	m := &MockUCIRunner{} // Errors is nil
	err := m.Commit("network")
	assert.NoError(t, err)
}
