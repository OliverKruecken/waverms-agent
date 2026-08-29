package uci

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockUCIRunner_GetSections(t *testing.T) {
	m := &MockUCIRunner{
		Sections: map[string][]Section{
			"network": {{ID: "lan", Type: "interface", Name: "lan", Options: map[string]interface{}{"proto": "static"}}},
		},
	}
	sections, err := m.GetSections("network")
	require.NoError(t, err)
	require.Len(t, sections, 1)
	assert.Equal(t, "lan", sections[0].ID)
	assert.Contains(t, m.Calls, "sections network")
}

func TestMockUCIRunner_GetSections_UnknownPackageReturnsEmpty(t *testing.T) {
	m := &MockUCIRunner{}
	sections, err := m.GetSections("network")
	require.NoError(t, err)
	assert.Empty(t, sections)
}

func TestMockUCIRunner_GetSections_ErrorInjection(t *testing.T) {
	injected := errors.New("not found")
	m := &MockUCIRunner{
		Errors: map[string]error{"sections network": injected},
	}
	_, err := m.GetSections("network")
	assert.ErrorIs(t, err, injected)
}

func TestMockUCIRunner_Add_Named(t *testing.T) {
	m := &MockUCIRunner{}
	id, err := m.Add("network", "interface", "lan")
	require.NoError(t, err)
	assert.Equal(t, "lan", id)
	assert.Contains(t, m.Calls, "add network interface lan")
	require.Len(t, m.AddCalls, 1)
	assert.Equal(t, AddCall{Pkg: "network", SectionType: "interface", Name: "lan"}, m.AddCalls[0])
}

func TestMockUCIRunner_Add_Anonymous(t *testing.T) {
	m := &MockUCIRunner{}
	id, err := m.Add("network", "rule", "")
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Contains(t, m.Calls, "add network rule")
}

func TestMockUCIRunner_SetValues(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.SetValues("network", "wan", map[string]interface{}{"proto": "dhcp"})
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "setvalues network.wan")
	require.Len(t, m.SetValuesCalls, 1)
	assert.Equal(t, "dhcp", m.SetValuesCalls[0].Values["proto"])
}

func TestMockUCIRunner_DeleteOptions(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.DeleteOptions("network", "wan", []string{"proto", "ipaddr"})
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "deleteoptions network.wan [proto ipaddr]")
}

func TestMockUCIRunner_Delete(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.Delete("network", "wan")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "delete network.wan")
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

func TestMockUCIRunner_RetypeExisting(t *testing.T) {
	m := &MockUCIRunner{}
	err := m.RetypeExisting("network", "wan", "interface")
	assert.NoError(t, err)
	assert.Contains(t, m.Calls, "set-type network.wan=interface")
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
	_ = m.SetValues("network", "wan", map[string]interface{}{"proto": "dhcp"})
	_ = m.Commit("network")

	assert.Len(t, m.Calls, 2)
	assert.Equal(t, "setvalues network.wan", m.Calls[0])
	assert.Equal(t, "commit network", m.Calls[1])
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
