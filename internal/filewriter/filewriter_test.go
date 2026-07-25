package filewriter

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockFileAccess_RecordsCall(t *testing.T) {
	m := &MockFileAccess{}

	err := m.WriteFile("/etc/dropbear/authorized_keys", []byte("ssh-ed25519 AAAA..."), 0600)
	require.NoError(t, err)

	require.Len(t, m.Calls, 1)
	assert.Equal(t, "/etc/dropbear/authorized_keys", m.Calls[0].Path)
	assert.Equal(t, []byte("ssh-ed25519 AAAA..."), m.Calls[0].Content)
	assert.Equal(t, os.FileMode(0600), m.Calls[0].Perm)
}

func TestMockFileAccess_RecordsMultipleCalls(t *testing.T) {
	m := &MockFileAccess{}

	require.NoError(t, m.WriteFile("/path/a", []byte("a"), 0600))
	require.NoError(t, m.WriteFile("/path/b", []byte("b"), 0644))

	require.Len(t, m.Calls, 2)
	assert.Equal(t, "/path/a", m.Calls[0].Path)
	assert.Equal(t, "/path/b", m.Calls[1].Path)
}

func TestMockFileAccess_InjectsErrorByPath(t *testing.T) {
	injected := errors.New("permission denied")
	m := &MockFileAccess{
		Errors: map[string]error{
			"/etc/protected": injected,
		},
	}

	err := m.WriteFile("/etc/protected", []byte("data"), 0600)
	assert.ErrorIs(t, err, injected)

	// Call is still recorded even when an error is injected.
	require.Len(t, m.Calls, 1)
	assert.Equal(t, "/etc/protected", m.Calls[0].Path)
}

func TestMockFileAccess_NonErroringPathSucceeds(t *testing.T) {
	m := &MockFileAccess{
		Errors: map[string]error{
			"/etc/protected": errors.New("no access"),
		},
	}

	err := m.WriteFile("/etc/allowed", []byte("ok"), 0644)
	require.NoError(t, err)

	require.Len(t, m.Calls, 1)
	assert.Equal(t, "/etc/allowed", m.Calls[0].Path)
}

func TestMockFileAccess_NilErrors_AlwaysSucceeds(t *testing.T) {
	m := &MockFileAccess{}

	require.NoError(t, m.WriteFile("/any/path", []byte("content"), 0755))
	require.Len(t, m.Calls, 1)
}

func TestMockFileAccess_ReadFile_ReturnsInjectedContent(t *testing.T) {
	m := &MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/dropbear/dropbear_ed25519_host_key": []byte("key-bytes"),
		},
	}

	got, err := m.ReadFile("/etc/dropbear/dropbear_ed25519_host_key")
	require.NoError(t, err)
	assert.Equal(t, []byte("key-bytes"), got)
}

func TestMockFileAccess_ReadFile_MissingPathReturnsNotExist(t *testing.T) {
	m := &MockFileAccess{}

	_, err := m.ReadFile("/etc/dropbear/dropbear_rsa_host_key")
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestMockFileAccess_ReadFile_InjectsError(t *testing.T) {
	injected := errors.New("permission denied")
	m := &MockFileAccess{
		ReadErrors: map[string]error{
			"/etc/dropbear/dropbear_ed25519_host_key": injected,
		},
	}

	_, err := m.ReadFile("/etc/dropbear/dropbear_ed25519_host_key")
	assert.ErrorIs(t, err, injected)
}
