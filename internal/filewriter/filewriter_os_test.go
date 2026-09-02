package filewriter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OSFileAccess shells out to `ubus call file <method> <json>` via
// UCIRunner.ExecCmd, exactly like uci.RealUCIRunner's own ubus-backed methods
// (see internal/uci/runner_test.go, which likewise exercises those only
// through MockUCIRunner, not a live ubus binary). These tests drive it the
// same way: a MockUCIRunner canned with the JSON `ubus` itself would print.

func mkdirOKResult() string { return `{"code":0}` }

func TestOSFileAccess_WritesFile(t *testing.T) {
	mkdirCmd := `cmd ubus call file exec {"command":"mkdir","params":["-p","/etc/dropbear"]}`
	writeCmd := fmt.Sprintf(`cmd ubus call file write {"base64":true,"data":%q,"mode":384,"path":"/etc/dropbear/authorized_keys"}`,
		base64.StdEncoding.EncodeToString([]byte("hello")))
	uciMock := &uci.MockUCIRunner{
		Results: map[string]string{mkdirCmd: mkdirOKResult()},
	}
	w := &OSFileAccess{UCI: uciMock}

	err := w.WriteFile("/etc/dropbear/authorized_keys", []byte("hello"), 0600)
	require.NoError(t, err)

	assert.Contains(t, uciMock.Calls, mkdirCmd)
	assert.Contains(t, uciMock.Calls, writeCmd)
}

func TestOSFileAccess_WriteFile_MkdirFailurePropagates(t *testing.T) {
	mkdirCmd := `cmd ubus call file exec {"command":"mkdir","params":["-p","/etc/dropbear"]}`
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{mkdirCmd: assert.AnError},
	}
	w := &OSFileAccess{UCI: uciMock}

	err := w.WriteFile("/etc/dropbear/authorized_keys", []byte("hello"), 0600)
	require.Error(t, err)
}

func TestOSFileAccess_ReadFile_ReturnsContent(t *testing.T) {
	content := []byte("binary\x00data")
	readCmd := `cmd ubus call file read {"base64":true,"path":"/etc/dropbear/key"}`
	resp, err := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(content)})
	require.NoError(t, err)
	uciMock := &uci.MockUCIRunner{
		Results: map[string]string{readCmd: string(resp)},
	}
	w := &OSFileAccess{UCI: uciMock}

	got, err := w.ReadFile("/etc/dropbear/key")
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestOSFileAccess_ReadFile_MissingFileReturnsNotExist(t *testing.T) {
	// A missing file makes the real `ubus call file read` exit non-zero,
	// which UCIRunner.ExecCmd surfaces as an error — simulate that here
	// rather than relying on MockUCIRunner's zero-value ("", nil) default
	// for an unconfigured call, which wouldn't exercise this path at all.
	readCmd := `cmd ubus call file read {"base64":true,"path":"/nonexistent/path/key"}`
	uciMock := &uci.MockUCIRunner{Errors: map[string]error{readCmd: assert.AnError}}
	w := &OSFileAccess{UCI: uciMock}

	_, err := w.ReadFile("/nonexistent/path/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestOSFileAccess_Remove(t *testing.T) {
	removeCmd := `cmd ubus call file remove {"path":"/etc/dropbear/dropbear_rsa_host_key"}`
	uciMock := &uci.MockUCIRunner{}
	w := &OSFileAccess{UCI: uciMock}

	require.NoError(t, w.Remove("/etc/dropbear/dropbear_rsa_host_key"))
	assert.Contains(t, uciMock.Calls, removeCmd)
}

func TestOSFileAccess_Exists(t *testing.T) {
	statCmd := `cmd ubus call file stat {"path":"/etc/init.d/network"}`
	uciMock := &uci.MockUCIRunner{
		Results: map[string]string{statCmd: `{"type":"file"}`},
	}
	w := &OSFileAccess{UCI: uciMock}

	assert.True(t, w.Exists("/etc/init.d/network"))
}

func TestOSFileAccess_Exists_MissingReturnsFalse(t *testing.T) {
	statCmd := `cmd ubus call file stat {"path":"/etc/init.d/nonexistent"}`
	uciMock := &uci.MockUCIRunner{Errors: map[string]error{statCmd: assert.AnError}}
	w := &OSFileAccess{UCI: uciMock}
	assert.False(t, w.Exists("/etc/init.d/nonexistent"))
}

func TestOSFileAccess_ListDir(t *testing.T) {
	listCmd := `cmd ubus call file list {"path":"/etc/config"}`
	uciMock := &uci.MockUCIRunner{
		Results: map[string]string{listCmd: `{"entries":[
			{"name":"network","type":"file"},
			{"name":"symlinked","type":"symlink"},
			{"name":"subdir","type":"directory"}
		]}`},
	}
	w := &OSFileAccess{UCI: uciMock}

	entries, err := w.ListDir("/etc/config")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, DirEntry{Name: "network", IsRegular: true}, entries[0])
	assert.Equal(t, DirEntry{Name: "symlinked", IsSymlink: true}, entries[1])
	assert.Equal(t, DirEntry{Name: "subdir"}, entries[2])
}
