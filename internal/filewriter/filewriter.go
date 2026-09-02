// Package filewriter provides the FileAccess interface and implementations for
// reading and writing files on the device filesystem.
package filewriter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// DirEntry is one entry returned by FileAccess.ListDir — a minimal subset of
// rpcd's `file list` response (name + type), just enough for the two callers
// (discoverPackages/discoverServices in internal/agent/agent.go) that need to
// tell a regular file from a symlink from anything else.
type DirEntry struct {
	Name      string
	IsRegular bool
	IsSymlink bool
}

// FileAccess abstracts filesystem reads and writes so that command handlers
// can be tested without touching the real filesystem.
type FileAccess interface {
	WriteFile(path string, content []byte, perm os.FileMode) error
	ReadFile(path string) ([]byte, error)
	// Remove deletes path. Removing a file that doesn't exist is not an
	// error (matches rpcd's file.remove, which already treats a missing
	// path as success).
	Remove(path string) error
	// Exists reports whether path exists.
	Exists(path string) bool
	// ListDir lists the entries directly under path.
	ListDir(path string) ([]DirEntry, error)
}

// OSFileAccess is the production FileAccess, backed by rpcd's `file` ubus
// object (`ubus call file read/write/remove/stat/list`) rather than direct
// os.* calls — the same ubus-instead-of-CLI-or-syscalls migration
// internal/uci.RealUCIRunner already made for UCI access. UCI is required:
// every method shells out via UCI.ExecCmd("ubus", "call", "file", ...),
// reusing the identical mockable ubus-call seam every other ubus interaction
// in this agent already goes through, rather than a second hand-rolled
// exec-ubus helper.
type OSFileAccess struct {
	UCI uci.UCIRunner
}

// callFile runs `ubus call file <method> <json-encoded params>` and returns its raw stdout.
func (w *OSFileAccess) callFile(method string, params interface{}) (string, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("marshal file %s params: %w", method, err)
	}
	return w.UCI.ExecCmd("ubus", "call", "file", method, string(body))
}

// ReadFile returns the contents of path via `ubus call file read`.
//
// rpcd distinguishes UBUS_STATUS_NOT_FOUND from other failures, but
// UCIRunner.ExecCmd's generic error wrapping (via exec.Cmd.Output()'s
// *exec.ExitError) doesn't preserve that distinction, and the `ubus` CLI's
// exact exit-code/stderr text per status isn't a contract worth depending on
// without a live device to verify it against. Every path this agent reads is
// root-owned and the agent always runs as root, so in practice a read
// failure here is absence, not a permission error — any failure is reported
// as fs.ErrNotExist so callers' existing os.IsNotExist(err) checks (see
// handleHostKeyFetch) keep working unchanged.
func (w *OSFileAccess) ReadFile(path string) ([]byte, error) {
	out, err := w.callFile("read", map[string]interface{}{"path": path, "base64": true})
	if err != nil {
		return nil, fmt.Errorf("ubus file read %s: %w", path, fs.ErrNotExist)
	}
	var resp struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("decode ubus file read %s: %w", path, err)
	}
	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("decode base64 file data for %s: %w", path, err)
	}
	return data, nil
}

// WriteFile creates all parent directories and writes content to path with
// the given permission bits, via `ubus call file exec` (rpcd's file object
// has no mkdir method — `mkdir -p` through its `exec` method is the closest
// ubus-native equivalent) followed by `ubus call file write`. This ensures
// that paths like /etc/dropbear/authorized_keys succeed even when the parent
// directory does not yet exist on the device, matching the previous
// os.MkdirAll-based behavior.
func (w *OSFileAccess) WriteFile(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	mkdirOut, err := w.callFile("exec", map[string]interface{}{
		"command": "mkdir",
		"params":  []string{"-p", dir},
	})
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	var mkdirResp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal([]byte(mkdirOut), &mkdirResp); err == nil && mkdirResp.Code != 0 {
		return fmt.Errorf("mkdir %s: exit code %d", dir, mkdirResp.Code)
	}

	_, err = w.callFile("write", map[string]interface{}{
		"path":   path,
		"data":   base64.StdEncoding.EncodeToString(content),
		"base64": true,
		"mode":   int(perm.Perm()),
	})
	if err != nil {
		return fmt.Errorf("ubus file write %s: %w", path, err)
	}
	return nil
}

// Remove deletes path via `ubus call file remove`. rpcd's remove already
// treats a missing path as success, so — unlike the previous os.Remove-based
// callers (handleHostKeyRemove/handleTlsCertRemove) — no os.IsNotExist
// special-casing is needed at the call site.
func (w *OSFileAccess) Remove(path string) error {
	if _, err := w.callFile("remove", map[string]interface{}{"path": path}); err != nil {
		return fmt.Errorf("ubus file remove %s: %w", path, err)
	}
	return nil
}

// Exists reports whether path exists, via `ubus call file stat`.
func (w *OSFileAccess) Exists(path string) bool {
	_, err := w.callFile("stat", map[string]interface{}{"path": path})
	return err == nil
}

// ListDir lists the entries directly under path via `ubus call file list`.
func (w *OSFileAccess) ListDir(path string) ([]DirEntry, error) {
	out, err := w.callFile("list", map[string]interface{}{"path": path})
	if err != nil {
		return nil, fmt.Errorf("ubus file list %s: %w", path, err)
	}
	var resp struct {
		Entries []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("decode ubus file list %s: %w", path, err)
	}
	entries := make([]DirEntry, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		entries = append(entries, DirEntry{
			Name:      e.Name,
			IsRegular: e.Type == "file",
			IsSymlink: e.Type == "symlink",
		})
	}
	return entries, nil
}
