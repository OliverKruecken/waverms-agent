package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// FileTransferFile is one bundled file inside a "file_transfer" command payload — a signed,
// per-device download URL paired with the destination path and permission bits on the device.
type FileTransferFile struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Path      string `json:"path"`
	Mode      string `json:"mode,omitempty"` // octal string e.g. "0755"; defaults to fileTransferDefaultMode
}

// FileTransferPayload is the inner payload for type "file_transfer" — added specifically for
// backend-side "file transfer templates" (a concept this agent has no other knowledge of, same
// posture as shell_exec for shell command templates). Unlike file_write, there is NO allowlist on
// Path here — an arbitrary target path is the entire point of this command type. The backend is
// responsible for gating who can create/run a template (ADMIN only) before it ever reaches the
// agent.
type FileTransferPayload struct {
	Files []FileTransferFile `json:"files"`
}

// FileTransferFileResult is one file's outcome, reported independently in the file_transfer ack —
// one file failing does not stop the rest of the batch from being attempted.
type FileTransferFileResult struct {
	Path   string `json:"path"`
	Status string `json:"status"` // "ok" | "error"
	Error  string `json:"error,omitempty"`
}

const (
	fileTransferDefaultMode     = "0644"
	fileTransferSizeHeadroom    = int64(1024 * 1024) // 1 MiB safety margin beyond declared size_bytes
	fileTransferDownloadTimeout = 5 * time.Minute    // per file
)

// FileTransferDownloader downloads one file from a URL, verifies its SHA-256 checksum, and
// atomically writes it to destPath with the given permission bits. Kept as its own interface
// (rather than generalizing FirmwareDownloader) because the two diverge in destination/semantics:
// FirmwareDownloader always writes to one fixed sysupgrade tmp path with no mode concept, this one
// writes to an arbitrary caller-supplied path and mode and never triggers a process replacement
// afterward. This agent's convention is one small interface per handler, not a shared "downloader"
// abstraction — see docs/agent-go.md.
type FileTransferDownloader interface {
	Download(ctx context.Context, url, destPath, sha256hex string, maxBytes int64, mode os.FileMode) error
}

// HTTPFileTransferDownloader is the production FileTransferDownloader using stdlib net/http.
type HTTPFileTransferDownloader struct{}

func (d *HTTPFileTransferDownloader) Download(ctx context.Context, url, destPath, sha256hex string, maxBytes int64, mode os.FileMode) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	client := &http.Client{Timeout: 0} // timeout managed by ctx
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	if info, err := os.Stat(destPath); err == nil && info.IsDir() {
		return fmt.Errorf("target path %s is an existing directory, not a file", destPath)
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp := destPath + ".waverms-tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}

	h := sha256.New()
	r := io.TeeReader(io.LimitReader(resp.Body, maxBytes+1), h)
	written, err := io.Copy(f, r)
	closeErr := f.Close()
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if closeErr != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, closeErr)
	}
	if written > maxBytes {
		os.Remove(tmp)
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes)", maxBytes)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != sha256hex {
		os.Remove(tmp)
		return fmt.Errorf("sha256 mismatch: expected %s got %s", sha256hex, got)
	}

	// OpenFile's mode is masked by umask, so an explicit chmod after write
	// guarantees the requested bits actually land on the temp file before rename.
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, destPath, err)
	}
	return nil
}

// parseFileMode parses an octal mode string like "0755", defaulting to fileTransferDefaultMode
// when empty. An invalid string also falls back to the default (with a warning log) rather than
// failing the whole file — this is a convenience default, not a security boundary. Unlike
// file_write's path allowlist, file_transfer has no path restriction at all: see the trust-boundary
// note in FileTransferPayload's doc comment and docs/file-transfer-templates.md.
func parseFileMode(s string) os.FileMode {
	if s == "" {
		s = fileTransferDefaultMode
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		slog.Warn("file_transfer: invalid mode, using default", "mode", s, "default", fileTransferDefaultMode)
		v, _ = strconv.ParseUint(fileTransferDefaultMode, 8, 32)
	}
	return os.FileMode(v)
}

// handleFileTransfer downloads and writes every bundled file to its target path, independently —
// one file failing does not stop the rest of the batch (matches the backend's per-device skip
// philosophy, applied here per-file). The command-level ack status is "ok" only if every file
// succeeded; the per-file detail always carries the full breakdown regardless.
func (a *Agent) handleFileTransfer(cmd Command) {
	var p FileTransferPayload
	if !a.decodeOrAck(cmd, &p) {
		return
	}
	if len(p.Files) == 0 {
		slog.Error("file_transfer rejected: no files in payload", "cmd_id", cmd.CmdID)
		a.publishAckFileTransfer(cmd.CmdID, "error", nil)
		return
	}

	results := make([]FileTransferFileResult, 0, len(p.Files))
	overallOK := true
	for _, file := range p.Files {
		if file.Path == "" || file.URL == "" || file.SHA256 == "" {
			results = append(results, FileTransferFileResult{Path: file.Path, Status: "error", Error: "missing path, url, or sha256"})
			overallOK = false
			continue
		}

		mode := parseFileMode(file.Mode)
		maxBytes := file.SizeBytes + fileTransferSizeHeadroom
		ctx, cancel := context.WithTimeout(context.Background(), fileTransferDownloadTimeout)
		err := a.fileTransferDownloader.Download(ctx, file.URL, file.Path, file.SHA256, maxBytes, mode)
		cancel()
		if err != nil {
			slog.Error("file_transfer: file failed", "cmd_id", cmd.CmdID, "path", file.Path, "err", err)
			results = append(results, FileTransferFileResult{Path: file.Path, Status: "error", Error: err.Error()})
			overallOK = false
			continue
		}
		slog.Info("file_transfer: file written", "cmd_id", cmd.CmdID, "path", file.Path)
		results = append(results, FileTransferFileResult{Path: file.Path, Status: "ok"})
	}

	status := "ok"
	if !overallOK {
		status = "error"
	}
	a.publishAckFileTransfer(cmd.CmdID, status, results)
	slog.Info("file_transfer: complete", "cmd_id", cmd.CmdID, "status", status, "files", len(results))
}

// publishAckFileTransfer publishes an ACK carrying the per-file result breakdown — the generic
// AckPayload has no concept of multiple files, so this mirrors shell_exec.go's/ubus.go's pattern of
// a dedicated ack shape for a command type that needs one.
func (a *Agent) publishAckFileTransfer(cmdID, status string, files []FileTransferFileResult) {
	slog.Debug("publishing file_transfer ack", "cmd_id", cmdID, "status", status)
	type fileTransferAckPayload struct {
		CmdID     string                   `json:"cmd_id"`
		Status    string                   `json:"status"`
		Files     []FileTransferFileResult `json:"files"`
		Timestamp string                   `json:"timestamp"`
	}
	publishTypedAck(a, cmdID, fileTransferAckPayload{
		CmdID:     cmdID,
		Status:    status,
		Files:     files,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// MockFileTransferDownloader records Download calls; per-call error controllable by URL so a
// batch test can make one file fail independently of the others.
type MockFileTransferDownloader struct {
	Calls    []string
	ErrByURL map[string]error
}

func (m *MockFileTransferDownloader) Download(_ context.Context, url, destPath, sha256hex string, _ int64, mode os.FileMode) error {
	m.Calls = append(m.Calls, fmt.Sprintf("download url=%s dest=%s sha256=%s mode=%o", url, destPath, sha256hex, mode))
	if err, ok := m.ErrByURL[url]; ok && err != nil {
		return err
	}
	return os.WriteFile(destPath, []byte("mock-file"), mode)
}
