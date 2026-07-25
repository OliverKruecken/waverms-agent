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
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// FirmwareDownloader downloads a firmware image from a URL, verifies its SHA-256
// checksum, and writes it to destPath.
type FirmwareDownloader interface {
	Download(ctx context.Context, url, destPath, sha256hex string, maxBytes int64) error
}

// SysupgradeRunner tests and executes sysupgrade on a firmware image.
type SysupgradeRunner interface {
	// Test runs sysupgrade --test to validate the image without flashing.
	Test(imagePath string) (string, error)
	// Exec replaces the running process with sysupgrade. keepConfig=false adds -n (factory reset).
	Exec(imagePath string, keepConfig bool) error
}

// DiskSpaceChecker reports available disk space for a directory.
type DiskSpaceChecker interface {
	FreeBytes(dir string) (uint64, error)
}

// HTTPFirmwareDownloader is the production FirmwareDownloader using stdlib net/http.
type HTTPFirmwareDownloader struct{}

func (d *HTTPFirmwareDownloader) Download(ctx context.Context, url, destPath, sha256hex string, maxBytes int64) error {
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

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer f.Close()

	h := sha256.New()
	r := io.TeeReader(io.LimitReader(resp.Body, maxBytes+1), h)
	written, err := io.Copy(f, r)
	if err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	if written > maxBytes {
		return fmt.Errorf("firmware exceeds maximum allowed size (%d bytes)", maxBytes)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != sha256hex {
		return fmt.Errorf("sha256 mismatch: expected %s got %s", sha256hex, got)
	}
	return nil
}

// OSSysupgradeRunner calls the real sysupgrade binary.
type OSSysupgradeRunner struct{}

func (r *OSSysupgradeRunner) Test(imagePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/sysupgrade", "--test", imagePath).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (r *OSSysupgradeRunner) Exec(imagePath string, keepConfig bool) error {
	args := []string{"/sbin/sysupgrade"}
	if !keepConfig {
		args = append(args, "-n")
	}
	args = append(args, imagePath)
	return syscall.Exec("/sbin/sysupgrade", args, os.Environ())
}

// StatfsDiskSpaceChecker uses syscall.Statfs to measure free bytes.
type StatfsDiskSpaceChecker struct{}

func (c *StatfsDiskSpaceChecker) FreeBytes(dir string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

// MockFirmwareDownloader records Download calls and returns a configurable error.
type MockFirmwareDownloader struct {
	Calls []string
	Err   error
}

func (m *MockFirmwareDownloader) Download(_ context.Context, url, destPath, sha256hex string, _ int64) error {
	m.Calls = append(m.Calls, fmt.Sprintf("download url=%s dest=%s sha256=%s", url, destPath, sha256hex))
	if m.Err == nil {
		// Write a placeholder file so callers can stat it.
		_ = os.WriteFile(destPath, []byte("mock-firmware"), 0o600)
	}
	return m.Err
}

// MockSysupgradeRunner records calls and returns configurable errors.
type MockSysupgradeRunner struct {
	TestCalls []string
	ExecCalls []string
	TestErr   error
	ExecErr   error
}

func (m *MockSysupgradeRunner) Test(imagePath string) (string, error) {
	m.TestCalls = append(m.TestCalls, imagePath)
	return "", m.TestErr
}

func (m *MockSysupgradeRunner) Exec(imagePath string, keepConfig bool) error {
	m.ExecCalls = append(m.ExecCalls, fmt.Sprintf("path=%s keepConfig=%v", imagePath, keepConfig))
	return m.ExecErr
}

// MockDiskSpaceChecker always reports the configured free space.
type MockDiskSpaceChecker struct {
	Free uint64
	Err  error
}

func (m *MockDiskSpaceChecker) FreeBytes(_ string) (uint64, error) {
	return m.Free, m.Err
}

const (
	sysupgradeTmpPath         = "/tmp/waverms-sysupgrade.bin"
	sysupgradeMinHeadroom     = int64(4 * 1024 * 1024) // 4 MiB safety margin beyond image size
	sysupgradeDownloadTimeout = 10 * time.Minute
)

// handleSysupgrade downloads, verifies, tests, and flashes a firmware image.
func (a *Agent) handleSysupgrade(cmd Command) {
	var p struct {
		URL        string `json:"url"`
		SHA256     string `json:"sha256"`
		SizeBytes  int64  `json:"size_bytes"`
		Version    string `json:"version"`
		KeepConfig bool   `json:"keep_config"`
	}
	if !a.decodeOrAck(cmd, &p) {
		return
	}
	if p.URL == "" || p.SHA256 == "" {
		a.publishAck(cmd.CmdID, "error", "payload missing url or sha256")
		return
	}

	// Free space check: need image + 4 MiB headroom (tmpfs is RAM-backed).
	required := uint64(p.SizeBytes + sysupgradeMinHeadroom)
	free, err := a.diskSpaceChecker.FreeBytes("/tmp")
	if err == nil && free < required {
		a.publishAck(cmd.CmdID, "error",
			fmt.Sprintf("insufficient space in /tmp: need %d bytes, have %d", required, free))
		return
	}

	// Download and verify checksum.
	ctx, cancel := context.WithTimeout(context.Background(), sysupgradeDownloadTimeout)
	defer cancel()
	maxBytes := p.SizeBytes + sysupgradeMinHeadroom
	if err := a.firmwareDownloader.Download(ctx, p.URL, sysupgradeTmpPath, p.SHA256, maxBytes); err != nil {
		os.Remove(sysupgradeTmpPath)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("download failed: %v", err))
		return
	}

	// Validate image without flashing.
	if out, err := a.sysupgradeRunner.Test(sysupgradeTmpPath); err != nil {
		os.Remove(sysupgradeTmpPath)
		msg := fmt.Sprintf("image validation failed: %v", err)
		if out != "" {
			msg += ": " + out
		}
		a.publishAck(cmd.CmdID, "error", msg)
		return
	}

	// Write sentinel before replacing the process. syscall.Exec never returns,
	// so PUBACK for this QoS-1 command is never sent. The broker re-delivers it
	// on the next connect; the sentinel makes the agent request CleanStart=true
	// for that connect, discarding the queued message.
	// Only needed for keep_config=true — factory reset wipes /etc/config/ and
	// also wipes the credentials, so the agent can't reconnect anyway.
	if p.KeepConfig {
		if err := os.WriteFile(a.cleanStartSentinelPath, []byte("1"), 0600); err != nil {
			slog.Warn("sysupgrade: could not write clean-start sentinel", "path", a.cleanStartSentinelPath, "err", err)
		}
	}

	// Send "started" ack at QoS 1 then replace the process with sysupgrade.
	// After syscall.Exec the process is gone — the ack must be in-flight first.
	a.publishAck(cmd.CmdID, "started", "image verified, starting sysupgrade")
	time.Sleep(time.Second)

	// Replace the process. If Exec returns, sysupgrade itself failed before flashing.
	if err := a.sysupgradeRunner.Exec(sysupgradeTmpPath, p.KeepConfig); err != nil {
		// Exec failed (sysupgrade didn't run) — remove sentinel, nothing was flashed.
		os.Remove(a.cleanStartSentinelPath)
		os.Remove(sysupgradeTmpPath)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("sysupgrade exec failed: %v", err))
	}
}
