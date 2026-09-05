package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/apply"
)

// decodeOrAck unmarshals cmd.Payload into out. On failure it logs the
// failure, publishes an "invalid payload" error ack for cmd, and returns
// false; callers should return immediately when false comes back.
func (a *Agent) decodeOrAck(cmd Command, out any) bool {
	if err := json.Unmarshal(cmd.Payload, out); err != nil {
		slog.Error("invalid command payload", "cmd_id", cmd.CmdID, "type", cmd.Type, "err", err)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("invalid payload: %v", err))
		return false
	}
	return true
}

// ackOkAndReport sends a success ack for cmd and re-publishes state so the
// backend sees the change without waiting for the next heartbeat.
func (a *Agent) ackOkAndReport(cmdID, trigger string) {
	a.publishAck(cmdID, "ok", "")
	a.publishStateAfterSuccess(trigger)
}

func (a *Agent) handleUCISet(cmd Command) {
	var uciPayload UCICommandPayload
	if !a.decodeOrAck(cmd, &uciPayload) {
		return
	}

	var output strings.Builder
	status := "ok"
	for _, rawCmd := range uciPayload.Commands {
		// Strip leading "uci " prefix if present.
		args := strings.Fields(strings.TrimPrefix(rawCmd, "uci "))
		if len(args) == 0 {
			continue
		}
		// Allowlist the subcommand to prevent injection of destructive
		// UCI operations (e.g. "batch", "import") if the broker is
		// compromised or a message is replayed.
		if !allowedUCISubcmds[args[0]] {
			slog.Error("uci_set rejected: subcommand not in allowlist", "cmd_id", cmd.CmdID, "subcommand", args[0])
			output.WriteString(fmt.Sprintf("error: uci subcommand not permitted: %s\n", args[0]))
			status = "error"
			continue
		}
		slog.Debug("uci exec", "args", args)
		out, err := runUCISetCommand(a.uci, args[0], args[1:])
		if out != "" {
			output.WriteString(out)
			output.WriteString("\n")
		}
		if err != nil {
			output.WriteString(fmt.Sprintf("error: %v\n", err))
			status = "error"
		}
	}
	a.publishAck(cmd.CmdID, status, strings.TrimSpace(output.String()))
}

func (a *Agent) handleConfigApply(cmd Command) {
	if a.isDuplicateConfigApply(cmd.CmdID) {
		// Broker redelivery of an already in-flight apply — the original
		// watchdog is still running and will send the one ack for this
		// cmd_id when it resolves. Reprocessing here would apply the same
		// config twice and race a second watchdog against the first.
		slog.Warn("config_apply: duplicate delivery while watchdog still in flight, ignoring", "cmd_id", cmd.CmdID)
		return
	}

	// Extract package names so we can backup before applying.
	var raw map[string]json.RawMessage
	if !a.decodeOrAck(cmd, &raw) {
		return
	}
	var pkgNames []string
	for k := range raw {
		if k != "packages" && k != "reboot" {
			pkgNames = append(pkgNames, k)
		}
	}

	backup, err := backupConfigFiles(pkgNames)
	if err != nil {
		slog.Error("config_apply: backup failed", "cmd_id", cmd.CmdID, "err", err)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("backup failed: %v", err))
		return
	}

	applier := apply.New(a.uci)
	committed, err := applier.Apply(cmd.Payload)
	if err != nil {
		slog.Error("config_apply failed", "cmd_id", cmd.CmdID, "err", err)
		a.publishAck(cmd.CmdID, "error", err.Error())
		return
	}
	slog.Info("config_apply succeeded, starting connectivity watchdog", "cmd_id", cmd.CmdID, "packages", committed, "watchdog", connectivityWatchdogTimeout)

	if reloadErrs := apply.RunReloads(committed); len(reloadErrs) > 0 {
		slog.Warn("config_apply: service reload failures", "errors", strings.Join(reloadErrs, "; "))
	}

	// Register the confirm channel before publishing state so the server-sent
	// config_confirm cannot arrive before the watchdog is ready to receive it.
	confirmCh := make(chan struct{})
	a.setWatchdogConfirm(cmd.CmdID, confirmCh)

	// Signal the reconnect loop to bypass exponential backoff for the duration
	// of the watchdog so a brief network-interface restart doesn't prevent the
	// device from reconnecting within the 2-minute window.
	a.watchdogActive.Store(true)

	// ACK is deferred: the watchdog goroutine either confirms connectivity and
	// sends ACK "ok", or rolls back the config and queues an ACK "error".
	go a.runConnectivityWatchdog(cmd.CmdID, backup, committed, a.getSessionDisconnCh(), confirmCh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.publishState(ctx, "apply_success", committed); err != nil {
		slog.Error("publish state after config_apply", "err", err)
	}
}

func (a *Agent) handleFileWrite(cmd Command) {
	var fwPayload FileWriteCommandPayload
	if !a.decodeOrAck(cmd, &fwPayload) {
		return
	}
	if fwPayload.Path == "" {
		a.publishAck(cmd.CmdID, "error", "path is required")
		return
	}
	// Reject paths outside the allowlist to prevent arbitrary file writes.
	// filepath.Clean collapses traversal sequences before the prefix check.
	if !isFileWritePathAllowed(fwPayload.Path) {
		slog.Error("file_write rejected: path not in allowlist", "cmd_id", cmd.CmdID, "path", fwPayload.Path)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("path not permitted: %s", fwPayload.Path))
		return
	}
	// Parse mode octal string ("0600" → os.FileMode). Default to 0600 if missing or invalid.
	perm := os.FileMode(0600)
	if fwPayload.Mode != "" {
		var modeInt uint32
		if _, err := fmt.Sscanf(fwPayload.Mode, "%o", &modeInt); err == nil {
			perm = os.FileMode(modeInt)
		}
	}
	// Decode content according to format.
	// "dropbear": content is standard base64 (RFC 4648) for raw binary files.
	// "openssh" or absent: content is a plain UTF-8 string (backward-compatible default).
	var fileContent []byte
	switch fwPayload.Format {
	case "dropbear":
		decoded, err := base64.StdEncoding.DecodeString(fwPayload.Content)
		if err != nil {
			slog.Error("file_write: base64 decode failed", "cmd_id", cmd.CmdID, "err", err)
			a.publishAck(cmd.CmdID, "error", fmt.Sprintf("base64 decode: %v", err))
			return
		}
		fileContent = decoded
	default: // "openssh" or absent — plain text, backward-compatible
		fileContent = []byte(fwPayload.Content)
	}
	if err := a.fileAccess.WriteFile(fwPayload.Path, fileContent, perm); err != nil {
		slog.Error("file_write failed", "cmd_id", cmd.CmdID, "path", fwPayload.Path, "err", err)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("write %s: %v", fwPayload.Path, err))
		return
	}
	slog.Info("file_write succeeded", "cmd_id", cmd.CmdID, "path", fwPayload.Path)
	a.ackOkAndReport(cmd.CmdID, "file_write")
}

func (a *Agent) handleHostKeyRestore(cmd Command) {
	var hkPayload HostKeyRestorePayload
	if !a.decodeOrAck(cmd, &hkPayload) {
		return
	}
	if len(hkPayload.Keys) == 0 {
		a.publishAck(cmd.CmdID, "error", "keys map is empty")
		return
	}
	allowedFilenames := allowedHostKeyFilenamesByDaemon[a.sshDaemon.Name]
	for name, content := range hkPayload.Keys {
		// filepath.Base strips directory components to prevent path traversal.
		safe := filepath.Base(name)
		// Allowlist check: only filenames valid for the detected SSH daemon are accepted.
		if !allowedFilenames[safe] {
			slog.Error("host_key_restore: filename not in allowlist", "cmd_id", cmd.CmdID, "file", safe, "daemon", a.sshDaemon.Name)
			a.publishAck(cmd.CmdID, "error", fmt.Sprintf("filename not permitted for %s: %s", a.sshDaemon.Name, safe))
			return
		}
		path := a.sshDaemon.Dir + safe
		if err := a.fileAccess.WriteFile(path, content, 0600); err != nil {
			slog.Error("host_key_restore: write failed", "cmd_id", cmd.CmdID, "file", safe, "err", err)
			a.publishAck(cmd.CmdID, "error", fmt.Sprintf("write %s: %v", safe, err))
			return
		}
		slog.Debug("host_key_restore: wrote key file", "file", safe)
	}
	// Restart the SSH daemon so it picks up the restored keys.
	if _, err := a.uci.ExecCmd(a.sshDaemon.Service, "restart"); err != nil {
		// Non-fatal: keys are already on disk; the daemon will use them on next connection.
		slog.Warn("host_key_restore: service restart failed (non-fatal)", "cmd_id", cmd.CmdID, "daemon", a.sshDaemon.Name, "err", err)
	}
	slog.Info("host_key_restore succeeded", "cmd_id", cmd.CmdID, "files", len(hkPayload.Keys))
	a.ackOkAndReport(cmd.CmdID, "host_key_restore")
}

func (a *Agent) handleHostKeyRemove(cmd Command) {
	removed := 0
	for name := range allowedHostKeyFilenamesByDaemon[a.sshDaemon.Name] {
		path := a.sshDaemon.Dir + name
		// ubus's file.remove already treats a missing path as success, so —
		// unlike the previous os.Remove-based version — there's no error to
		// distinguish "didn't exist" from "removal failed"; check existence
		// first so the removed count still reflects files that genuinely
		// existed, same as before.
		exists, err := a.fileAccess.Exists(path)
		if err != nil {
			slog.Warn("host_key_remove: could not check existence", "cmd_id", cmd.CmdID, "path", path, "err", err)
			continue
		}
		if !exists {
			continue
		}
		if err := a.fileAccess.Remove(path); err != nil {
			slog.Warn("host_key_remove: could not remove file", "cmd_id", cmd.CmdID, "path", path, "err", err)
			continue
		}
		slog.Debug("host_key_remove: removed key file", "path", path)
		removed++
	}
	if _, err := a.uci.ExecCmd(a.sshDaemon.Service, "restart"); err != nil {
		// Non-fatal: keys are already gone; the daemon will regenerate on next start.
		slog.Warn("host_key_remove: service restart failed (non-fatal)", "cmd_id", cmd.CmdID, "daemon", a.sshDaemon.Name, "err", err)
	}
	slog.Info("host_key_remove succeeded", "cmd_id", cmd.CmdID, "removed", removed)
	a.ackOkAndReport(cmd.CmdID, "host_key_remove")
}

type setPasswordPayload struct {
	Target string `json:"target"`
	Hash   string `json:"hash"`
}

func (a *Agent) handleSetPassword(cmd Command) {
	var p setPasswordPayload
	if !a.decodeOrAck(cmd, &p) {
		return
	}
	if p.Target != "root" {
		slog.Error("set_password rejected: unsupported target", "cmd_id", cmd.CmdID, "target", p.Target)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("unsupported target: %s", p.Target))
		return
	}
	if p.Hash == "" {
		a.publishAck(cmd.CmdID, "error", "hash is required")
		return
	}
	if err := a.passwordSetter.SetPassword(p.Target, p.Hash); err != nil {
		slog.Error("set_password failed", "cmd_id", cmd.CmdID, "target", p.Target, "err", err)
		a.publishAck(cmd.CmdID, "error", err.Error())
		return
	}
	slog.Info("set_password succeeded", "cmd_id", cmd.CmdID, "target", p.Target)
	a.ackOkAndReport(cmd.CmdID, "set_password")
}

func (a *Agent) handleHostKeyFetch(cmd Command) {
	allowedFilenames := allowedHostKeyFilenamesByDaemon[a.sshDaemon.Name]
	slog.Info("host_key_fetch: scanning", "cmd_id", cmd.CmdID, "daemon", a.sshDaemon.Name, "dir", a.sshDaemon.Dir)
	keys := make(map[string][]byte)
	for name := range allowedFilenames {
		path := a.sshDaemon.Dir + name
		content, err := a.fileAccess.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				slog.Debug("host_key_fetch: not found, skipping", "file", path)
				continue
			}
			slog.Error("host_key_fetch: read failed", "cmd_id", cmd.CmdID, "file", name, "err", err)
			a.publishAck(cmd.CmdID, "error", fmt.Sprintf("read %s: %v", name, err))
			return
		}
		slog.Info("host_key_fetch: found key file", "cmd_id", cmd.CmdID, "file", name)
		keys[name] = content
	}
	if len(keys) == 0 {
		slog.Info("host_key_fetch: no host key files found, reporting empty set", "cmd_id", cmd.CmdID, "daemon", a.sshDaemon.Name)
	} else {
		slog.Info("host_key_fetch succeeded", "cmd_id", cmd.CmdID, "files", len(keys))
	}
	a.publishAckKeys(cmd.CmdID, keys)
}

type tlsCertPushPayload struct {
	CertPEM        string `json:"cert_pem"`
	KeyPEM         string `json:"key_pem"`
	CertPath       string `json:"cert_path"`
	KeyPath        string `json:"key_path"`
	RestartService string `json:"restart_service"`
}

func (a *Agent) handleTlsCertPush(cmd Command) {
	var p tlsCertPushPayload
	if !a.decodeOrAck(cmd, &p) {
		return
	}
	if p.CertPEM == "" || p.KeyPEM == "" {
		a.publishAck(cmd.CmdID, "error", "cert_pem and key_pem are required")
		return
	}
	if p.CertPath == "" || p.KeyPath == "" {
		a.publishAck(cmd.CmdID, "error", "cert_path and key_path are required")
		return
	}
	if !isTlsCertPathAllowed(p.CertPath) {
		slog.Error("tls_cert_push rejected: cert_path not in allowlist", "cmd_id", cmd.CmdID, "path", p.CertPath)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("cert_path not permitted: %s", p.CertPath))
		return
	}
	if !isTlsCertPathAllowed(p.KeyPath) {
		slog.Error("tls_cert_push rejected: key_path not in allowlist", "cmd_id", cmd.CmdID, "path", p.KeyPath)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("key_path not permitted: %s", p.KeyPath))
		return
	}

	if err := a.fileAccess.WriteFile(p.CertPath, []byte(p.CertPEM), 0644); err != nil {
		slog.Error("tls_cert_push: write cert failed", "cmd_id", cmd.CmdID, "path", p.CertPath, "err", err)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("write cert: %v", err))
		return
	}
	if err := a.fileAccess.WriteFile(p.KeyPath, []byte(p.KeyPEM), 0600); err != nil {
		slog.Error("tls_cert_push: write key failed", "cmd_id", cmd.CmdID, "path", p.KeyPath, "err", err)
		a.publishAck(cmd.CmdID, "error", fmt.Sprintf("write key: %v", err))
		return
	}

	svc := p.RestartService
	if svc == "" {
		svc = "uhttpd"
	}
	if _, err := a.uci.ExecCmd("/etc/init.d/"+svc, "restart"); err != nil {
		slog.Warn("tls_cert_push: service restart failed (best-effort)", "cmd_id", cmd.CmdID, "service", svc, "err", err)
	}

	a.setTLSCertPaths(p.CertPath, p.KeyPath)

	slog.Info("tls_cert_push succeeded", "cmd_id", cmd.CmdID, "cert_path", p.CertPath, "key_path", p.KeyPath)
	a.ackOkAndReport(cmd.CmdID, "tls_cert_push")
}

// defaultTLSKeyPath is the key file counterpart to defaultTLSCertPath.
// Matches TlsCertService.DEFAULT_KEY_PATH on the backend.
const defaultTLSKeyPath = "/etc/uhttpd.key"

func (a *Agent) handleTlsCertRemove(cmd Command) {
	certPath := a.getTLSCertPath()
	if certPath == "" {
		certPath = defaultTLSCertPath
	}
	keyPath := a.getTLSKeyPath()
	if keyPath == "" {
		keyPath = defaultTLSKeyPath
	}

	for _, path := range []string{certPath, keyPath} {
		// ubus's file.remove already treats a missing path as success, so —
		// unlike the previous os.Remove-based version — any error here is a
		// genuine failure, not "didn't exist."
		if err := a.fileAccess.Remove(path); err != nil {
			slog.Warn("tls_cert_remove: could not remove file", "cmd_id", cmd.CmdID, "path", path, "err", err)
		}
	}

	if _, err := a.uci.ExecCmd("/etc/init.d/uhttpd", "restart"); err != nil {
		slog.Warn("tls_cert_remove: uhttpd restart failed (non-fatal)", "cmd_id", cmd.CmdID, "err", err)
	}

	a.setTLSCertPaths("", "")
	slog.Info("tls_cert_remove succeeded", "cmd_id", cmd.CmdID, "cert_path", certPath, "key_path", keyPath)
	a.ackOkAndReport(cmd.CmdID, "tls_cert_remove")
}

// isTlsCertPathAllowed validates that the path starts with /etc/ or /tmp/ after cleaning.
func isTlsCertPathAllowed(path string) bool {
	return pathHasAllowedPrefix(path, tlsCertAllowedDirs)
}

func (a *Agent) handleServiceApply(cmd Command) {
	var p struct {
		Services map[string]bool `json:"services"`
	}
	if !a.decodeOrAck(cmd, &p) {
		return
	}

	var errs []string
	for name, enable := range p.Services {
		if !safeIdentifierRe.MatchString(name) || len(name) > 64 {
			slog.Warn("service_apply: invalid service name, skipping", "cmd_id", cmd.CmdID, "name", name)
			errs = append(errs, fmt.Sprintf("%s: invalid name", name))
			continue
		}
		script := filepath.Join(a.initdDir, name)
		exists, err := a.fileAccess.Exists(script)
		if err != nil {
			slog.Error("service_apply: existence check failed", "cmd_id", cmd.CmdID, "name", name, "err", err)
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if !exists {
			slog.Warn("service_apply: service not found, skipping", "cmd_id", cmd.CmdID, "name", name)
			errs = append(errs, fmt.Sprintf("%s: not found", name))
			continue
		}

		if enable {
			if _, err := a.uci.ExecCmd(script, "enable"); err != nil {
				slog.Error("service_apply: enable failed", "cmd_id", cmd.CmdID, "name", name, "err", err)
				errs = append(errs, fmt.Sprintf("%s: enable: %v", name, err))
				continue
			}
			if _, err := a.uci.ExecCmd(script, "start"); err != nil {
				slog.Error("service_apply: start failed", "cmd_id", cmd.CmdID, "name", name, "err", err)
				errs = append(errs, fmt.Sprintf("%s: start: %v", name, err))
				continue
			}
		} else {
			if _, err := a.uci.ExecCmd(script, "stop"); err != nil {
				slog.Warn("service_apply: stop failed (best-effort)", "cmd_id", cmd.CmdID, "name", name, "err", err)
			}
			if _, err := a.uci.ExecCmd(script, "disable"); err != nil {
				slog.Error("service_apply: disable failed", "cmd_id", cmd.CmdID, "name", name, "err", err)
				errs = append(errs, fmt.Sprintf("%s: disable: %v", name, err))
				continue
			}
		}
		slog.Info("service_apply: applied", "cmd_id", cmd.CmdID, "name", name, "enabled", enable)
	}

	if len(errs) > 0 {
		a.publishAck(cmd.CmdID, "error", strings.Join(errs, "; "))
		return
	}
	a.publishAck(cmd.CmdID, "ok", "")
}

type logControlPayload struct {
	Enabled bool `json:"enabled"`
}

// handleLogControl toggles the persistent activity log file at runtime
// (device.log survives reboots and is enabled by default — see
// internal/agent/activitylog.go). Nil-safe: if the log file failed to open
// at startup, a.activityLog is nil and this is a no-op ack "ok".
func (a *Agent) handleLogControl(cmd Command) {
	var p logControlPayload
	if !a.decodeOrAck(cmd, &p) {
		return
	}
	if a.activityLog != nil {
		a.activityLog.SetEnabled(p.Enabled)
	}
	slog.Info("log_control applied", "cmd_id", cmd.CmdID, "enabled", p.Enabled)
	a.publishAck(cmd.CmdID, "ok", "")
}
