package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
)

// ApkPackageInfo holds metadata for a single APK package.
type ApkPackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	Size    string `json:"size,omitempty"`
	Desc    string `json:"description,omitempty"`
}

// ApkReportData is embedded in the ACK payload for apk_report commands.
type ApkReportData struct {
	Available []ApkPackageInfo `json:"available"`
	Installed []ApkPackageInfo `json:"installed"`
}

// revisionRe matches the APK revision suffix like "r0", "r12".
var revisionRe = regexp.MustCompile(`^r\d+$`)

// parseApkListLine parses one line of `apk list` output.
// APK v3 format: "name-version-rN arch {origin} (license) [flags]"
// Returns (name, version, arch) or ("", "", "") on parse failure.
func parseApkListLine(line string) (name, version, arch string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", ""
	}
	nameVerRev := fields[0]
	arch = fields[1]

	// Split nameVerRev on "-" and find the revision from the right.
	parts := strings.Split(nameVerRev, "-")
	if len(parts) < 3 {
		return "", "", ""
	}

	// Scan from the right to find the revision part (r\d+).
	revIdx := -1
	for i := len(parts) - 1; i >= 2; i-- {
		if revisionRe.MatchString(parts[i]) {
			revIdx = i
			break
		}
	}
	if revIdx < 2 {
		// No valid revision found; try treating last part as revision anyway
		// (handles edge cases like single-segment versions).
		if revisionRe.MatchString(parts[len(parts)-1]) {
			revIdx = len(parts) - 1
		}
		if revIdx < 2 {
			return "", "", ""
		}
	}

	version = parts[revIdx-1]
	name = strings.Join(parts[:revIdx-1], "-")
	return name, version, arch
}

// parseApkList parses the full output of `apk list` into []ApkPackageInfo.
func parseApkList(output string) []ApkPackageInfo {
	var result []ApkPackageInfo
	for _, line := range strings.Split(output, "\n") {
		name, version, arch := parseApkListLine(line)
		if name == "" {
			continue
		}
		result = append(result, ApkPackageInfo{Name: name, Version: version, Arch: arch})
	}
	return result
}

// runApkList executes `apk list <args>` and returns the raw output.
func (a *Agent) runApkList(args ...string) (string, error) {
	fullArgs := append([]string{"list"}, args...)
	out, err := a.uci.ExecCmd("apk", fullArgs...)
	return string(out), err
}

// handleApkReport runs `apk list -I` and `apk list -a`, then ACKs with both lists.
func (a *Agent) handleApkReport(cmd Command) {
	slog.Debug("apk_report: fetching package lists", "cmd_id", cmd.CmdID)

	installedOut, err := a.runApkList("-I")
	if err != nil {
		slog.Warn("apk_report: apk list -I failed", "err", err)
		// Still continue — available list might succeed
	}

	// Refresh the package index so apk list -a returns the full repository contents.
	// Without this, the local APK database may be empty and available would be [].
	if _, errUpdate := a.uci.ExecCmd("apk", "update"); errUpdate != nil {
		slog.Warn("apk_report: apk update failed — using cached index", "err", errUpdate)
	}

	availableOut, errAvail := a.runApkList("-a")
	if errAvail != nil {
		slog.Warn("apk_report: apk list -a failed", "err", errAvail)
		if err != nil {
			a.publishAck(cmd.CmdID, "error", "apk list failed: "+err.Error())
			return
		}
	}

	installed := parseApkList(installedOut)
	available := parseApkList(availableOut)

	a.publishAckApk(cmd.CmdID, "ok", "", &ApkReportData{
		Available: available,
		Installed: installed,
	})
	slog.Info("apk_report: complete", "cmd_id", cmd.CmdID, "installed", len(installed), "available", len(available))
}

// publishAckApk publishes an ACK carrying APK package data.
func (a *Agent) publishAckApk(cmdID, status, output string, packages *ApkReportData) {
	slog.Debug("publishing apk ack", "cmd_id", cmdID, "status", status)
	type apkAckPayload struct {
		CmdID       string         `json:"cmd_id"`
		Status      string         `json:"status"`
		Output      string         `json:"output,omitempty"`
		Timestamp   string         `json:"timestamp"`
		ApkPackages *ApkReportData `json:"apk_packages,omitempty"`
	}
	ack := apkAckPayload{
		CmdID:       cmdID,
		Status:      status,
		Output:      output,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ApkPackages: packages,
	}
	payload, err := json.Marshal(ack)
	if err != nil {
		slog.Error("marshal apk ack", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.mqtt.Publish(ctx, mqttclient.TopicAck(a.creds.DeviceID), payload, 1, false); err != nil {
		slog.Error("publish apk ack", "cmd_id", cmdID, "err", err)
	}
}
