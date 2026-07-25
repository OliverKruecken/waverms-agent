package agent

import (
	"encoding/json"
	"testing"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

func TestParseApkListLine(t *testing.T) {
	tests := []struct {
		line        string
		wantName    string
		wantVersion string
		wantArch    string
	}{
		{
			line:        "busybox-1.37.0-r0 x86_64 {busybox} (GPL-2.0-only) [installed]",
			wantName:    "busybox",
			wantVersion: "1.37.0",
			wantArch:    "x86_64",
		},
		{
			line:        "kmod-usb-net-rndis-6.6.63-r1 x86_64 {kmod-usb-net-rndis} (GPL-2.0-only)",
			wantName:    "kmod-usb-net-rndis",
			wantVersion: "6.6.63",
			wantArch:    "x86_64",
		},
		{
			line:        "libc-musl-1.2.5-r0 x86_64 {musl} (MIT)",
			wantName:    "libc-musl",
			wantVersion: "1.2.5",
			wantArch:    "x86_64",
		},
		{
			line:        "# comment line",
			wantName:    "",
			wantVersion: "",
			wantArch:    "",
		},
		{
			line:        "",
			wantName:    "",
			wantVersion: "",
			wantArch:    "",
		},
		{
			line:        "invalid",
			wantName:    "",
			wantVersion: "",
			wantArch:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, version, arch := parseApkListLine(tt.line)
			if name != tt.wantName || version != tt.wantVersion || arch != tt.wantArch {
				t.Errorf("parseApkListLine(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.line, name, version, arch, tt.wantName, tt.wantVersion, tt.wantArch)
			}
		})
	}
}

func TestParseApkList(t *testing.T) {
	output := `busybox-1.37.0-r0 x86_64 {busybox} (GPL-2.0-only) [installed]
kmod-usb-net-rndis-6.6.63-r1 x86_64 {kmod-usb-net-rndis} (GPL-2.0-only)
libc-musl-1.2.5-r0 x86_64 {musl} (MIT)
`
	pkgs := parseApkList(output)
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "busybox" || pkgs[0].Version != "1.37.0" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
	if pkgs[1].Name != "kmod-usb-net-rndis" || pkgs[1].Version != "6.6.63" {
		t.Errorf("pkgs[1] = %+v", pkgs[1])
	}
}

func TestHandleApkReport(t *testing.T) {
	const installedOutput = "busybox-1.37.0-r0 x86_64 {busybox} (GPL-2.0-only) [installed]\n"
	const availableOutput = "busybox-1.37.0-r0 x86_64 {busybox} (GPL-2.0-only)\ncurl-8.5.0-r0 x86_64 {curl} (curl)\n"

	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"cmd apk list -I": installedOutput,
			"cmd apk update":  "",
			"cmd apk list -a": availableOutput,
		},
	}

	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-1",
		Type:    "apk_report",
		Payload: []byte(`{}`),
	}
	a.handleApkReport(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]

	var ack struct {
		CmdID  string `json:"cmd_id"`
		Status string `json:"status"`
		Pkgs   *struct {
			Installed []ApkPackageInfo `json:"installed"`
			Available []ApkPackageInfo `json:"available"`
		} `json:"apk_packages"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.CmdID != "test-cmd-1" {
		t.Errorf("cmd_id = %q, want %q", ack.CmdID, "test-cmd-1")
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if ack.Pkgs == nil || len(ack.Pkgs.Installed) == 0 {
		t.Errorf("expected installed packages in ack, got %+v", ack.Pkgs)
	}
	if ack.Pkgs == nil || len(ack.Pkgs.Available) == 0 {
		t.Errorf("expected available packages in ack, got %+v", ack.Pkgs)
	}

	// Verify apk update was called to refresh the repository index.
	found := false
	for _, call := range mock.Calls {
		if call == "cmd apk update" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'apk update' to be called before listing available packages; calls: %v", mock.Calls)
	}
}

func TestHandleApkManage_InvalidPackageName(t *testing.T) {
	mock := &uci.MockUCIRunner{}
	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-2",
		Type:    "apk_manage",
		Payload: []byte(`{"install":["../../etc/passwd"],"remove":[]}`),
	}
	a.handleApkManage(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "error" {
		t.Errorf("expected error status for invalid package name, got %q", ack.Status)
	}
}

func TestHandleApkManage_Success(t *testing.T) {
	const installedOutput = "curl-8.5.0-r0 x86_64 {curl} (curl)\n"
	mock := &uci.MockUCIRunner{
		Results: map[string]string{
			"cmd apk list -I": installedOutput,
			"cmd apk add curl": "",
			"cmd apk del wget": "",
		},
	}

	mqttMock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mqttMock, mock)

	cmd := Command{
		CmdID:   "test-cmd-3",
		Type:    "apk_manage",
		Payload: []byte(`{"install":["curl"],"remove":["wget"]}`),
	}
	a.handleApkManage(cmd)

	if len(mqttMock.Published) == 0 {
		t.Fatal("expected ACK to be published")
	}
	lastMsg := mqttMock.Published[len(mqttMock.Published)-1]
	var ack struct {
		CmdID  string `json:"cmd_id"`
		Status string `json:"status"`
		Pkgs   *struct {
			Installed []ApkPackageInfo `json:"installed"`
		} `json:"apk_packages"`
	}
	if err := json.Unmarshal(lastMsg.Payload, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Status != "ok" {
		t.Errorf("status = %q, want ok", ack.Status)
	}
	if ack.Pkgs == nil || len(ack.Pkgs.Installed) == 0 {
		t.Errorf("expected installed packages in apk_manage ack")
	}
}
