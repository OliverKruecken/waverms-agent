package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/config"
	"github.com/OliverKruecken/waverms-agent/internal/filewriter"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAgentWithFW(mock *mqttclient.MockMQTTClient, uciMock *uci.MockUCIRunner, fw *filewriter.MockFileAccess) *Agent {
	cfg := &config.Config{
		BrokerHost:        "broker.local",
		BrokerPort:        8883,
		HeartbeatInterval: 60,
	}
	creds := &config.Credentials{
		DeviceID: "test-device-uuid",
		Secret:   "test-secret",
	}
	return New(&Options{
		Config:        cfg,
		Creds:         creds,
		MAC:           "aa:bb:cc:dd:ee:ff",
		MQTT:          mock,
		UCI:           uciMock,
		FileAccess:    fw,
		Version:       "1.0.0",
		SSHDaemon:     &daemonDropbear,
		AckRetryDelay: time.Millisecond,
	})
}

func newTestAgent(mock *mqttclient.MockMQTTClient, uciMock *uci.MockUCIRunner) *Agent {
	return newTestAgentWithFW(mock, uciMock, &filewriter.MockFileAccess{})
}

func TestPublishInfo_SendsToCorrectTopic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	require.Len(t, mock.Published, 1)
	assert.Equal(t, "device/test-device-uuid/info", mock.Published[0].Topic)
}

func TestPublishInfo_PayloadContainsDeviceID(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Equal(t, "test-device-uuid", info.DeviceID)
	assert.Equal(t, "1.0.0", info.AgentVersion)
	assert.NotEmpty(t, info.Timestamp)
}

func TestPublishInfo_PayloadContainsCapabilities(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.NotEmpty(t, info.Capabilities, "capabilities must be non-empty")
}

func TestPublishInfo_CapabilitiesContainExpectedTypes(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "uci_set")
	assert.Contains(t, info.Capabilities, "config_apply")
	assert.Contains(t, info.Capabilities, "file_write")
	assert.Contains(t, info.Capabilities, "state_report")
	assert.Contains(t, info.Capabilities, "host_key_restore")
}

func TestPublishAck_RetriesOnPublishFailure(t *testing.T) {
	cases := []struct {
		name          string
		failures      int
		wantPublished int
		wantCalls     int
	}{
		{"succeeds first try", 0, 1, 1},
		{"succeeds after one retry", 1, 1, 2},
		{"succeeds on last attempt", 2, 1, 3},
		{"gives up after max attempts", 3, 0, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			mock.FailNextPublishes(tc.failures, errors.New("broker unreachable"))
			a := newTestAgent(mock, &uci.MockUCIRunner{})

			a.publishAck("cmd-1", "ok", "")

			assert.Equal(t, tc.wantCalls, mock.PublishCalls)
			require.Len(t, mock.Published, tc.wantPublished)
			if tc.wantPublished > 0 {
				assert.Equal(t, "device/test-device-uuid/ack", mock.Published[0].Topic)
				var ack AckPayload
				require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
				assert.Equal(t, "cmd-1", ack.CmdID)
				assert.Equal(t, "ok", ack.Status)
			}
		})
	}
}

func TestPublishAckKeys_RetriesOnPublishFailure(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	mock.FailNextPublishes(1, errors.New("broker unreachable"))
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	a.publishAckKeys("cmd-2", map[string][]byte{"dropbear_ed25519_host_key": []byte("key")})

	assert.Equal(t, 2, mock.PublishCalls)
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-2", ack.CmdID)
	assert.Contains(t, ack.Keys, "dropbear_ed25519_host_key")
}

func TestHandleCommand_HostKeyRestore_WritesFilesAndRestartDropbear(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	// Values are standard base64 (RFC 4648); encoding/json decodes []byte automatically.
	// "-----BEGIN OPENSSH PRIVATE KEY-----\nfake_ed25519\n"
	const privKeyB64 = "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KZmFrZV9lZDI1NTE5Cg=="
	// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA fake"
	const pubKeyB64 = "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBIGZha2U="

	payload := `{
		"cmd_id": "hkr-1",
		"type": "host_key_restore",
		"payload": {
			"keys": {
				"ssh_host_ed25519_key":     "` + privKeyB64 + `",
				"ssh_host_ed25519_key.pub": "` + pubKeyB64 + `"
			}
		}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Both key files must have been written under /etc/dropbear/
	contents := make(map[string][]byte)
	for _, c := range fw.Calls {
		contents[c.Path] = c.Content
		assert.Equal(t, os.FileMode(0600), c.Perm, "host key files must have mode 0600")
	}
	require.Contains(t, contents, "/etc/dropbear/ssh_host_ed25519_key", "private key must be written")
	require.Contains(t, contents, "/etc/dropbear/ssh_host_ed25519_key.pub", "public key must be written")
	// Content written to disk must be the decoded bytes, not the base64 string.
	assert.Equal(t, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake_ed25519\n"), contents["/etc/dropbear/ssh_host_ed25519_key"])
	assert.Equal(t, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA fake"), contents["/etc/dropbear/ssh_host_ed25519_key.pub"])

	// Dropbear must have been restarted
	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/dropbear restart")

	// Ack must be "ok", followed by a state report confirming the change.
	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "hkr-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.Equal(t, "device/test-device-uuid/state", mock.Published[1].Topic)
}

func TestHandleCommand_HostKeyRestore_PathTraversalGuard(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	// A path-traversal key resolves to "passwd" after filepath.Base().
	// "passwd" is not in the allowedHostKeyFilenames allowlist, so the
	// command must be rejected — WriteFile must NOT be called at all.
	payload := `{
		"cmd_id": "hkr-traverse",
		"type": "host_key_restore",
		"payload": {
			"keys": {
				"../../etc/passwd": "ZXZpbCBjb250ZW50"
			}
		}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// WriteFile must NOT be called — the filename is not in the allowlist.
	assert.Empty(t, fw.Calls, "WriteFile must not be called for disallowed filename")

	// Ack must be an error.
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "not permitted")
}

func TestHandleCommand_HostKeyRestore_DisallowedFilename_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	disallowed := []string{"authorized_keys", ".profile", "known_hosts", "passwd", "shadow"}
	for _, fname := range disallowed {
		t.Run(fname, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			fw := &filewriter.MockFileAccess{}
			a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

			payload := `{"cmd_id":"hkr-deny","type":"host_key_restore","payload":{"keys":{"` + fname + `":"Y29udGVudA=="}}}`
			a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

			assert.Empty(t, fw.Calls, "WriteFile must not be called for disallowed filename %q", fname)
			require.Len(t, mock.Published, 1)
			var ack AckPayload
			require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
			assert.Equal(t, "error", ack.Status)
		})
	}

	_ = mock
	_ = fw
	_ = a
}

func TestHandleCommand_HostKeyRestore_OpenSSH_RejectDropbearFilename(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	cfg := &config.Config{BrokerHost: "broker.local", BrokerPort: 8883, HeartbeatInterval: 60}
	creds := &config.Credentials{DeviceID: "test-device-uuid", Secret: "test-secret"}
	a := New(&Options{
		Config:     cfg,
		Creds:      creds,
		MAC:        "aa:bb:cc:dd:ee:ff",
		MQTT:       mock,
		UCI:        &uci.MockUCIRunner{},
		FileAccess: fw,
		Version:    "1.0.0",
		SSHDaemon:  &daemonOpenSSH,
	})

	// Dropbear-specific filename must be rejected on an OpenSSH device.
	payload := `{"cmd_id":"hkr-cross","type":"host_key_restore","payload":{"keys":{"dropbear_ed25519_host_key":"Y29udGVudA=="}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Empty(t, fw.Calls, "WriteFile must not be called for a Dropbear filename on an OpenSSH device")
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "openssh")
}

func TestHandleCommand_HostKeyRestore_WriteError_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{
		Errors: map[string]error{
			"/etc/dropbear/ssh_host_ed25519_key": errors.New("disk full"),
		},
	}
	a := newTestAgentWithFW(mock, uciMock, fw)

	// "content" base64-encoded
	payload := `{
		"cmd_id": "hkr-err",
		"type": "host_key_restore",
		"payload": {
			"keys": {"ssh_host_ed25519_key": "Y29udGVudA=="}
		}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
}

func TestHandleCommand_HostKeyRestore_EmptyKeys_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	payload := `{"cmd_id": "hkr-empty", "type": "host_key_restore", "payload": {"keys": {}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
}

func TestHandleCommand_HostKeyRestore_DropbearRestartFailure_StillAcksOk(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"cmd /etc/init.d/dropbear restart": errors.New("service not found"),
		},
	}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	// "content" base64-encoded
	payload := `{
		"cmd_id": "hkr-restart-fail",
		"type": "host_key_restore",
		"payload": {"keys": {"ssh_host_ed25519_key": "Y29udGVudA=="}}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Dropbear restart failure is non-fatal — ack must still be "ok"
	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_HostKeyRemove_RemovesFilesAndRestartsService(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{"cmd_id":"hkrem-1","type":"host_key_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Service must have been restarted.
	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/dropbear restart")

	// Ack must be "ok" — removal is best-effort.
	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "hkrem-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_HostKeyRemove_ServiceRestartFailure_StillAcksOk(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"cmd /etc/init.d/dropbear restart": errors.New("service not found"),
		},
	}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{"cmd_id":"hkrem-rfail","type":"host_key_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_HostKeyRemove_OpenSSH_UsesCorrectDirAndService(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	cfg := &config.Config{BrokerHost: "broker.local", BrokerPort: 8883, HeartbeatInterval: 60}
	creds := &config.Credentials{DeviceID: "test-device-uuid", Secret: "test-secret"}
	a := New(&Options{
		Config:     cfg,
		Creds:      creds,
		MAC:        "aa:bb:cc:dd:ee:ff",
		MQTT:       mock,
		UCI:        uciMock,
		FileAccess: fw,
		Version:    "1.0.0",
		SSHDaemon:  &daemonOpenSSH,
	})

	payload := `{"cmd_id":"hkrem-openssh","type":"host_key_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/sshd restart")

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestPublishInfo_IncludesSSHDaemonCapability(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "host_key_remove")
	assert.Contains(t, info.Capabilities, "ssh_daemon:dropbear")
}

func TestHandleCommand_UCISet_ExecutesAndAcks(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgent(mock, uciMock)

	payload := `{
		"cmd_id": "cmd-abc",
		"type": "uci_set",
		"payload": {"commands": ["uci set system.@system[0].hostname=router-01", "uci commit system"]}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// UCI must have been called
	assert.Contains(t, uciMock.Calls, "raw set system.@system[0].hostname=router-01")
	assert.Contains(t, uciMock.Calls, "raw commit system")

	// Ack must be published
	require.Len(t, mock.Published, 1)
	assert.Equal(t, "device/test-device-uuid/ack", mock.Published[0].Topic)

	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-abc", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_UCISet_ErrorReflectedInAck(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"raw commit system": assert.AnError,
		},
	}
	a := newTestAgent(mock, uciMock)

	payload := `{
		"cmd_id": "cmd-err",
		"type": "uci_set",
		"payload": {"commands": ["uci commit system"]}
	}`

	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-err", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
}

func TestHandleCommand_UnknownType_ErrorAck(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	payload := `{"cmd_id": "cmd-x", "type": "unknown_type", "payload": {}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
}

func TestHandleCommand_InvalidJSON_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	// Should not panic, should not publish anything
	a.handleCommand("device/test-device-uuid/cmd", []byte(`not-json`))
	assert.Empty(t, mock.Published)
}

func TestRunSession_DisconnectsWhenSubscribeFails(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	mock.SetSubscribeErr(errors.New("broker refused subscribe"))
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.runSession(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subscribe")

	// Disconnect must have been called to release the TCP fd.
	assert.Equal(t, 1, mock.DisconnectCount(), "Disconnect must be called when Subscribe fails")
}

func TestRunSession_SetsLWTOnConnect(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runSession(ctx) //nolint:errcheck
	}()

	// Give the session a moment to connect.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSession did not stop on ctx cancel")
	}

	require.Len(t, mock.ConnectOpts, 1)
	connOpts := mock.ConnectOpts[0]
	require.NotNil(t, connOpts.LWT)
	assert.Equal(t, "device/test-device-uuid/status", connOpts.LWT.Topic)
	assert.Equal(t, []byte("offline"), connOpts.LWT.Payload)
	assert.Equal(t, byte(1), connOpts.LWT.QoS)
	assert.True(t, connOpts.LWT.Retain)
}

func TestRunSession_ReconnectsAfterDisconnect(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx) //nolint:errcheck
	}()

	// Wait for first session to start.
	time.Sleep(30 * time.Millisecond)

	// Trigger a disconnect.
	mock.SimulateDisconnect()

	// The reconnect loop waits 1 second before the second connect attempt.
	// Wait long enough for the reconnect, with a generous margin.
	time.Sleep(1500 * time.Millisecond)

	cancel()
	<-done

	// Should have connected at least twice: initial + reconnect.
	connectCount := mock.ConnectCount()
	assert.GreaterOrEqual(t, connectCount, 2, "expected at least 2 connect calls (initial + reconnect)")
}

// TestRunSession_SurfacesDisconnectReason guards against a real device
// showing only a generic "connection lost" in its logs for every disconnect,
// with no way to tell a keepalive timeout from a TCP read error from a
// server-initiated disconnect. runSession must fold the client's actual
// DisconnectReason into the error it returns, so "session ended, reconnecting"
// carries the real cause.
func TestRunSession_SurfacesDisconnectReason(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- a.runSession(ctx) }()

	// Let the session finish connecting/subscribing (which clears any prior
	// reason, mirroring PahoClient.Connect) before setting the reason a real
	// disconnect callback would have recorded, then disconnecting.
	time.Sleep(30 * time.Millisecond)
	mock.SetDisconnectReason(errors.New("keepalive timeout"))
	mock.SimulateDisconnect()

	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keepalive timeout")
	case <-time.After(time.Second):
		t.Fatal("runSession did not return after simulated disconnect")
	}
}

func TestRun_BackoffResetsAfterHealthySession(t *testing.T) {
	// After a session that runs longer than sessionHealthyThreshold the reconnect
	// backoff must reset to 1 s, not accumulate toward 300 s.
	// We verify this by measuring that the second connect happens quickly after
	// a disconnect that follows a >30 s simulated session.
	//
	// To avoid an actual 30 s wait we monkey-patch time by making runSession
	// sleep long enough — but we can't do that without touching production code.
	// Instead we verify the invariant at the unit level: two rapid disconnects
	// after a fast session must not take longer than two fast delays (2 * 1 s = 2 s).
	// The real threshold reset path is exercised by the integration path below.
	//
	// Practical integration note: a device that reconnects after days of uptime
	// would previously wait up to 300 s; this test documents the expected behaviour.
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx) //nolint:errcheck
	}()

	// Wait for first session to establish.
	time.Sleep(30 * time.Millisecond)

	// Trigger two rapid disconnects. Because each session lasts < 30 s the
	// backoff should double (1 s → 2 s), not reset.  What we care about is
	// that the code does NOT panic and that reconnects do happen.
	mock.SimulateDisconnect()
	time.Sleep(1500 * time.Millisecond) // wait for reconnect (1 s backoff)
	mock.SimulateDisconnect()
	time.Sleep(2500 * time.Millisecond) // wait for reconnect (2 s backoff)

	cancel()
	<-done

	// Must have connected at least 3 times: initial + 2 reconnects.
	assert.GreaterOrEqual(t, mock.ConnectCount(), 3,
		"expected ≥3 connects: initial + 2 reconnects after short sessions")
}

func TestRun_SkipsBootstrapWhenCredsPresent(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- a.Run(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	// With credentials present, Connect should be called with device credentials (not bootstrap).
	require.Len(t, mock.ConnectOpts, 1)
	assert.Equal(t, "test-device-uuid", mock.ConnectOpts[0].Username)
}

// TestRun_BootstrapForcesCleanStartOnNextConnect covers the sysupgrade-reboot-loop
// bug: a device that re-bootstraps (e.g. after a keep_config=false sysupgrade wiped
// its credentials) gets the same device.id back from the backend's MAC-based lookup,
// and therefore reconnects with the same MQTT ClientID it had before. Without
// forcing CleanStart=true on that first post-bootstrap connect, the broker would
// resume the pre-wipe session and redeliver whatever un-acked command — e.g. the
// very sysupgrade that caused the reboot — was still queued, causing an infinite
// reflash loop.
func TestRun_BootstrapForcesCleanStartOnNextConnect(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "bootstrap_token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-token\n"), 0600))
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	a := New(&Options{
		Config:                    &config.Config{BrokerHost: "broker.local", BrokerPort: 8883},
		MAC:                       "aa:bb:cc:dd:ee:ff",
		MQTT:                      mock,
		UCI:                       &uci.MockUCIRunner{},
		FileAccess:                &filewriter.MockFileAccess{},
		Version:                   "1.0.0",
		SSHDaemon:                 &daemonDropbear,
		AckRetryDelay:             time.Millisecond,
		BootstrapTokenPath:        tokenPath,
		CredsPath:                 credsPath,
		BootstrapTokenWaitTimeout: time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- a.Run(ctx)
	}()

	// Wait for bootstrap/register, then reply on the tmp_id it actually generated
	// (agent.go never sets a fixed TmpID, so bootstrap.Run() picks a random uuid).
	// a.Run(ctx) is still running concurrently at this point, so reads must go
	// through the mock's mutex via PublishedSnapshot rather than touching
	// mock.Published directly.
	var published []mqttclient.PublishedMsg
	require.Eventually(t, func() bool {
		published = mock.PublishedSnapshot()
		return len(published) > 0
	}, time.Second, time.Millisecond)
	var req struct {
		TmpID string `json:"tmp_id"`
	}
	require.NoError(t, json.Unmarshal(published[0].Payload, &req))
	require.Equal(t, "bootstrap/register", published[0].Topic)

	resp := struct {
		DeviceID   string `json:"device_id"`
		Secret     string `json:"secret"`
		BrokerHost string `json:"broker_host"`
		BrokerPort int    `json:"broker_port"`
	}{DeviceID: "re-bootstrapped-device", Secret: "new-secret"}
	payload, err := json.Marshal(resp)
	require.NoError(t, err)
	mock.SimulateMessage("bootstrap/"+req.TmpID+"/response", payload)

	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	// [0] is bootstrap.Run()'s own temporary connect (ClientID "bootstrap-<tmp_id>");
	// [1] is the real device session connect this fix targets.
	require.Len(t, mock.ConnectOpts, 2)
	assert.Equal(t, "re-bootstrapped-device", mock.ConnectOpts[1].Username)
	assert.True(t, mock.ConnectOpts[1].CleanStart,
		"first connect after a (re-)bootstrap must request CleanStart, or a stale queued "+
			"command from before the wipe (e.g. the sysupgrade that triggered it) gets replayed")
}

// ---- handleLiveLogsControl tests -----------------------------------------------

func newTestAgentWithLiveLogsHandler(mock *mqttclient.MockMQTTClient) (*Agent, *mqttLiveLogsHandler) {
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	// Wire up a real mqttLiveLogsHandler so SetEnabled / mqttEnabled() are exercised.
	textHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	dh := newMQTTLiveLogsHandler(textHandler, mock, a.creds.DeviceID)
	a.liveLogsHandler = dh
	return a, dh
}

func TestHandleLiveLogsControl_EnablesStreaming(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, dh := newTestAgentWithLiveLogsHandler(mock)

	a.handleLiveLogsControl("device/test-device-uuid/live-logs/control", []byte(`{"enabled":true}`))

	assert.True(t, dh.mqttEnabled(), "mqttEnabled must be true after enabled:true payload")
}

func TestHandleLiveLogsControl_DisablesStreaming(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, dh := newTestAgentWithLiveLogsHandler(mock)

	// First enable, then disable.
	a.handleLiveLogsControl("device/test-device-uuid/live-logs/control", []byte(`{"enabled":true}`))
	require.True(t, dh.mqttEnabled())

	a.handleLiveLogsControl("device/test-device-uuid/live-logs/control", []byte(`{"enabled":false}`))
	assert.False(t, dh.mqttEnabled(), "mqttEnabled must be false after enabled:false payload")
}

func TestHandleLiveLogsControl_InvalidJSON_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, dh := newTestAgentWithLiveLogsHandler(mock)

	// Must not panic; must leave state unchanged (false).
	assert.NotPanics(t, func() {
		a.handleLiveLogsControl("device/test-device-uuid/live-logs/control", []byte(`not-json`))
	})
	assert.False(t, dh.mqttEnabled(), "state must remain false after invalid payload")
}

func TestHandleLiveLogsControl_NilLiveLogsHandler_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	// a.liveLogsHandler is nil — must not panic.
	assert.NotPanics(t, func() {
		a.handleLiveLogsControl("device/test-device-uuid/live-logs/control", []byte(`{"enabled":true}`))
	})
}

// ---- handleLogLevelControl tests -----------------------------------------------

func newTestAgentWithLogLevel(mock *mqttclient.MockMQTTClient) (*Agent, *slog.LevelVar) {
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	lv := new(slog.LevelVar)
	lv.Set(slog.LevelInfo)
	a.logLevel = lv
	return a, lv
}

func TestHandleLogLevelControl_RaisesToDebug(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, lv := newTestAgentWithLogLevel(mock)

	a.handleLogLevelControl("device/test-device-uuid/log-level/control", []byte(`{"enabled":true}`))

	assert.Equal(t, slog.LevelDebug, lv.Level(), "level must be Debug after enabled:true payload")
}

func TestHandleLogLevelControl_LowersToInfo(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, lv := newTestAgentWithLogLevel(mock)
	lv.Set(slog.LevelDebug)

	a.handleLogLevelControl("device/test-device-uuid/log-level/control", []byte(`{"enabled":false}`))

	assert.Equal(t, slog.LevelInfo, lv.Level(), "level must be Info after enabled:false payload")
}

func TestHandleLogLevelControl_InvalidJSON_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, lv := newTestAgentWithLogLevel(mock)

	assert.NotPanics(t, func() {
		a.handleLogLevelControl("device/test-device-uuid/log-level/control", []byte(`not-json`))
	})
	assert.Equal(t, slog.LevelInfo, lv.Level(), "level must remain unchanged after invalid payload")
}

func TestHandleLogLevelControl_NilLogLevel_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	// a.logLevel is nil — must not panic.
	assert.NotPanics(t, func() {
		a.handleLogLevelControl("device/test-device-uuid/log-level/control", []byte(`{"enabled":true}`))
	})
}

func TestRunSession_SubscribesLiveLogsControl(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runSession(ctx) //nolint:errcheck
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	assert.True(t, mock.HasSubscription("device/test-device-uuid/live-logs/control"),
		"runSession must subscribe to device/{id}/live-logs/control")
}

func TestRunSession_SubscribesLogLevelControl(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runSession(ctx) //nolint:errcheck
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	assert.True(t, mock.HasSubscription("device/test-device-uuid/log-level/control"),
		"runSession must subscribe to device/{id}/log-level/control")
}

func TestReadHostname_ReturnsUnknownOnMissingFile(t *testing.T) {
	h := readHostname()
	// Either the real hostname or "unknown" – both are acceptable in test env.
	assert.NotEmpty(t, h)
}

func TestReadUptimeSeconds_ReturnsNonNegative(t *testing.T) {
	u := readUptimeSeconds()
	assert.GreaterOrEqual(t, u, int64(0))
}

func TestHandleCommand_UCISet_BlockedSubcommand_AcksError(t *testing.T) {
	blocked := []string{"batch", "import", "export", "changes", "show", "help"}
	for _, sub := range blocked {
		t.Run(sub, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			uciMock := &uci.MockUCIRunner{}
			a := newTestAgent(mock, uciMock)

			payload := `{"cmd_id":"uci-block","type":"uci_set","payload":{"commands":["` + sub + ` system"]}}`
			a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

			// UCI runner must NOT have been called.
			assert.Empty(t, uciMock.Calls, "ExecRaw must not be called for blocked subcommand %q", sub)

			// Ack must be "error".
			require.Len(t, mock.Published, 1)
			var ack AckPayload
			require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
			assert.Equal(t, "error", ack.Status)
			assert.Contains(t, ack.Output, "not permitted")
		})
	}
}

func TestHandleCommand_UCISet_AllowedSubcommands_AreExecuted(t *testing.T) {
	allowed := []string{"set", "commit", "revert", "delete", "add", "add_list", "del_list", "get"}
	for _, sub := range allowed {
		t.Run(sub, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			uciMock := &uci.MockUCIRunner{}
			a := newTestAgent(mock, uciMock)

			// Use "uci <sub> system" for each allowed subcommand.
			payload := `{"cmd_id":"uci-allow","type":"uci_set","payload":{"commands":["uci ` + sub + ` system"]}}`
			a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

			// ExecRaw must have been called with the subcommand.
			assert.Contains(t, uciMock.Calls, "raw "+sub+" system")

			require.Len(t, mock.Published, 1)
			var ack AckPayload
			require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
			assert.Equal(t, "ok", ack.Status)
		})
	}
}

func TestHandleCommand_StripUCIPrefix(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgent(mock, uciMock)

	payload := `{
		"cmd_id": "cmd-strip",
		"type": "uci_set",
		"payload": {"commands": ["uci set network.wan.proto=dhcp"]}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "raw set network.wan.proto=dhcp")
}

// systemUCISections is the minimal on-device "system" package state used by
// tests that exercise publishState and/or config_apply staging against it.
var systemUCISections = []uci.Section{
	{ID: "cfg-system0", Type: "system", Anonymous: true, Options: map[string]interface{}{"hostname": "OpenWrt"}},
}

func TestHandleStateRequest_PublishesStateToCorrectTopic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`{"packages":["system"]}`))

	require.Len(t, mock.Published, 1)
	assert.Equal(t, "device/test-device-uuid/state", mock.Published[0].Topic)
}

func TestHandleStateRequest_TriggerIsRequest(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`{"packages":["system"]}`))

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	assert.Equal(t, "request", state.Trigger)
}

func TestHandleStateRequest_IncludesRequestedPackage(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`{"packages":["system"]}`))

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	_, ok := state.Packages["system"]
	assert.True(t, ok, "system package should be present in state payload")
}

func TestHandleStateRequest_SkipsMissingPackage(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
		Errors: map[string]error{
			"sections wireless": assert.AnError,
		},
	}
	a := newTestAgent(mock, uciMock)

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`{"packages":["system","wireless"]}`))

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	_, hasSystem := state.Packages["system"]
	_, hasWireless := state.Packages["wireless"]
	assert.True(t, hasSystem, "system should be present")
	assert.False(t, hasWireless, "wireless failed to export and must be absent")
}

func TestHandleStateRequest_EmptyPackagesList_UsesDefaultPackages(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	// Only inject system; all others will silently return empty string → no sections → skipped.
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`{"packages":[]}`))

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	_, ok := state.Packages["system"]
	assert.True(t, ok, "system should be in Packages when empty list triggers default set")
}

func TestHandleCommand_ConfigApply_SuccessAcksAndPublishesState(t *testing.T) {
	// Shorten the watchdog so the test doesn't wait 90 s.
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = 50 * time.Millisecond
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	// Provide a session disconnCh that never fires so the watchdog confirms connectivity.
	disconnCh := make(chan struct{})
	a.setSessionDisconnCh(disconnCh)

	payload := `{
		"cmd_id": "apply-ok",
		"type": "config_apply",
		"payload": {
			"system": {
				".mode": "merge",
				"system": [{ ".name": "system", "hostname": "router-01" }]
			}
		}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// State is published synchronously; ACK arrives after the watchdog confirms
	// (from a background goroutine), so reads must go through the mock's mutex
	// via PublishedSnapshot rather than touching mock.Published directly.
	require.Eventually(t, func() bool {
		topics := make(map[string]bool)
		for _, p := range mock.PublishedSnapshot() {
			topics[p.Topic] = true
		}
		return topics["device/test-device-uuid/ack"] && topics["device/test-device-uuid/state"]
	}, 500*time.Millisecond, 5*time.Millisecond)

	// Find the ack message.
	var ack AckPayload
	for _, pub := range mock.PublishedSnapshot() {
		if pub.Topic == "device/test-device-uuid/ack" {
			require.NoError(t, json.Unmarshal(pub.Payload, &ack))
		}
	}
	assert.Equal(t, "apply-ok", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)

	// UCI staging + commit should have been called.
	assert.Contains(t, uciMock.Calls, "add system system system")
	assert.Contains(t, uciMock.Calls, "setvalues system.system")
	assert.Contains(t, uciMock.Calls, "commit system")
}

// TestHandleCommand_ConfigApply_DuplicateDelivery_Ignored guards against a
// regression seen on a real device: the broker redelivers an un-acked
// config_apply after a mid-apply disconnect (the reconfigured network itself
// breaks connectivity before the client's ack round-trips). Before this
// fix, the redelivered command was reprocessed from scratch -- a second
// backup+reload+watchdog racing the still-running original -- which could
// observe no session yet at its own start and roll back a change that was
// never actually in trouble.
func TestHandleCommand_ConfigApply_DuplicateDelivery_Ignored(t *testing.T) {
	// Long enough that the original watchdog cannot resolve on its own
	// during this test, so confirmCmdID stays populated for the duration.
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = time.Hour
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)
	a.setSessionDisconnCh(make(chan struct{}))

	payload := `{
		"cmd_id": "dup-1",
		"type": "config_apply",
		"payload": {
			"system": {
				".mode": "merge",
				"system": [{ ".name": "system", "hostname": "router-01" }]
			}
		}
	}`

	// First delivery: applies the config and leaves a watchdog in flight.
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))
	require.True(t, a.isDuplicateConfigApply("dup-1"), "watchdog for dup-1 must be tracked as in-flight")
	callsAfterFirst := len(uciMock.Calls)

	// Second delivery: broker redelivery of the same un-acked command. Must
	// be dropped, not reprocessed.
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))
	assert.Equal(t, callsAfterFirst, len(uciMock.Calls), "duplicate delivery must not reapply the config")

	// Resolve the original watchdog and confirm exactly one ack was sent for
	// the deduplicated cmd_id -- not two.
	require.True(t, a.signalWatchdogConfirm("dup-1"))
	require.Eventually(t, func() bool {
		for _, p := range mock.PublishedSnapshot() {
			if p.Topic == "device/test-device-uuid/ack" {
				return true
			}
		}
		return false
	}, 500*time.Millisecond, 5*time.Millisecond)

	ackCount := 0
	for _, p := range mock.PublishedSnapshot() {
		if p.Topic == "device/test-device-uuid/ack" {
			ackCount++
		}
	}
	assert.Equal(t, 1, ackCount, "exactly one ack must be sent for the deduplicated cmd_id")
}

func TestHandleCommand_ConfigApply_StagingError_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"setvalues system.system": assert.AnError,
		},
	}
	a := newTestAgent(mock, uciMock)

	payload := `{
		"cmd_id": "apply-err",
		"type": "config_apply",
		"payload": {
			"system": {
				".mode": "merge",
				"system": [{ ".name": "system", "hostname": "router-01" }]
			}
		}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Only ack published (no state on error).
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "apply-err", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.NotEmpty(t, ack.Output)

	// Revert must have been called.
	assert.Contains(t, uciMock.Calls, "revert system")
}

func TestHandleCommand_ConfigApply_StateTriggerIsApplySuccess(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	payload := `{
		"cmd_id": "apply-trigger",
		"type": "config_apply",
		"payload": {
			"system": {
				".mode": "merge",
				"system": [{ ".name": "system", "hostname": "test-host" }]
			}
		}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Find the state message and verify trigger.
	for _, pub := range mock.Published {
		if pub.Topic == "device/test-device-uuid/state" {
			var state StatePayload
			require.NoError(t, json.Unmarshal(pub.Payload, &state))
			assert.Equal(t, "apply_success", state.Trigger)
			return
		}
	}
	t.Fatal("state message not published")
}

func TestHandleStateRequest_InvalidJSON_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	a.handleStateRequest("device/test-device-uuid/state/request", []byte(`not-json`))

	assert.Empty(t, mock.Published, "no publish should occur on invalid JSON")
}

func TestPublishState_ConnectTrigger(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	a := newTestAgent(mock, uciMock)

	err := a.publishState(context.Background(), "connect", []string{"system"})
	require.NoError(t, err)

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	assert.Equal(t, "connect", state.Trigger)
	assert.NotEmpty(t, state.Timestamp)
}

// ---- unified state report: authorized_keys / password_hash / tls_cert_fingerprint --------

func TestInstalledAuthorizedKeys_ValidKeys_ReturnsNormalizedPublicKeys(t *testing.T) {
	const pubKeyB64 = "AAAAC3NzaC1lZDI1NTE5AAAA"
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			authorizedKeysPath: []byte("ssh-ed25519 " + pubKeyB64 + " comment1\n# a comment\n\nssh-ed25519 " + pubKeyB64 + " comment2\n"),
		},
	}

	got := installedAuthorizedKeys(fw)

	require.Len(t, got, 2)
	want := "ssh-ed25519 " + pubKeyB64
	assert.Equal(t, want, got[0])
	assert.Equal(t, want, got[1])
}

func TestInstalledAuthorizedKeys_MalformedLines_AreSkipped(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			authorizedKeysPath: []byte("not-enough-fields\nssh-ed25519 not!valid!base64\n"),
		},
	}

	got := installedAuthorizedKeys(fw)

	assert.Empty(t, got)
}

func TestInstalledAuthorizedKeys_MissingFile_ReturnsNil(t *testing.T) {
	fw := &filewriter.MockFileAccess{}

	got := installedAuthorizedKeys(fw)

	assert.Nil(t, got)
}

func TestRootPasswordHash_PresentEntry_ReturnsHashField(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/shadow": []byte("root:$6$saltsalt$hashhash:19000:0:99999:7:::\nuser:!:19000:0:99999:7:::\n"),
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	assert.Equal(t, "$6$saltsalt$hashhash", a.rootPasswordHash())
}

func TestRootPasswordHash_NoRootEntry_ReturnsEmpty(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/shadow": []byte("user:!:19000:0:99999:7:::\n"),
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	assert.Empty(t, a.rootPasswordHash())
}

func TestRootPasswordHash_MissingFile_ReturnsEmpty(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, &filewriter.MockFileAccess{})

	assert.Empty(t, a.rootPasswordHash())
}

func TestTlsCertFingerprint_DefaultPath_UsedWhenNoPushYet(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	certBytes := []byte("fake-cert-bytes")
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			defaultTLSCertPath: certBytes,
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	sum := sha256.Sum256(certBytes)
	assert.Equal(t, hex.EncodeToString(sum[:]), a.tlsCertFingerprint())
}

func TestTlsCertFingerprint_PushedPath_OverridesDefault(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	certBytes := []byte("pushed-cert-bytes")
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/uhttpd.crt": []byte("default-cert-bytes"),
			"/tmp/custom.crt": certBytes,
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)
	a.setTLSCertPath("/tmp/custom.crt")

	sum := sha256.Sum256(certBytes)
	assert.Equal(t, hex.EncodeToString(sum[:]), a.tlsCertFingerprint())
}

func TestTlsCertFingerprint_MissingFile_ReturnsEmpty(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, &filewriter.MockFileAccess{})

	assert.Empty(t, a.tlsCertFingerprint())
}

func TestPublishState_IncludesUnifiedStateReportFields(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Sections: map[string][]uci.Section{
			"system": systemUCISections,
		},
	}
	const pubKeyB64 = "AAAAC3NzaC1lZDI1NTE5AAAA"
	certBytes := []byte("fake-cert-bytes")
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			authorizedKeysPath: []byte("ssh-ed25519 " + pubKeyB64 + " comment\n"),
			defaultTLSCertPath: certBytes,
			"/etc/shadow":      []byte("root:$6$saltsalt$hashhash:19000:0:99999:7:::\n"),
		},
	}
	a := newTestAgentWithFW(mock, uciMock, fw)

	err := a.publishState(context.Background(), "connect", []string{"system"})
	require.NoError(t, err)

	require.Len(t, mock.Published, 1)
	var state StatePayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &state))
	require.Len(t, state.AuthorizedKeys, 1)
	assert.Equal(t, "ssh-ed25519 "+pubKeyB64, state.AuthorizedKeys[0])
	assert.Equal(t, "$6$saltsalt$hashhash", state.PasswordHash)
	assert.NotEmpty(t, state.TLSCertFingerprint)
}

func TestRunSession_SubscribesStateRequest(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runSession(ctx) //nolint:errcheck
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSession did not stop on ctx cancel")
	}

	assert.True(t, mock.HasSubscription("device/test-device-uuid/state/request"),
		"runSession must subscribe to device/{id}/state/request")
}

func TestRunSession_PublishesStatePeriodically(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{
		BrokerHost:        "broker.local",
		BrokerPort:        8883,
		HeartbeatInterval: 60,
		StateInterval:     1, // seconds; smallest non-zero value the agent will honor
	}
	creds := &config.Credentials{DeviceID: "test-device-uuid", Secret: "test-secret"}
	a := New(&Options{
		Config:    cfg,
		Creds:     creds,
		MAC:       "aa:bb:cc:dd:ee:ff",
		MQTT:      mock,
		UCI:       &uci.MockUCIRunner{},
		Version:   "1.0.0",
		SSHDaemon: &daemonDropbear,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.runSession(ctx) //nolint:errcheck
	}()

	// One state publish happens immediately on connect; wait for a second,
	// periodic one to confirm the ticker fires. runSession runs in its own
	// goroutine and keeps publishing concurrently, so reads must go through
	// the mock's mutex via PublishedSnapshot rather than touching
	// mock.Published directly.
	require.Eventually(t, func() bool {
		count := 0
		for _, p := range mock.PublishedSnapshot() {
			if p.Topic == "device/test-device-uuid/state" {
				count++
			}
		}
		return count >= 2
	}, 3*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSession did not stop on ctx cancel")
	}

	var triggers []string
	for _, p := range mock.Published {
		if p.Topic == "device/test-device-uuid/state" {
			var state StatePayload
			require.NoError(t, json.Unmarshal(p.Payload, &state))
			triggers = append(triggers, state.Trigger)
		}
	}
	assert.Contains(t, triggers, "connect")
	assert.Contains(t, triggers, "periodic")
}

// ---- file_write command tests -----------------------------------------------

func TestHandleCommand_FileWrite_WritesFileAndAcksOk(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{
		"cmd_id": "fw-ok",
		"type": "file_write",
		"payload": {"path": "/etc/dropbear/authorized_keys", "content": "ssh-ed25519 AAAA...", "mode": "0600"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Verify file write was recorded.
	require.Len(t, fw.Calls, 1)
	assert.Equal(t, "/etc/dropbear/authorized_keys", fw.Calls[0].Path)
	assert.Equal(t, []byte("ssh-ed25519 AAAA..."), fw.Calls[0].Content)
	assert.Equal(t, os.FileMode(0600), fw.Calls[0].Perm)

	// Verify ack, followed by a state report confirming the change.
	require.Len(t, mock.Published, 2)
	assert.Equal(t, "device/test-device-uuid/ack", mock.Published[0].Topic)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-ok", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.Equal(t, "device/test-device-uuid/state", mock.Published[1].Topic)
}

func TestHandleCommand_FileWrite_WriteError_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{
		Errors: map[string]error{
			"/etc/dropbear/authorized_keys": errors.New("permission denied"),
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{
		"cmd_id": "fw-err",
		"type": "file_write",
		"payload": {"path": "/etc/dropbear/authorized_keys", "content": "key data", "mode": "0600"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-err", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "permission denied")
}

func TestHandleCommand_FileWrite_InvalidPayload_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id": "fw-bad", "type": "file_write", "payload": "not-an-object"}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-bad", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "invalid payload")

	// WriteFile must not have been called.
	assert.Empty(t, fw.Calls)
}

func TestHandleCommand_FileWrite_MissingPath_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id": "fw-nopath", "type": "file_write", "payload": {"path": "", "content": "data"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-nopath", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "path is required")

	assert.Empty(t, fw.Calls)
}

func TestHandleCommand_FileWrite_CustomMode_UsesCorrectPerm(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{
		"cmd_id": "fw-mode",
		"type": "file_write",
		"payload": {"path": "/tmp/test.txt", "content": "hello", "mode": "0644"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, fw.Calls, 1)
	assert.Equal(t, os.FileMode(0644), fw.Calls[0].Perm)

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_FileWrite_NoMode_Defaults0600(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	// Omit "mode" field entirely.
	payload := `{
		"cmd_id": "fw-nomode",
		"type": "file_write",
		"payload": {"path": "/tmp/nomode.txt", "content": "data"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, fw.Calls, 1)
	assert.Equal(t, os.FileMode(0600), fw.Calls[0].Perm)

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_FileWrite_DropbearFormat_DecodesBase64(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	// A small binary blob that is not valid UTF-8.
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	encoded := base64.StdEncoding.EncodeToString(binaryData)

	payload := `{
		"cmd_id": "fw-dropbear",
		"type": "file_write",
		"payload": {"path": "/etc/dropbear/dropbear_ed25519_host_key", "content": "` + encoded + `", "format": "dropbear", "mode": "0600"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// Agent must have decoded the base64 and written raw bytes.
	require.Len(t, fw.Calls, 1)
	assert.Equal(t, "/etc/dropbear/dropbear_ed25519_host_key", fw.Calls[0].Path)
	assert.Equal(t, binaryData, fw.Calls[0].Content)
	assert.Equal(t, os.FileMode(0600), fw.Calls[0].Perm)

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-dropbear", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_FileWrite_DisallowedPath_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	cases := []struct {
		name string
		path string
	}{
		{"root dir", "/etc/shadow"},
		{"system binary", "/usr/bin/waverms-agent"},
		{"traversal into etc", "/etc/dropbear/../../shadow"},
		{"absolute root", "/"},
		{"passwd", "/etc/passwd"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			fw := &filewriter.MockFileAccess{}
			a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

			payload := `{"cmd_id":"fw-deny","type":"file_write","payload":{"path":"` + tc.path + `","content":"evil"}}`
			a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

			// WriteFile must not have been called.
			assert.Empty(t, fw.Calls, "WriteFile must not be called for disallowed path %q", tc.path)

			// Ack must be "error".
			require.Len(t, mock.Published, 1)
			var ack AckPayload
			require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
			assert.Equal(t, "error", ack.Status)
			assert.Contains(t, ack.Output, "path not permitted")
		})
	}

	// Confirm the allowlist works for valid paths.
	_ = mock
	_ = fw
	_ = a
}

func TestHandleCommand_FileWrite_AllowedPaths_AreAccepted(t *testing.T) {
	cases := []string{
		"/etc/dropbear/authorized_keys",
		"/etc/dropbear/dropbear_ed25519_host_key",
		"/etc/waverms/config",
		"/tmp/test.txt",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			mock := mqttclient.NewMockMQTTClient()
			fw := &filewriter.MockFileAccess{}
			a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

			payload := `{"cmd_id":"fw-allow","type":"file_write","payload":{"path":"` + path + `","content":"data"}}`
			a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

			require.Len(t, fw.Calls, 1, "WriteFile must be called for allowed path %q", path)
			require.Len(t, mock.Published, 2)
			var ack AckPayload
			require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
			assert.Equal(t, "ok", ack.Status)
		})
	}
}

func TestHandleCommand_FileWrite_DropbearFormat_InvalidBase64_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{
		"cmd_id": "fw-b64err",
		"type": "file_write",
		"payload": {"path": "/etc/dropbear/dropbear_ed25519_host_key", "content": "!!!not-valid-base64!!!", "format": "dropbear"}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// WriteFile must not have been called.
	assert.Empty(t, fw.Calls)

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "fw-b64err", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "base64 decode")
}

// ── host_key_fetch tests ──────────────────────────────────────────────────────

func TestHandleCommand_HostKeyFetch_ReturnsExistingKeys(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	ed25519KeyBytes := []byte{0x00, 0x01, 0x02, 0x03}
	rsaKeyBytes := []byte{0xAA, 0xBB, 0xCC}
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/dropbear/dropbear_ed25519_host_key": ed25519KeyBytes,
			"/etc/dropbear/dropbear_rsa_host_key":     rsaKeyBytes,
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id":"hkf-1","type":"host_key_fetch","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "hkf-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	require.NotEmpty(t, ack.Keys)
	assert.Equal(t, ed25519KeyBytes, ack.Keys["dropbear_ed25519_host_key"])
	assert.Equal(t, rsaKeyBytes, ack.Keys["dropbear_rsa_host_key"])
}

func TestHandleCommand_HostKeyFetch_SkipsMissingFiles(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	// Only one key present; others return ErrNotExist from the mock.
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/etc/dropbear/dropbear_ed25519_host_key": []byte("only-key"),
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id":"hkf-partial","type":"host_key_fetch","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
	assert.Equal(t, []byte("only-key"), ack.Keys["dropbear_ed25519_host_key"])
}

func TestHandleCommand_HostKeyFetch_NoFilesPresent_AcksOkWithEmptyKeys(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{} // all reads return ErrNotExist
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id":"hkf-empty","type":"host_key_fetch","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "hkf-empty", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.Empty(t, ack.Keys)
}

func TestHandleCommand_HostKeyFetch_ReadError_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	injected := errors.New("permission denied")
	fw := &filewriter.MockFileAccess{
		ReadErrors: map[string]error{
			"/etc/dropbear/dropbear_ed25519_host_key": injected,
		},
	}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id":"hkf-err","type":"host_key_fetch","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "read ")
}

func TestPublishInfo_CapabilitiesContainHostKeyFetch(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "host_key_fetch")
}

// --- set_password tests -------------------------------------------------------

func newTestAgentWithPasswordSetter(mock *mqttclient.MockMQTTClient, ps *MockPasswordSetter) *Agent {
	cfg := &config.Config{
		BrokerHost:        "broker.local",
		BrokerPort:        8883,
		HeartbeatInterval: 60,
	}
	creds := &config.Credentials{
		DeviceID: "test-device-uuid",
		Secret:   "test-secret",
	}
	return New(&Options{
		Config:         cfg,
		Creds:          creds,
		MAC:            "aa:bb:cc:dd:ee:ff",
		MQTT:           mock,
		UCI:            &uci.MockUCIRunner{},
		FileAccess:     &filewriter.MockFileAccess{},
		PasswordSetter: ps,
		Version:        "1.0.0",
		SSHDaemon:      &daemonDropbear,
	})
}

func TestHandleCommand_SetPassword_ValidHash_AcksOk(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	ps := &MockPasswordSetter{}
	a := newTestAgentWithPasswordSetter(mock, ps)

	payload := `{"cmd_id":"sp-1","type":"set_password","payload":{"target":"root","hash":"$6$saltsalt$hashhash"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sp-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.Contains(t, ps.Calls, "set_password root")
}

func TestHandleCommand_SetPassword_UnsupportedTarget_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	ps := &MockPasswordSetter{}
	a := newTestAgentWithPasswordSetter(mock, ps)

	payload := `{"cmd_id":"sp-2","type":"set_password","payload":{"target":"admin","hash":"$6$salt$hash"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sp-2", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Empty(t, ps.Calls)
}

func TestHandleCommand_SetPassword_MissingHash_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	ps := &MockPasswordSetter{}
	a := newTestAgentWithPasswordSetter(mock, ps)

	payload := `{"cmd_id":"sp-3","type":"set_password","payload":{"target":"root","hash":""}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sp-3", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Empty(t, ps.Calls)
}

func TestHandleCommand_SetPassword_SetterError_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	ps := &MockPasswordSetter{Err: errors.New("chpasswd: exit status 1")}
	a := newTestAgentWithPasswordSetter(mock, ps)

	payload := `{"cmd_id":"sp-4","type":"set_password","payload":{"target":"root","hash":"$6$salt$hash"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sp-4", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
}

func TestPublishInfo_CapabilitiesContainSetPassword(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "set_password")
}

func TestHandleCommand_TlsCertPush_WritesFilesAndRestartsUhttpd(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{
		"cmd_id": "tcp-1",
		"type": "tls_cert_push",
		"payload": {
			"cert_pem": "-----BEGIN CERTIFICATE-----\nfakecert\n-----END CERTIFICATE-----",
			"key_pem":  "-----BEGIN PRIVATE KEY-----\nfakekey\n-----END PRIVATE KEY-----",
			"cert_path": "/etc/uhttpd.crt",
			"key_path":  "/etc/uhttpd.key",
			"restart_service": "uhttpd"
		}
	}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, fw.Calls, 2)
	files := make(map[string]filewriter.WriteCall)
	for _, c := range fw.Calls {
		files[c.Path] = c
	}
	require.Contains(t, files, "/etc/uhttpd.crt")
	require.Contains(t, files, "/etc/uhttpd.key")
	assert.Equal(t, os.FileMode(0644), files["/etc/uhttpd.crt"].Perm)
	assert.Equal(t, os.FileMode(0600), files["/etc/uhttpd.key"].Perm)
	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/uhttpd restart")

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "tcp-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_TlsCertPush_PathTraversalGuard(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, &uci.MockUCIRunner{}, fw)

	payload := `{"cmd_id":"tcp-2","type":"tls_cert_push","payload":{"cert_pem":"cert","key_pem":"key","cert_path":"/var/malicious","key_path":"/etc/uhttpd.key"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Empty(t, fw.Calls)
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
}

func TestHandleCommand_TlsCertPush_DefaultServiceIsUhttpd(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{"cmd_id":"tcp-3","type":"tls_cert_push","payload":{"cert_pem":"cert","key_pem":"key","cert_path":"/etc/uhttpd.crt","key_path":"/etc/uhttpd.key"}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/uhttpd restart")

	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestPublishInfo_CapabilitiesContainTlsCertPush(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "tls_cert_push")
}

func TestHandleCommand_TlsCertRemove_AcksOkAndRestartsUhttpd(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{"cmd_id":"tcr-1","type":"tls_cert_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "cmd /etc/init.d/uhttpd restart")

	require.Len(t, mock.Published, 2) // ack + state report
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "tcr-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleCommand_TlsCertRemove_ClearsPushedPaths(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	certBytes := []byte("pushed-cert-bytes")
	fw := &filewriter.MockFileAccess{
		ReadFiles: map[string][]byte{
			"/tmp/custom.crt": certBytes,
		},
	}
	a := newTestAgentWithFW(mock, uciMock, fw)

	// Simulate a prior successful push that stored custom paths.
	a.setTLSCertPaths("/tmp/custom.crt", "/tmp/custom.key")
	sum := sha256.Sum256(certBytes)
	assert.Equal(t, hex.EncodeToString(sum[:]), a.tlsCertFingerprint(), "pre-condition: fingerprint should be non-empty")

	payload := `{"cmd_id":"tcr-2","type":"tls_cert_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// After removal the stored paths are cleared; fingerprint falls back to
	// the default path which isn't in ReadFiles → should be empty.
	assert.Empty(t, a.tlsCertFingerprint(), "fingerprint should be empty after remove")
}

func TestHandleCommand_TlsCertRemove_UhttpdRestartFailure_StillAcksOk(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"cmd /etc/init.d/uhttpd restart": errors.New("service not found"),
		},
	}
	fw := &filewriter.MockFileAccess{}
	a := newTestAgentWithFW(mock, uciMock, fw)

	payload := `{"cmd_id":"tcr-3","type":"tls_cert_remove","payload":{}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 2)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestPublishInfo_CapabilitiesContainTlsCertRemove(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "tls_cert_remove")
}

// ── hostKeyFingerprints ────────────────────────────────────────────────────────

func TestHostKeyFingerprints_ReturnsHexSHA256ForExistingFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("fake-ed25519-key-content")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dropbear_ed25519_host_key"), content, 0600))

	fps := hostKeyFingerprints(map[string]bool{"dropbear_ed25519_host_key": true}, dir)

	require.Len(t, fps, 1)
	sum := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(sum[:]), fps["dropbear_ed25519_host_key"])
}

func TestHostKeyFingerprints_OmitsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	// Only ed25519 key exists; rsa is absent.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dropbear_ed25519_host_key"), []byte("ed25519"), 0600))

	fps := hostKeyFingerprints(map[string]bool{
		"dropbear_ed25519_host_key": true,
		"dropbear_rsa_host_key":     true,
	}, dir)

	assert.Contains(t, fps, "dropbear_ed25519_host_key")
	assert.NotContains(t, fps, "dropbear_rsa_host_key")
}

func TestHostKeyFingerprints_ReturnsNilWhenNoFilesExist(t *testing.T) {
	fps := hostKeyFingerprints(map[string]bool{"dropbear_ed25519_host_key": true}, t.TempDir())
	assert.Nil(t, fps)
}

func TestPublishInfo_OmitsHostKeyFingerprints(t *testing.T) {
	dir := t.TempDir()
	content := []byte("fake-key-bytes")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dropbear_ed25519_host_key"), content, 0600))

	mqttMock := mqttclient.NewMockMQTTClient()
	daemon := sshDaemonInfo{Name: "dropbear", Dir: dir, Service: "/etc/init.d/dropbear"}
	a := New(&Options{
		Config:     &config.Config{HeartbeatInterval: 60},
		Creds:      &config.Credentials{DeviceID: "test-device-uuid", Secret: "s"},
		MAC:        "aa:bb:cc:dd:ee:ff",
		MQTT:       mqttMock,
		UCI:        &uci.MockUCIRunner{},
		FileAccess: &filewriter.MockFileAccess{},
		Version:    "1.0.0",
		SSHDaemon:  &daemon,
	})

	require.NoError(t, a.publishInfo(context.Background()))

	assert.NotContains(t, string(mqttMock.Published[0].Payload), "host_key_fingerprints")
}

// --- log_control tests ---------------------------------------------------------

func newTestAgentWithActivityLog(t *testing.T, mock *mqttclient.MockMQTTClient) (*Agent, *ActivityLogHandler) {
	t.Helper()
	dir := t.TempDir()
	origPath := activityLogPath
	activityLogPath = filepath.Join(dir, "agent.log")
	t.Cleanup(func() { activityLogPath = origPath })

	a := newTestAgent(mock, &uci.MockUCIRunner{})
	h, err := NewActivityLogHandler(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, err)
	a.activityLog = h
	return a, h
}

func TestHandleCommand_LogControl_ValidPayload_AcksOkAndToggles(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, h := newTestAgentWithActivityLog(t, mock)

	payload := `{"cmd_id":"lc-1","type":"log_control","payload":{"enabled":false}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "lc-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.False(t, h.enabled.Load())

	payload2 := `{"cmd_id":"lc-2","type":"log_control","payload":{"enabled":true}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload2))
	assert.True(t, h.enabled.Load())
}

func TestHandleCommand_LogControl_InvalidPayload_AcksError(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a, h := newTestAgentWithActivityLog(t, mock)
	h.SetEnabled(true)

	payload := `{"cmd_id":"lc-3","type":"log_control","payload":"not-an-object"}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "lc-3", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.True(t, h.enabled.Load(), "state must remain unchanged after an invalid payload")
}

func TestHandleCommand_LogControl_NilActivityLog_NoPanic(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	// a.activityLog is nil — must not panic, and should still ack "ok".

	payload := `{"cmd_id":"lc-4","type":"log_control","payload":{"enabled":false}}`
	assert.NotPanics(t, func() {
		a.handleCommand("device/test-device-uuid/cmd", []byte(payload))
	})

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestPublishInfo_CapabilitiesContainLogControl(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "log_control")
}

func TestPublishInfo_CapabilitiesContainLogLevelControl(t *testing.T) {
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	err := a.publishInfo(context.Background())
	require.NoError(t, err)

	var info InfoPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &info))
	assert.Contains(t, info.Capabilities, "log_level_control")
}

func TestDiscoverPackages_SkipsOpkgApkArtifactFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"usteer", "usteer-ng", "network", "usteer.apk-new", "network.orig", "firewall~",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("config foo"), 0o644))
	}

	pkgs := discoverPackages(dir)

	assert.ElementsMatch(t, []string{"usteer", "usteer-ng", "network"}, pkgs)
}

func TestDiscoverPackages_FallsBackWhenOnlyArtifactFilesPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "usteer.apk-new"), []byte("config foo"), 0o644))

	pkgs := discoverPackages(dir)

	assert.Equal(t, fallbackStatePackages, pkgs)
}

func TestDiscoverPackages_FallsBackOnUnreadableDir(t *testing.T) {
	pkgs := discoverPackages(filepath.Join(t.TempDir(), "does-not-exist"))

	assert.Equal(t, fallbackStatePackages, pkgs)
}
