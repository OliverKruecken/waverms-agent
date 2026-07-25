package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/config"
	"github.com/OliverKruecken/waverms-agent/internal/filewriter"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAgentWithInitd creates an agent with a custom initd directory for service_apply tests.
func newTestAgentWithInitd(mock *mqttclient.MockMQTTClient, uciMock *uci.MockUCIRunner, initdDir string) *Agent {
	cfg := &config.Config{BrokerHost: "broker.local", BrokerPort: 8883, HeartbeatInterval: 60}
	creds := &config.Credentials{DeviceID: "test-device-uuid", Secret: "test-secret"}
	return New(&Options{
		Config:     cfg,
		Creds:      creds,
		MAC:        "aa:bb:cc:dd:ee:ff",
		MQTT:       mock,
		UCI:        uciMock,
		FileAccess: &filewriter.MockFileAccess{},
		Version:    "1.0.0",
		SSHDaemon:  &daemonDropbear,
		InitdDir:   initdDir,
	})
}

func makeInitdDir(t *testing.T, services []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range services {
		f, err := os.Create(filepath.Join(dir, name))
		require.NoError(t, err)
		f.Close()
	}
	return dir
}

func TestHandleServiceApply_EnablesAndStartsService(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"sshd", "uhttpd"})
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	payload := `{"cmd_id":"sa-1","type":"service_apply","payload":{"services":{"sshd":true}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "cmd "+initdDir+"/sshd enable")
	assert.Contains(t, uciMock.Calls, "cmd "+initdDir+"/sshd start")

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sa-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleServiceApply_DisablesAndStopsService(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"uhttpd"})
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	payload := `{"cmd_id":"sa-2","type":"service_apply","payload":{"services":{"uhttpd":false}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	assert.Contains(t, uciMock.Calls, "cmd "+initdDir+"/uhttpd stop")
	assert.Contains(t, uciMock.Calls, "cmd "+initdDir+"/uhttpd disable")

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleServiceApply_SkipsUnknownService(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"sshd"})
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	// "missing" does not exist in initdDir
	payload := `{"cmd_id":"sa-3","type":"service_apply","payload":{"services":{"missing":true}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "sa-3", ack.CmdID)
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "not found")
}

func TestHandleServiceApply_RejectsInvalidServiceName(t *testing.T) {
	initdDir := makeInitdDir(t, []string{})
	mock := mqttclient.NewMockMQTTClient()
	uciMock := &uci.MockUCIRunner{}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	payload := `{"cmd_id":"sa-4","type":"service_apply","payload":{"services":{"../evil":true}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// No ExecCmd calls should be made for invalid names
	assert.Empty(t, uciMock.Calls)

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "invalid name")
}

func TestHandleServiceApply_EnableFailure_AcksError(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"sshd"})
	mock := mqttclient.NewMockMQTTClient()
	script := initdDir + "/sshd"
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"cmd " + script + " enable": errors.New("permission denied"),
		},
	}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	payload := `{"cmd_id":"sa-5","type":"service_apply","payload":{"services":{"sshd":true}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "enable")
}

func TestHandleServiceApply_StopFailure_ContinuesToDisable(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"uhttpd"})
	mock := mqttclient.NewMockMQTTClient()
	script := initdDir + "/uhttpd"
	uciMock := &uci.MockUCIRunner{
		Errors: map[string]error{
			"cmd " + script + " stop": errors.New("already stopped"),
		},
	}
	a := newTestAgentWithInitd(mock, uciMock, initdDir)

	payload := `{"cmd_id":"sa-6","type":"service_apply","payload":{"services":{"uhttpd":false}}}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	// stop failure is best-effort; disable must still be called
	assert.Contains(t, uciMock.Calls, "cmd "+script+" disable")

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "ok", ack.Status)
}

func TestHandleServiceApply_InvalidJSON_AcksError(t *testing.T) {
	initdDir := makeInitdDir(t, []string{})
	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgentWithInitd(mock, &uci.MockUCIRunner{}, initdDir)

	payload := `{"cmd_id":"sa-7","type":"service_apply","payload":"not-an-object"}`
	a.handleCommand("device/test-device-uuid/cmd", []byte(payload))

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "error", ack.Status)
	assert.Contains(t, ack.Output, "invalid payload")
}

// ── discoverServices ─────────────────────────────────────────────────────────

func TestDiscoverServices_ReturnsEnabledAndRunningState(t *testing.T) {
	initdDir := makeInitdDir(t, []string{"sshd", "uhttpd"})
	uciMock := &uci.MockUCIRunner{
		// sshd: enabled (exit 0) + running (exit 0) → both true
		// uhttpd: disabled (non-zero) + not running (non-zero) → both false
		Errors: map[string]error{
			"cmd " + initdDir + "/uhttpd enabled": errors.New("disabled"),
			"cmd " + initdDir + "/uhttpd running": errors.New("not running"),
		},
	}

	services := discoverServices(uciMock, initdDir)

	byName := make(map[string]ServiceInfo)
	for _, s := range services {
		byName[s.Name] = s
	}

	require.Contains(t, byName, "sshd")
	assert.True(t, byName["sshd"].Enabled)
	assert.True(t, byName["sshd"].Running)

	require.Contains(t, byName, "uhttpd")
	assert.False(t, byName["uhttpd"].Enabled)
	assert.False(t, byName["uhttpd"].Running)
}

func TestDiscoverServices_SkipsInvalidNames(t *testing.T) {
	initdDir := t.TempDir()
	// Create a file with an invalid name (contains slash is not possible in filenames,
	// so use a dot-prefixed hidden file which won't match [a-zA-Z0-9_-]+)
	f, err := os.Create(filepath.Join(initdDir, ".hidden"))
	require.NoError(t, err)
	f.Close()

	services := discoverServices(&uci.MockUCIRunner{}, initdDir)
	for _, s := range services {
		assert.NotEqual(t, ".hidden", s.Name)
	}
}

func TestDiscoverServices_EmptyDir_ReturnsNil(t *testing.T) {
	initdDir := t.TempDir()
	services := discoverServices(&uci.MockUCIRunner{}, initdDir)
	assert.Nil(t, services)
}
