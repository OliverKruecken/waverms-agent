package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackupAndRestore verifies that backupConfigFiles captures the current
// file contents and restore() writes them back correctly.
func TestBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	orig := uciConfigDir
	uciConfigDir = dir
	t.Cleanup(func() { uciConfigDir = orig })

	// Write initial config files.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network"), []byte("original network"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system"), []byte("original system"), 0644))

	backup, err := backupConfigFiles([]string{"network", "system", "nonexistent"})
	require.NoError(t, err)
	assert.Equal(t, []byte("original network"), backup.data["network"])
	assert.Equal(t, []byte("original system"), backup.data["system"])
	assert.Nil(t, backup.data["nonexistent"])

	// Simulate a bad apply: overwrite config files.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network"), []byte("broken network"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "system"), []byte("broken system"), 0644))

	require.NoError(t, backup.restore([]string{"network", "system"}))

	gotNetwork, _ := os.ReadFile(filepath.Join(dir, "network"))
	gotSystem, _ := os.ReadFile(filepath.Join(dir, "system"))
	assert.Equal(t, "original network", string(gotNetwork))
	assert.Equal(t, "original system", string(gotSystem))
}

// TestBackupRestore_NewPackageIsRemoved verifies that a package that did not
// exist before the apply is removed when rolling back.
func TestBackupRestore_NewPackageIsRemoved(t *testing.T) {
	dir := t.TempDir()
	orig := uciConfigDir
	uciConfigDir = dir
	t.Cleanup(func() { uciConfigDir = orig })

	// "vpn" does not exist before the apply.
	backup, err := backupConfigFiles([]string{"vpn"})
	require.NoError(t, err)
	assert.Nil(t, backup.data["vpn"])

	// Apply creates the file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vpn"), []byte("vpn config"), 0644))

	require.NoError(t, backup.restore([]string{"vpn"}))

	_, err = os.Stat(filepath.Join(dir, "vpn"))
	assert.True(t, os.IsNotExist(err), "vpn config should have been removed by rollback")
}

// TestWatchdog_Confirmed verifies that when the MQTT connection stays up for
// the full watchdog window, the agent sends ACK "ok" and does not set a pending ack.
func TestWatchdog_Confirmed(t *testing.T) {
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = 50 * time.Millisecond
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	origDir := uciConfigDir
	uciConfigDir = t.TempDir()
	t.Cleanup(func() { uciConfigDir = origDir })

	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	// Simulate an active session so getSessionDisconnCh() returns non-nil when the timer fires.
	activeCh := make(chan struct{}) // never closed — session stays up
	a.setSessionDisconnCh(activeCh)

	disconnCh := make(chan struct{}) // never closed → no disconnect during watchdog
	confirmCh := make(chan struct{}) // never closed → no server confirm
	backup := configBackup{data: map[string][]byte{}}

	a.runConnectivityWatchdog("cmd-1", backup, nil, disconnCh, confirmCh)

	// ACK "ok" must have been published.
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-1", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)

	// No pending rollback ACK.
	assert.Nil(t, a.takePendingRollbackAck())
}

// TestWatchdog_ConfirmedByServer verifies that closing confirmCh cuts the watchdog
// short and publishes ACK "ok" without waiting for the full timeout.
func TestWatchdog_ConfirmedByServer(t *testing.T) {
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = 10 * time.Second // long — we close confirmCh first
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	origDir := uciConfigDir
	uciConfigDir = t.TempDir()
	t.Cleanup(func() { uciConfigDir = origDir })

	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	disconnCh := make(chan struct{}) // never closed
	confirmCh := make(chan struct{})
	backup := configBackup{data: map[string][]byte{}}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.runConnectivityWatchdog("cmd-confirm", backup, nil, disconnCh, confirmCh)
	}()

	close(confirmCh)
	wg.Wait()

	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-confirm", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)
	assert.Nil(t, a.takePendingRollbackAck())
}

// TestWatchdog_Rollback verifies that when the MQTT connection drops and the device
// does NOT reconnect before the watchdog timer fires, the agent rolls back the config
// and queues a deferred ACK error. (disconnCh fires, no new session → timer → rollback)
func TestWatchdog_Rollback(t *testing.T) {
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = 50 * time.Millisecond // short so test doesn't stall
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	dir := t.TempDir()
	origDir := uciConfigDir
	uciConfigDir = dir
	t.Cleanup(func() { uciConfigDir = origDir })

	// Write "good" and "bad" versions of the network config.
	goodConfig := []byte("good network config")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network"), goodConfig, 0644))
	backup, err := backupConfigFiles([]string{"network"})
	require.NoError(t, err)

	// Simulate a bad apply.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network"), []byte("bad network config"), 0644))

	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})
	// sessionDisconnCh is nil (no active session) — rollback should happen when timer fires.

	disconnCh := make(chan struct{})
	noConfirm := make(chan struct{}) // never closed — server never sends config_confirm in this test

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.runConnectivityWatchdog("cmd-2", backup, []string{"network"}, disconnCh, noConfirm)
	}()

	// Simulate connection drop; the device does not reconnect (sessionDisconnCh stays nil).
	close(disconnCh)
	wg.Wait()

	// Config must be restored.
	restored, err := os.ReadFile(filepath.Join(dir, "network"))
	require.NoError(t, err)
	assert.Equal(t, string(goodConfig), string(restored))

	// Pending rollback ACK must be queued.
	ack := a.takePendingRollbackAck()
	require.NotNil(t, ack)
	assert.Equal(t, "cmd-2", ack.cmdID)
	assert.Equal(t, "error", ack.status)
	assert.Contains(t, ack.output, "rolled back")

	// No MQTT publish yet (ACK is deferred until reconnect).
	assert.Empty(t, mock.Published)
}

// TestWatchdog_DisconnectThenReconnect verifies that when the session drops after
// a config_apply but the device reconnects before the watchdog timer fires, the
// agent auto-confirms (sends ACK "ok") instead of rolling back.
func TestWatchdog_DisconnectThenReconnect(t *testing.T) {
	origTimeout := connectivityWatchdogTimeout
	connectivityWatchdogTimeout = 100 * time.Millisecond
	t.Cleanup(func() { connectivityWatchdogTimeout = origTimeout })

	dir := t.TempDir()
	origDir := uciConfigDir
	uciConfigDir = dir
	t.Cleanup(func() { uciConfigDir = origDir })

	goodConfig := []byte("good network config")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "network"), goodConfig, 0644))
	backup, err := backupConfigFiles([]string{"network"})
	require.NoError(t, err)

	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	// Simulate reconnect: give the agent an active session disconnect channel so
	// getSessionDisconnCh() returns non-nil when the timer fires.
	reconnectedCh := make(chan struct{}) // never closed — new session is alive
	a.setSessionDisconnCh(reconnectedCh)

	disconnCh := make(chan struct{})
	noConfirm := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.runConnectivityWatchdog("cmd-reconnect", backup, []string{"network"}, disconnCh, noConfirm)
	}()

	// Simulate the brief disconnect caused by network interface restart.
	close(disconnCh)
	wg.Wait()

	// Config must NOT be rolled back.
	current, err := os.ReadFile(filepath.Join(dir, "network"))
	require.NoError(t, err)
	assert.Equal(t, string(goodConfig), string(current))

	// ACK "ok" must have been published (auto-confirm).
	require.Len(t, mock.Published, 1)
	var ack AckPayload
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &ack))
	assert.Equal(t, "cmd-reconnect", ack.CmdID)
	assert.Equal(t, "ok", ack.Status)

	// No pending rollback ACK.
	assert.Nil(t, a.takePendingRollbackAck())
}

// TestWatchdog_NilDisconnCh verifies that a nil disconnCh (session gone) causes
// an immediate rollback without panicking.
func TestWatchdog_NilDisconnCh(t *testing.T) {
	dir := t.TempDir()
	origDir := uciConfigDir
	uciConfigDir = dir
	t.Cleanup(func() { uciConfigDir = origDir })

	mock := mqttclient.NewMockMQTTClient()
	a := newTestAgent(mock, &uci.MockUCIRunner{})

	backup := configBackup{data: map[string][]byte{}}
	a.runConnectivityWatchdog("cmd-3", backup, nil, nil, nil)

	ack := a.takePendingRollbackAck()
	require.NotNil(t, ack)
	assert.Equal(t, "error", ack.status)
}

// TestPendingAckHelpers verifies the set/take helpers are race-free.
func TestPendingAckHelpers(t *testing.T) {
	a := &Agent{}

	assert.Nil(t, a.takePendingRollbackAck())

	a.setPendingRollbackAck(&rollbackAck{cmdID: "x", status: "error", output: "msg"})
	got := a.takePendingRollbackAck()
	require.NotNil(t, got)
	assert.Equal(t, "x", got.cmdID)

	// Second take returns nil (consumed).
	assert.Nil(t, a.takePendingRollbackAck())
}
