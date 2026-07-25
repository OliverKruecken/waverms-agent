package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/config"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTokenFile(t *testing.T, dir, token string) string {
	t.Helper()
	path := filepath.Join(dir, "bootstrap_token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0600))
	return path
}

func TestRun_Success(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "test-token-abc")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "broker.local", BrokerPort: 8883}
	opts := Options{
		TokenPath:      tokenPath,
		CredsPath:      credsPath,
		TmpID:          "fixed-tmp-id",
		MAC:            "aa:bb:cc:dd:ee:ff",
		AgentVersion:   "1.0.0",
		Model:          "test-model",
		OpenWrtVersion: "23.05",
	}

	// We need to deliver the response after subscribe but before timeout.
	// Run bootstrap in a goroutine; simulate the server response via SimulateMessage.
	respCh := make(chan *BootstrapResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		resp, err := Run(context.Background(), cfg, opts, mock)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	// Give the goroutine time to register its subscription.
	time.Sleep(20 * time.Millisecond)

	// Deliver the server response.
	serverResp := BootstrapResponse{
		DeviceID:   "device-uuid-456",
		Secret:     "supersecret",
		BrokerHost: "broker.prod",
		BrokerPort: 8884,
	}
	payload, _ := json.Marshal(serverResp)
	mock.SimulateMessage("bootstrap/fixed-tmp-id/response", payload)

	select {
	case resp := <-respCh:
		require.NotNil(t, resp)
		assert.Equal(t, "device-uuid-456", resp.DeviceID)
		assert.Equal(t, "supersecret", resp.Secret)
		assert.Equal(t, "broker.prod", resp.BrokerHost)
		assert.Equal(t, 8884, resp.BrokerPort)
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("test timed out waiting for bootstrap response")
	}

	// Verify that bootstrap/register was published with correct payload.
	require.Len(t, mock.Published, 1)
	assert.Equal(t, "bootstrap/register", mock.Published[0].Topic)

	var req BootstrapRequest
	require.NoError(t, json.Unmarshal(mock.Published[0].Payload, &req))
	assert.Equal(t, "fixed-tmp-id", req.TmpID)
	assert.Equal(t, "test-token-abc", req.BootstrapToken)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", req.HwInfo.MAC)
	assert.Equal(t, "1.0.0", req.HwInfo.AgentVersion)
}

func TestRun_SavesCredentials(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "tok")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "b", BrokerPort: 1883}
	opts := Options{
		TokenPath: tokenPath,
		CredsPath: credsPath,
		TmpID:     "tid",
	}

	respCh := make(chan *BootstrapResponse, 1)
	go func() {
		resp, err := Run(context.Background(), cfg, opts, mock)
		if err == nil {
			respCh <- resp
		}
	}()

	time.Sleep(20 * time.Millisecond)
	serverResp, _ := json.Marshal(BootstrapResponse{DeviceID: "d1", Secret: "s1"})
	mock.SimulateMessage("bootstrap/tid/response", serverResp)

	select {
	case <-respCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}

	creds, err := config.LoadCredentials(credsPath)
	require.NoError(t, err)
	assert.Equal(t, "d1", creds.DeviceID)
	assert.Equal(t, "s1", creds.Secret)
}

func TestRun_DeletesBootstrapToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "tok")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "b", BrokerPort: 1883}
	opts := Options{TokenPath: tokenPath, CredsPath: credsPath, TmpID: "tid"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(context.Background(), cfg, opts, mock) //nolint:errcheck
	}()

	time.Sleep(20 * time.Millisecond)
	payload, _ := json.Marshal(BootstrapResponse{DeviceID: "d", Secret: "s"})
	mock.SimulateMessage("bootstrap/tid/response", payload)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}

	_, err := os.Stat(tokenPath)
	assert.True(t, os.IsNotExist(err), "bootstrap_token should have been deleted")
}

func TestRun_Timeout(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "tok")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "b", BrokerPort: 1883}
	opts := Options{TokenPath: tokenPath, CredsPath: credsPath, TmpID: "tid"}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := Run(ctx, cfg, opts, mock)
	require.Error(t, err)
	// Accept either context cancellation or bootstrap timeout messages.
	assert.True(t,
		err == context.DeadlineExceeded ||
			err.Error() == "bootstrap timeout after 30s" ||
			err.Error() == "context deadline exceeded",
		"unexpected error: %v", err)
}

func TestRun_ConnectUsesBootstrapCredentials(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "secret-token")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "mqtt.example.com", BrokerPort: 8883}
	opts := Options{TokenPath: tokenPath, CredsPath: credsPath, TmpID: "t1"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(context.Background(), cfg, opts, mock) //nolint:errcheck
	}()

	time.Sleep(20 * time.Millisecond)
	payload, _ := json.Marshal(BootstrapResponse{DeviceID: "d", Secret: "s"})
	mock.SimulateMessage("bootstrap/t1/response", payload)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}

	require.Len(t, mock.ConnectOpts, 1)
	assert.Equal(t, "bootstrap", mock.ConnectOpts[0].Username)
	assert.Equal(t, "secret-token", mock.ConnectOpts[0].Password)
	assert.Equal(t, "mqtt.example.com", mock.ConnectOpts[0].BrokerHost)
	assert.Equal(t, 8883, mock.ConnectOpts[0].BrokerPort)
	assert.Equal(t, "bootstrap-t1", mock.ConnectOpts[0].ClientID)
}

func TestRun_SubscribesBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	tokenPath := setupTokenFile(t, dir, "tok")
	credsPath := filepath.Join(dir, "credentials")

	mock := mqttclient.NewMockMQTTClient()
	cfg := &config.Config{BrokerHost: "b", BrokerPort: 1883}
	opts := Options{TokenPath: tokenPath, CredsPath: credsPath, TmpID: "t1"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(context.Background(), cfg, opts, mock) //nolint:errcheck
	}()

	time.Sleep(20 * time.Millisecond)

	// The response topic must be registered before the register is published.
	assert.True(t, mock.HasSubscription("bootstrap/t1/response"), "response topic should be subscribed before publish")

	payload, _ := json.Marshal(BootstrapResponse{DeviceID: "d", Secret: "s"})
	mock.SimulateMessage("bootstrap/t1/response", payload)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}
