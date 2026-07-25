package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_AllKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := `# WaveRMS config
BROKER_HOST=waverms.example.com
BROKER_PORT=8883
TLS_INSECURE=true
HEARTBEAT_INTERVAL=30
STATE_INTERVAL=120
AGENT_VERSION=2.0.0
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "waverms.example.com", cfg.BrokerHost)
	assert.Equal(t, 8883, cfg.BrokerPort)
	assert.True(t, cfg.TLSInsecure)
	assert.Equal(t, 30, cfg.HeartbeatInterval)
	assert.Equal(t, 120, cfg.StateInterval)
	assert.Equal(t, "2.0.0", cfg.AgentVersion)
}

func TestLoad_Defaults_OnMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config")
	require.NoError(t, err)

	assert.Equal(t, defaultBrokerPort, cfg.BrokerPort)
	assert.Equal(t, defaultHeartbeatInterval, cfg.HeartbeatInterval)
	assert.Equal(t, defaultStateInterval, cfg.StateInterval)
	assert.False(t, cfg.TLSInsecure)
}

func TestLoad_Defaults_OnMissingKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("BROKER_HOST=srv\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "srv", cfg.BrokerHost)
	assert.Equal(t, defaultBrokerPort, cfg.BrokerPort)
	assert.Equal(t, defaultHeartbeatInterval, cfg.HeartbeatInterval)
	assert.Equal(t, defaultStateInterval, cfg.StateInterval)
}

func TestLoad_InvalidPort_IgnoredUsesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("BROKER_PORT=notanumber\n"), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, defaultBrokerPort, cfg.BrokerPort)
}

func TestLoad_CommentsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := `# full line comment
BROKER_HOST=mqtt.local # inline comment
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, "mqtt.local", cfg.BrokerHost)
}

func TestLoad_EmptyFile_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte(""), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, defaultBrokerPort, cfg.BrokerPort)
}

func TestReadBootstrapToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap_token")
	require.NoError(t, os.WriteFile(path, []byte("mytoken\n"), 0600))

	token, err := ReadBootstrapToken(path)
	require.NoError(t, err)
	assert.Equal(t, "mytoken", token)
}

func TestReadBootstrapToken_MissingFile(t *testing.T) {
	_, err := ReadBootstrapToken("/nonexistent/bootstrap_token")
	assert.Error(t, err)
}

func TestWaitForBootstrapToken_ZeroTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap_token")
	require.NoError(t, os.WriteFile(path, []byte("mytoken\n"), 0600))

	tok, err := WaitForBootstrapToken(path, 0)
	require.NoError(t, err)
	assert.Equal(t, "mytoken", tok)
}

func TestWaitForBootstrapToken_ZeroTimeout_Missing(t *testing.T) {
	_, err := WaitForBootstrapToken("/nonexistent/bootstrap_token", 0)
	assert.Error(t, err)
}

func TestWaitForBootstrapToken_FileAppearsAfterDelay(t *testing.T) {
	orig := bootstrapTokenPollInterval
	bootstrapTokenPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { bootstrapTokenPollInterval = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap_token")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte("dhcp-token\n"), 0600)
	}()

	tok, err := WaitForBootstrapToken(path, 500*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "dhcp-token", tok)
}

func TestWaitForBootstrapToken_Timeout(t *testing.T) {
	orig := bootstrapTokenPollInterval
	bootstrapTokenPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { bootstrapTokenPollInterval = orig })

	_, err := WaitForBootstrapToken("/nonexistent/bootstrap_token", 30*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap token not found")
}

func TestLoadWithOverlay_DHCPWins(t *testing.T) {
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "config")
	dhcpPath := filepath.Join(dir, "dhcp")
	require.NoError(t, os.WriteFile(staticPath, []byte("BROKER_HOST=static.host\nBROKER_PORT=8883\n"), 0644))
	require.NoError(t, os.WriteFile(dhcpPath, []byte("BROKER_HOST=dhcp.host\nBROKER_PORT=1234\n"), 0644))

	cfg, err := LoadWithOverlay(staticPath, dhcpPath)
	require.NoError(t, err)
	assert.Equal(t, "dhcp.host", cfg.BrokerHost)
	assert.Equal(t, 1234, cfg.BrokerPort)
}

func TestLoadWithOverlay_NoDHCPFile(t *testing.T) {
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(staticPath, []byte("BROKER_HOST=static.host\nBROKER_PORT=9999\n"), 0644))

	cfg, err := LoadWithOverlay(staticPath, filepath.Join(dir, "dhcp"))
	require.NoError(t, err)
	assert.Equal(t, "static.host", cfg.BrokerHost)
	assert.Equal(t, 9999, cfg.BrokerPort)
}

func TestLoadWithOverlay_PartialDHCP(t *testing.T) {
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "config")
	dhcpPath := filepath.Join(dir, "dhcp")
	require.NoError(t, os.WriteFile(staticPath, []byte("BROKER_HOST=static.host\nBROKER_PORT=8883\n"), 0644))
	require.NoError(t, os.WriteFile(dhcpPath, []byte("BROKER_HOST=dhcp.host\n"), 0644))

	cfg, err := LoadWithOverlay(staticPath, dhcpPath)
	require.NoError(t, err)
	assert.Equal(t, "dhcp.host", cfg.BrokerHost)
	assert.Equal(t, 8883, cfg.BrokerPort) // port still from static
}

func TestWaitForBrokerHost_ImmediateStatic(t *testing.T) {
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(staticPath, []byte("BROKER_HOST=static.host\n"), 0644))

	cfg, err := WaitForBrokerHost(staticPath, filepath.Join(dir, "dhcp"), 100*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "static.host", cfg.BrokerHost)
}

func TestWaitForBrokerHost_FileAppearsAfterDelay(t *testing.T) {
	orig := brokerHostPollInterval
	brokerHostPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { brokerHostPollInterval = orig })

	dir := t.TempDir()
	dhcpPath := filepath.Join(dir, "dhcp")

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(dhcpPath, []byte("BROKER_HOST=dhcp.host\n"), 0600)
	}()

	cfg, err := WaitForBrokerHost(filepath.Join(dir, "config"), dhcpPath, 500*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "dhcp.host", cfg.BrokerHost)
}

func TestWaitForBrokerHost_Timeout(t *testing.T) {
	orig := brokerHostPollInterval
	brokerHostPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { brokerHostPollInterval = orig })

	dir := t.TempDir()
	_, err := WaitForBrokerHost(filepath.Join(dir, "config"), filepath.Join(dir, "dhcp"), 30*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BROKER_HOST not available")
}

func TestWaitForBrokerHost_ZeroTimeout_Missing(t *testing.T) {
	dir := t.TempDir()
	_, err := WaitForBrokerHost(filepath.Join(dir, "config"), filepath.Join(dir, "dhcp"), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BROKER_HOST is not set")
}

func TestWaitForBootstrapToken_EmptyFileWaitsForContent(t *testing.T) {
	orig := bootstrapTokenPollInterval
	bootstrapTokenPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { bootstrapTokenPollInterval = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap_token")
	// Create empty file first; real content arrives later.
	require.NoError(t, os.WriteFile(path, []byte(""), 0600))

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(path, []byte("real-token\n"), 0600)
	}()

	tok, err := WaitForBootstrapToken(path, 500*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "real-token", tok)
}
