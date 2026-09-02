// Package config handles reading and writing agent configuration files.
// Config files use a simple key=value format, one per line, with # for comments.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the runtime configuration for the agent.
type Config struct {
	BrokerHost        string
	BrokerPort        int
	TLSInsecure       bool
	HeartbeatInterval int
	StateInterval     int
	AgentVersion      string
	Debug             bool
}

const (
	defaultBrokerPort        = 8883
	defaultHeartbeatInterval = 60
	defaultStateInterval     = 600
)

// applyConfigKey maps a single key=value pair from a config file onto the
// matching Config field. Unknown keys are ignored.
func applyConfigKey(cfg *Config, key, value string) {
	switch key {
	case "BROKER_HOST":
		cfg.BrokerHost = value
	case "BROKER_PORT":
		if p, err := strconv.Atoi(value); err == nil {
			cfg.BrokerPort = p
		}
	case "TLS_INSECURE":
		cfg.TLSInsecure = strings.EqualFold(value, "true")
	case "HEARTBEAT_INTERVAL":
		if v, err := strconv.Atoi(value); err == nil {
			cfg.HeartbeatInterval = v
		}
	case "STATE_INTERVAL":
		if v, err := strconv.Atoi(value); err == nil {
			cfg.StateInterval = v
		}
	case "AGENT_VERSION":
		cfg.AgentVersion = value
	case "DEBUG":
		cfg.Debug = strings.EqualFold(value, "true")
	}
}

// scanKeyValueFile opens path and calls fn(key, value) for each key=value
// line, skipping blank lines and full-line comments (#). A missing file is
// not an error — fn is simply never called. When stripInlineComments is
// true, a trailing " #..." on the value is removed before fn is called.
func scanKeyValueFile(path string, stripInlineComments bool, fn func(key, value string)) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if stripInlineComments {
			if idx := strings.Index(value, " #"); idx >= 0 {
				value = strings.TrimSpace(value[:idx])
			}
		}
		fn(key, value)
	}
	return scanner.Err()
}

// Load reads the config file at path and returns a Config.
// Missing keys fall back to defaults. A missing file is not an error – defaults are used.
func Load(path string) (*Config, error) {
	cfg := &Config{
		BrokerPort:        defaultBrokerPort,
		HeartbeatInterval: defaultHeartbeatInterval,
		StateInterval:     defaultStateInterval,
		AgentVersion:      "1.0.0",
	}

	if err := scanKeyValueFile(path, true, func(key, value string) {
		applyConfigKey(cfg, key, value)
	}); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadKeys parses a key=value config file at path and returns a map of keys to
// values using the same format as Load. A missing file is not an error.
func loadKeys(path string) (map[string]string, error) {
	out := map[string]string{}
	if err := scanKeyValueFile(path, true, func(key, value string) {
		out[key] = value
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// LoadWithOverlay reads the static config at staticPath and then overlays keys
// from dhcpPath on top. DHCP values win on conflict. A missing dhcp file is not
// an error — the static config is returned as-is.
func LoadWithOverlay(staticPath, dhcpPath string) (*Config, error) {
	cfg, err := Load(staticPath)
	if err != nil {
		return nil, err
	}
	overlay, err := loadKeys(dhcpPath)
	if err != nil {
		return nil, fmt.Errorf("dhcp config: %w", err)
	}
	for key, value := range overlay {
		applyConfigKey(cfg, key, value)
	}
	return cfg, nil
}

// brokerHostPollInterval is the sleep between polls in WaitForBrokerHost.
// Overridden in tests to avoid slow sleeps.
var brokerHostPollInterval = 5 * time.Second

// pollUntil calls tryOnce every interval (clamped to whatever time remains
// before timeout) until it reports success, returning timeoutErr() if the
// deadline passes first. Shared by WaitForBrokerHost and
// WaitForBootstrapToken, whose only difference beyond this loop is what
// counts as "ready" and how the timeout error reads — timeout must be > 0;
// each caller keeps its own zero-timeout ("try once, no wait") special case,
// since those differ too (WaitForBrokerHost synthesizes a message,
// WaitForBootstrapToken just returns ReadBootstrapToken's own error).
func pollUntil[T any](timeout, interval time.Duration, tryOnce func() (T, bool), timeoutErr func() error) (T, error) {
	deadline := time.Now().Add(timeout)
	for {
		if v, ok := tryOnce(); ok {
			return v, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			var zero T
			return zero, timeoutErr()
		}
		time.Sleep(min(interval, remaining))
	}
}

// WaitForBrokerHost polls LoadWithOverlay until cfg.BrokerHost is non-empty or
// timeout elapses. Use this when broker_host may be delivered by a DHCP hook
// (option 225) written after the agent starts. Zero timeout means one try with
// no wait — returns an error if BrokerHost is still empty.
func WaitForBrokerHost(staticPath, dhcpPath string, timeout time.Duration) (*Config, error) {
	tryOnce := func() (*Config, bool) {
		cfg, err := LoadWithOverlay(staticPath, dhcpPath)
		if err == nil && cfg.BrokerHost != "" {
			return cfg, true
		}
		return cfg, false
	}

	if timeout <= 0 {
		cfg, ok := tryOnce()
		if !ok {
			return nil, fmt.Errorf("BROKER_HOST is not set in %s or %s", staticPath, dhcpPath)
		}
		return cfg, nil
	}

	return pollUntil(timeout, brokerHostPollInterval, tryOnce, func() error {
		return fmt.Errorf("BROKER_HOST not available in %s or %s after %v", staticPath, dhcpPath, timeout)
	})
}

// ReadBootstrapToken reads the one-line token file at path.
func ReadBootstrapToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// bootstrapTokenPollInterval is the sleep between polls in WaitForBootstrapToken.
// Overridden in tests to avoid slow sleeps.
var bootstrapTokenPollInterval = 5 * time.Second

// WaitForBootstrapToken polls path until a non-empty token appears or timeout
// elapses. Use this when the token may be written by a DHCP hook after the
// agent starts. A zero timeout is equivalent to ReadBootstrapToken (one try,
// no wait). Poll interval is bootstrapTokenPollInterval (5 s in production).
func WaitForBootstrapToken(path string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return ReadBootstrapToken(path)
	}
	tryOnce := func() (string, bool) {
		tok, err := ReadBootstrapToken(path)
		return tok, err == nil && tok != ""
	}
	return pollUntil(timeout, bootstrapTokenPollInterval, tryOnce, func() error {
		return fmt.Errorf("bootstrap token not found at %s after %v", path, timeout)
	})
}
