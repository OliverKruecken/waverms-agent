package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Credentials holds the device credentials written by the bootstrap flow.
type Credentials struct {
	DeviceID   string
	Secret     string
	BrokerHost string
	BrokerPort int
}

// HasCredentials returns true when the credentials contain a non-empty DeviceID and Secret.
func (c *Credentials) HasCredentials() bool {
	return c != nil && c.DeviceID != "" && c.Secret != ""
}

// LoadCredentials reads credentials from path. Returns an empty Credentials (not an error)
// if the file does not exist – callers should check HasCredentials().
//
// Inline comments are NOT stripped (stripInlineComments=false passed to
// scanKeyValueFile): credentials are machine-written by SaveCredentials and
// never contain comments, and stripping " #" would silently truncate a
// SECRET or DEVICE_ID that happens to contain that byte sequence, causing
// MQTT authentication failures with no obvious error message.
func LoadCredentials(path string) (*Credentials, error) {
	creds := &Credentials{}

	err := scanKeyValueFile(path, false, func(key, value string) {
		switch key {
		case "DEVICE_ID":
			creds.DeviceID = value
		case "SECRET":
			creds.Secret = value
		case "BROKER_HOST":
			creds.BrokerHost = value
		case "BROKER_PORT":
			if p, err := strconv.Atoi(value); err == nil {
				creds.BrokerPort = p
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("scan credentials %s: %w", path, err)
	}

	return creds, nil
}

// SaveCredentials writes credentials atomically to path (chmod 600).
// It writes to a temporary file in the same directory and then renames it
// into place. On Linux, rename(2) is atomic — a power loss during the write
// cannot leave a truncated credentials file, which would break bootstrap.
func SaveCredentials(path, deviceID, secret, brokerHost string, brokerPort int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "DEVICE_ID=%s\n", deviceID)
	fmt.Fprintf(&b, "SECRET=%s\n", secret)
	if brokerHost != "" {
		fmt.Fprintf(&b, "BROKER_HOST=%s\n", brokerHost)
	}
	if brokerPort > 0 {
		fmt.Fprintf(&b, "BROKER_PORT=%d\n", brokerPort)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp credentials: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp credentials: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp credentials: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp credentials: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename credentials %s: %w", path, err)
	}
	return nil
}
