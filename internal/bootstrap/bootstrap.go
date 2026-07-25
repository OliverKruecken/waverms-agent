// Package bootstrap implements the first-boot and re-bootstrap registration flow.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/OliverKruecken/waverms-agent/internal/config"
	mqttclient "github.com/OliverKruecken/waverms-agent/internal/mqtt"
	"github.com/google/uuid"
)

// BootstrapRequest is the payload published to bootstrap/register.
type BootstrapRequest struct {
	TmpID          string `json:"tmp_id"`
	BootstrapToken string `json:"bootstrap_token"`
	HwInfo         HwInfo `json:"hw_info"`
}

// HwInfo carries hardware identification sent during bootstrap.
type HwInfo struct {
	MAC            string `json:"mac"`
	Model          string `json:"model"`
	OpenWrtVersion string `json:"openwrt_version"`
	AgentVersion   string `json:"agent_version"`
	Target         string `json:"target"`
	Profile        string `json:"profile"`
	VersionCode    string `json:"version_code"`
}

// BootstrapResponse is the payload received on the response topic.
type BootstrapResponse struct {
	DeviceID   string `json:"device_id"`
	Secret     string `json:"secret"`
	BrokerHost string `json:"broker_host"`
	BrokerPort int    `json:"broker_port"`
}

// Options configures a bootstrap run. In production all fields are filled by
// main.go; in tests they are injected to control behaviour without a real device.
type Options struct {
	// TokenPath is the path of the bootstrap token file (plain text, one line).
	TokenPath string
	// CredsPath is where the new credentials will be written (chmod 600).
	CredsPath string
	// TmpID is the temporary correlation UUID. If empty, uuid.New() is used.
	TmpID string
	// TokenWaitTimeout is how long to wait for the token file to appear.
	// Used when the token is delivered by a DHCP hook (see docs/agent-go.md).
	// Zero means try once and return an error if the file is missing.
	TokenWaitTimeout time.Duration
	// Hardware fields included in the registration request.
	MAC            string
	AgentVersion   string
	Model          string
	OpenWrtVersion string
	Target         string
	Profile        string
	VersionCode    string
}

// Run executes the full bootstrap flow:
//  1. Read the bootstrap token from TokenPath.
//  2. Connect to the broker as the bootstrap user.
//  3. Subscribe to the response topic before publishing the request.
//  4. Publish the registration request.
//  5. Wait up to 30 s for the server's response.
//  6. Write the received credentials to CredsPath and delete the token file.
func Run(ctx context.Context, cfg *config.Config, opts Options, client mqttclient.MQTTClient) (*BootstrapResponse, error) {
	if opts.TmpID == "" {
		opts.TmpID = uuid.New().String()
	}

	slog.Debug("bootstrap: reading token", "path", opts.TokenPath, "wait", opts.TokenWaitTimeout)
	token, err := config.WaitForBootstrapToken(opts.TokenPath, opts.TokenWaitTimeout)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap token: %w", err)
	}

	connOpts := mqttclient.ConnectOptions{
		BrokerHost: cfg.BrokerHost,
		BrokerPort: cfg.BrokerPort,
		ClientID:   "bootstrap-" + opts.TmpID,
		Username:   "bootstrap",
		Password:   token,
	}
	slog.Debug("bootstrap: connecting", "tmp_id", opts.TmpID, "host", cfg.BrokerHost, "port", cfg.BrokerPort)
	if err := client.Connect(ctx, connOpts); err != nil {
		return nil, fmt.Errorf("bootstrap connect: %w", err)
	}

	responseCh := make(chan BootstrapResponse, 1)
	responseTopic := mqttclient.TopicBootstrapResponse(opts.TmpID)

	if err := client.Subscribe(ctx, responseTopic, 1, func(_ string, payload []byte) {
		var resp BootstrapResponse
		if err := json.Unmarshal(payload, &resp); err != nil {
			return
		}
		select {
		case responseCh <- resp:
		default:
		}
	}); err != nil {
		return nil, fmt.Errorf("subscribe bootstrap response: %w", err)
	}
	slog.Debug("bootstrap: subscribed to response", "topic", responseTopic)

	req := BootstrapRequest{
		TmpID:          opts.TmpID,
		BootstrapToken: token,
		HwInfo: HwInfo{
			MAC:            opts.MAC,
			Model:          opts.Model,
			OpenWrtVersion: opts.OpenWrtVersion,
			AgentVersion:   opts.AgentVersion,
			Target:         opts.Target,
			Profile:        opts.Profile,
			VersionCode:    opts.VersionCode,
		},
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal bootstrap request: %w", err)
	}
	if err := client.Publish(ctx, mqttclient.TopicBootstrapRegister(), payload, 1, false); err != nil {
		return nil, fmt.Errorf("publish bootstrap request: %w", err)
	}
	slog.Debug("bootstrap: registration published", "tmp_id", opts.TmpID, "mac", opts.MAC)

	select {
	case resp := <-responseCh:
		slog.Info("bootstrap: complete", "device_id", resp.DeviceID)
		if err := config.SaveCredentials(opts.CredsPath, resp.DeviceID, resp.Secret, resp.BrokerHost, resp.BrokerPort); err != nil {
			return nil, fmt.Errorf("save credentials: %w", err)
		}
		_ = os.Remove(opts.TokenPath)
		return &resp, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("bootstrap timeout after 30s")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
