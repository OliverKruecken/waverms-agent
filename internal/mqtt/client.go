package mqtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/eclipse/paho.golang/paho"
)

// MessageHandler is a callback invoked when a message arrives on a subscribed topic.
type MessageHandler func(topic string, payload []byte)

// LWT carries Last-Will-Testament settings for the CONNECT packet.
type LWT struct {
	Topic   string
	Payload []byte
	QoS     byte
	Retain  bool
}

// ConnectOptions collects all parameters for Connect.
type ConnectOptions struct {
	BrokerHost string
	BrokerPort int
	ClientID   string
	Username   string
	Password   string
	LWT        *LWT
	TLSConfig  *tls.Config
	// CleanStart requests a fresh broker session, discarding any queued messages.
	// Use once after sysupgrade to prevent re-delivery of the flashing command.
	CleanStart bool
}

// MQTTClient abstracts the MQTT connection so agent logic and tests
// can use the same interface.
type MQTTClient interface {
	Connect(ctx context.Context, opts ConnectOptions) error
	Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error
	Subscribe(ctx context.Context, topic string, qos byte, handler MessageHandler) error
	Disconnect()
	// Disconnected returns a channel that is closed when the connection is lost unexpectedly.
	Disconnected() <-chan struct{}
	// DisconnectReason returns the error that caused the most recent unexpected
	// disconnect (from the paho client's OnClientError/OnServerDisconnect
	// callbacks), or nil if the current session hasn't disconnected yet.
	// Cleared at the start of each Connect call.
	DisconnectReason() error
}

// disconnectState holds the reason for an unexpected disconnect. It's a
// separate object (not a *PahoClient field read directly) so that
// OnClientError/OnServerDisconnect — which run on the paho client's internal
// goroutines and must never block on PahoClient.mu, since Connect holds that
// mutex for the entire handshake — only ever touch their own small mutex.
type disconnectState struct {
	mu     sync.Mutex
	reason error
}

func (d *disconnectState) set(err error) {
	d.mu.Lock()
	if d.reason == nil { // keep the first reason; later callbacks are just noise
		d.reason = err
	}
	d.mu.Unlock()
}

func (d *disconnectState) get() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reason
}

// PahoClient wraps github.com/eclipse/paho.golang/paho and implements MQTTClient.
type PahoClient struct {
	tlsCfg *tls.Config

	mu              sync.Mutex
	client          *paho.Client
	router          *paho.StandardRouter
	disconnCh       chan struct{}
	closeOnce       *sync.Once
	disconnectState *disconnectState
}

// NewPahoClient creates a PahoClient. Pass nil for tlsCfg to use plain TCP.
func NewPahoClient(tlsCfg *tls.Config) *PahoClient {
	return &PahoClient{tlsCfg: tlsCfg}
}

// Connect dials the broker, performs the MQTT CONNECT handshake, and starts the
// client's background workers. It must be called exactly once per session.
func (c *PahoClient) Connect(ctx context.Context, opts ConnectOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Fresh disconnect channel, once, and reason holder for each connection attempt.
	disconnCh := make(chan struct{})
	closeOnce := &sync.Once{}
	state := &disconnectState{}
	c.disconnCh = disconnCh
	c.closeOnce = closeOnce
	c.disconnectState = state

	addr := net.JoinHostPort(opts.BrokerHost, fmt.Sprintf("%d", opts.BrokerPort))

	// opts.TLSConfig overrides the client-level config; fall back to the
	// PahoClient's own tlsCfg (set at construction time in main.go).
	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = c.tlsCfg
	}

	var conn net.Conn
	var err error
	if tlsCfg != nil {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	router := paho.NewStandardRouter()
	c.router = router

	cfg := paho.ClientConfig{
		ClientID: opts.ClientID,
		Conn:     conn,
		Router:   router,
		OnClientError: func(e error) {
			state.set(e)
			closeOnce.Do(func() { close(disconnCh) })
		},
		OnServerDisconnect: func(d *paho.Disconnect) {
			state.set(fmt.Errorf("server disconnect: reason code %d", d.ReasonCode))
			closeOnce.Do(func() { close(disconnCh) })
		},
	}

	client := paho.NewClient(cfg)
	c.client = client

	cp := &paho.Connect{
		ClientID:   opts.ClientID,
		CleanStart: opts.CleanStart,
		KeepAlive:  30,
		Properties: &paho.ConnectProperties{
			// 5-minute session expiry lets the broker queue QoS-1 commands
			// for brief disconnects (reconnects, DHCP renewals).
			SessionExpiryInterval: func() *uint32 { v := uint32(300); return &v }(),
		},
	}

	if opts.Username != "" {
		cp.Username = opts.Username
		cp.UsernameFlag = true
	}
	if opts.Password != "" {
		cp.Password = []byte(opts.Password)
		cp.PasswordFlag = true
	}

	if opts.LWT != nil {
		cp.WillMessage = &paho.WillMessage{
			Topic:   opts.LWT.Topic,
			Payload: opts.LWT.Payload,
			QoS:     opts.LWT.QoS,
			Retain:  opts.LWT.Retain,
		}
		cp.WillProperties = &paho.WillProperties{}
	}

	ca, err := client.Connect(ctx, cp)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mqtt connect: %w", err)
	}
	if ca.ReasonCode != 0 {
		conn.Close()
		return fmt.Errorf("mqtt connect rejected: reason code %d", ca.ReasonCode)
	}

	return nil
}

// Publish sends a message to topic.
func (c *PahoClient) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()

	if client == nil {
		return fmt.Errorf("not connected")
	}

	_, err := client.Publish(ctx, &paho.Publish{
		QoS:     qos,
		Retain:  retain,
		Topic:   topic,
		Payload: payload,
	})
	return err
}

// Subscribe registers handler for all messages arriving on topic.
func (c *PahoClient) Subscribe(ctx context.Context, topic string, qos byte, handler MessageHandler) error {
	c.mu.Lock()
	client := c.client
	router := c.router
	c.mu.Unlock()

	if client == nil {
		return fmt.Errorf("not connected")
	}

	router.RegisterHandler(topic, func(pub *paho.Publish) {
		handler(pub.Topic, pub.Payload)
	})

	_, err := client.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{Topic: topic, QoS: qos},
		},
	})
	return err
}

// Disconnect sends a clean DISCONNECT to the broker.
func (c *PahoClient) Disconnect() {
	c.mu.Lock()
	client := c.client
	closeOnce := c.closeOnce
	disconnCh := c.disconnCh
	c.mu.Unlock()

	if client == nil {
		return
	}
	_ = client.Disconnect(&paho.Disconnect{ReasonCode: 0})
	// Close the disconnect channel so callers waiting on it unblock.
	if closeOnce != nil {
		closeOnce.Do(func() { close(disconnCh) })
	}
}

// Disconnected returns a channel closed when the connection is lost unexpectedly.
func (c *PahoClient) Disconnected() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnCh
}

func (c *PahoClient) DisconnectReason() error {
	c.mu.Lock()
	state := c.disconnectState
	c.mu.Unlock()
	if state == nil {
		return nil
	}
	return state.get()
}

// PublishedMsg records a single Publish call on MockMQTTClient.
type PublishedMsg struct {
	Topic   string
	Payload []byte
	QoS     byte
	Retain  bool
}

// MockMQTTClient is a test double that records all interactions.
type MockMQTTClient struct {
	mu            sync.Mutex
	ConnectOpts   []ConnectOptions
	Published     []PublishedMsg
	Subscriptions map[string]MessageHandler
	PublishCalls  int // total Publish invocations, including failed ones
	disconnCh     chan struct{}
	connectErr    error
	subscribeErr  error // returned by every Subscribe call when set
	publishErr    error // returned by Publish while publishFails > 0
	publishFails  int   // number of upcoming Publish calls that fail
	disconnectCnt int   // incremented by every Disconnect call
	disconnectErr error // returned by DisconnectReason; set via SetDisconnectReason
}

// NewMockMQTTClient creates a ready-to-use mock.
func NewMockMQTTClient() *MockMQTTClient {
	return &MockMQTTClient{
		Subscriptions: make(map[string]MessageHandler),
		disconnCh:     make(chan struct{}),
	}
}

// SetConnectErr causes Connect to return err.
func (m *MockMQTTClient) SetConnectErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectErr = err
}

func (m *MockMQTTClient) Connect(_ context.Context, opts ConnectOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ConnectOpts = append(m.ConnectOpts, opts)
	if m.connectErr != nil {
		return m.connectErr
	}
	// Each successful Connect gets a fresh disconnect channel and clears the
	// previous disconnect reason, mirroring PahoClient.
	m.disconnCh = make(chan struct{})
	m.disconnectErr = nil
	return nil
}

// FailNextPublishes makes the next n Publish calls return err instead of
// recording the message.
func (m *MockMQTTClient) FailNextPublishes(n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publishFails = n
	m.publishErr = err
}

func (m *MockMQTTClient) Publish(_ context.Context, topic string, payload []byte, qos byte, retain bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PublishCalls++
	if m.publishFails > 0 {
		m.publishFails--
		return m.publishErr
	}
	m.Published = append(m.Published, PublishedMsg{
		Topic:   topic,
		Payload: payload,
		QoS:     qos,
		Retain:  retain,
	})
	return nil
}

// SetSubscribeErr causes every Subscribe call to return err.
func (m *MockMQTTClient) SetSubscribeErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribeErr = err
}

func (m *MockMQTTClient) Subscribe(_ context.Context, topic string, _ byte, handler MessageHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subscribeErr != nil {
		return m.subscribeErr
	}
	m.Subscriptions[topic] = handler
	return nil
}

// DisconnectCount returns the number of times Disconnect has been called.
func (m *MockMQTTClient) DisconnectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disconnectCnt
}

func (m *MockMQTTClient) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnectCnt++
}

func (m *MockMQTTClient) Disconnected() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disconnCh
}

// SimulateMessage delivers payload to the registered handler for topic.
func (m *MockMQTTClient) SimulateMessage(topic string, payload []byte) {
	m.mu.Lock()
	handler := m.Subscriptions[topic]
	m.mu.Unlock()
	if handler != nil {
		handler(topic, payload)
	}
}

// SimulateDisconnect closes the disconnect channel, triggering reconnect in the agent.
func (m *MockMQTTClient) SimulateDisconnect() {
	m.mu.Lock()
	ch := m.disconnCh
	m.mu.Unlock()

	select {
	case <-ch:
		// already closed
	default:
		close(ch)
	}
}

// SetDisconnectReason makes the next DisconnectReason call return err —
// useful for testing that a specific disconnect cause surfaces in logs.
func (m *MockMQTTClient) SetDisconnectReason(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnectErr = err
}

// DisconnectReason returns the error set via SetDisconnectReason, or nil.
func (m *MockMQTTClient) DisconnectReason() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disconnectErr
}

// HasSubscription returns true if the mock has a handler registered for topic.
func (m *MockMQTTClient) HasSubscription(topic string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.Subscriptions[topic]
	return ok
}

// ConnectCount returns the number of Connect calls made.
func (m *MockMQTTClient) ConnectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ConnectOpts)
}

// PublishedSnapshot returns a copy of the messages published so far. Use this
// instead of reading the Published field directly whenever a background
// goroutine (e.g. the config_apply connectivity watchdog) may still be
// publishing concurrently with the test — a direct field read in that case is
// a data race, not just a style nit.
func (m *MockMQTTClient) PublishedSnapshot() []PublishedMsg {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PublishedMsg, len(m.Published))
	copy(out, m.Published)
	return out
}

// Reset prepares the mock for a new connection attempt (new disconnCh).
func (m *MockMQTTClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnCh = make(chan struct{})
	m.Published = nil
	m.ConnectOpts = nil
	m.Subscriptions = make(map[string]MessageHandler)
}
