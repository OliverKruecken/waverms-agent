package mqtt

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockMQTTClient_Connect_RecordsOpts(t *testing.T) {
	m := NewMockMQTTClient()
	opts := ConnectOptions{
		BrokerHost: "broker.local",
		BrokerPort: 8883,
		ClientID:   "test-client",
		Username:   "user",
		Password:   "pass",
	}
	err := m.Connect(context.Background(), opts)
	require.NoError(t, err)
	require.Len(t, m.ConnectOpts, 1)
	assert.Equal(t, opts, m.ConnectOpts[0])
}

func TestMockMQTTClient_Publish_RecordsMsg(t *testing.T) {
	m := NewMockMQTTClient()
	err := m.Publish(context.Background(), "device/abc/info", []byte(`{"ok":true}`), 1, false)
	require.NoError(t, err)
	require.Len(t, m.Published, 1)
	assert.Equal(t, "device/abc/info", m.Published[0].Topic)
	assert.Equal(t, []byte(`{"ok":true}`), m.Published[0].Payload)
	assert.Equal(t, byte(1), m.Published[0].QoS)
	assert.False(t, m.Published[0].Retain)
}

func TestMockMQTTClient_Subscribe_RecordsAndDelivers(t *testing.T) {
	m := NewMockMQTTClient()

	received := make(chan []byte, 1)
	err := m.Subscribe(context.Background(), "device/abc/cmd", 1, func(topic string, payload []byte) {
		received <- payload
	})
	require.NoError(t, err)

	m.SimulateMessage("device/abc/cmd", []byte(`{"cmd_id":"x"}`))

	msg := <-received
	assert.Equal(t, []byte(`{"cmd_id":"x"}`), msg)
}

func TestMockMQTTClient_SimulateDisconnect(t *testing.T) {
	m := NewMockMQTTClient()
	ch := m.Disconnected()

	m.SimulateDisconnect()

	select {
	case <-ch:
		// expected
	default:
		t.Fatal("disconnect channel should be closed")
	}
}

func TestMockMQTTClient_SimulateDisconnect_Idempotent(t *testing.T) {
	m := NewMockMQTTClient()
	// calling twice should not panic
	m.SimulateDisconnect()
	m.SimulateDisconnect()
}

func TestMockMQTTClient_Reset_ClearsState(t *testing.T) {
	m := NewMockMQTTClient()
	_ = m.Connect(context.Background(), ConnectOptions{})
	_ = m.Publish(context.Background(), "t", []byte("p"), 0, false)
	m.SimulateDisconnect()

	m.Reset()

	assert.Empty(t, m.ConnectOpts)
	assert.Empty(t, m.Published)
	assert.Empty(t, m.Subscriptions)
	// new channel should be open
	select {
	case <-m.Disconnected():
		t.Fatal("disconnect channel should be open after Reset")
	default:
	}
}

func TestMockMQTTClient_ConnectErr(t *testing.T) {
	m := NewMockMQTTClient()
	m.SetConnectErr(assert.AnError)
	err := m.Connect(context.Background(), ConnectOptions{})
	assert.ErrorIs(t, err, assert.AnError)
}

func TestMockMQTTClient_SubscribeErr(t *testing.T) {
	m := NewMockMQTTClient()
	m.SetSubscribeErr(assert.AnError)
	err := m.Subscribe(context.Background(), "t/1", 1, func(string, []byte) {})
	assert.ErrorIs(t, err, assert.AnError)
	// Handler must not have been registered.
	assert.NotContains(t, m.Subscriptions, "t/1")
}

func TestMockMQTTClient_DisconnectCount(t *testing.T) {
	m := NewMockMQTTClient()
	assert.Equal(t, 0, m.DisconnectCount())
	m.Disconnect()
	assert.Equal(t, 1, m.DisconnectCount())
	m.Disconnect()
	assert.Equal(t, 2, m.DisconnectCount())
}

// --- PahoClient unit tests (no broker required) ---

func TestPahoClient_PublishBeforeConnect_ReturnsError(t *testing.T) {
	c := NewPahoClient(nil)
	err := c.Publish(context.Background(), "t/1", []byte("hello"), 1, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestPahoClient_SubscribeBeforeConnect_ReturnsError(t *testing.T) {
	c := NewPahoClient(nil)
	err := c.Subscribe(context.Background(), "t/1", 1, func(string, []byte) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestPahoClient_DisconnectBeforeConnect_IsNoop(t *testing.T) {
	c := NewPahoClient(nil)
	// Must not panic when client field is nil.
	assert.NotPanics(t, func() { c.Disconnect() })
}

func TestPahoClient_DisconnectedBeforeConnect_ReturnsNilChannel(t *testing.T) {
	c := NewPahoClient(nil)
	// disconnCh is nil until the first Connect; callers must not select on it
	// before connecting — this test documents current behaviour.
	ch := c.Disconnected()
	assert.Nil(t, ch, "Disconnected() returns nil before Connect is called")
}

func TestPahoClient_DisconnectReasonBeforeConnect_ReturnsNil(t *testing.T) {
	c := NewPahoClient(nil)
	assert.NoError(t, c.DisconnectReason())
}

func TestDisconnectState_SetGet_KeepsFirstReason(t *testing.T) {
	s := &disconnectState{}
	assert.NoError(t, s.get(), "no reason set yet")

	s.set(assert.AnError)
	assert.ErrorIs(t, s.get(), assert.AnError)

	// A later call (e.g. OnServerDisconnect firing after OnClientError already
	// did) must not overwrite the first recorded reason.
	s.set(fmt.Errorf("a different, later error"))
	assert.ErrorIs(t, s.get(), assert.AnError, "first reason must win")
}

func TestMockMQTTClient_DisconnectReason(t *testing.T) {
	m := NewMockMQTTClient()
	assert.NoError(t, m.DisconnectReason())

	m.SetDisconnectReason(assert.AnError)
	assert.ErrorIs(t, m.DisconnectReason(), assert.AnError)

	// Connect clears the previous reason, mirroring PahoClient starting a
	// fresh disconnectState per connection attempt.
	require.NoError(t, m.Connect(context.Background(), ConnectOptions{}))
	assert.NoError(t, m.DisconnectReason())
}
