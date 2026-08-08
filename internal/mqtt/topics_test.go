package mqtt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTopicInfo(t *testing.T) {
	assert.Equal(t, "device/abc-123/info", TopicInfo("abc-123"))
}

func TestTopicCommand(t *testing.T) {
	assert.Equal(t, "device/abc-123/cmd", TopicCommand("abc-123"))
}

func TestTopicAck(t *testing.T) {
	assert.Equal(t, "device/abc-123/ack", TopicAck("abc-123"))
}

func TestTopicStatus(t *testing.T) {
	assert.Equal(t, "device/abc-123/status", TopicStatus("abc-123"))
}

func TestTopicBootstrapRegister(t *testing.T) {
	assert.Equal(t, "bootstrap/register", TopicBootstrapRegister())
}

func TestTopicBootstrapResponse(t *testing.T) {
	assert.Equal(t, "bootstrap/tmp-uuid-001/response", TopicBootstrapResponse("tmp-uuid-001"))
}

func TestTopicLogLevelControl(t *testing.T) {
	assert.Equal(t, "device/abc-123/log-level/control", TopicLogLevelControl("abc-123"))
}

func TestTopicUbusStatus(t *testing.T) {
	assert.Equal(t, "device/abc-123/ubus-status", TopicUbusStatus("abc-123"))
}
