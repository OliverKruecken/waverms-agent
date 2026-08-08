// Package mqtt provides the MQTTClient interface, a Paho-backed implementation,
// a mock for testing, and topic builder functions.
package mqtt

import "fmt"

// TopicInfo returns the topic for periodic device info heartbeats.
func TopicInfo(deviceID string) string {
	return fmt.Sprintf("device/%s/info", deviceID)
}

// TopicCommand returns the topic the server publishes commands to.
func TopicCommand(deviceID string) string {
	return fmt.Sprintf("device/%s/cmd", deviceID)
}

// TopicAck returns the topic the agent publishes command acknowledgements to.
func TopicAck(deviceID string) string {
	return fmt.Sprintf("device/%s/ack", deviceID)
}

// TopicStatus returns the LWT topic for the device.
func TopicStatus(deviceID string) string {
	return fmt.Sprintf("device/%s/status", deviceID)
}

// TopicBootstrapRegister returns the topic the agent publishes the register request to.
func TopicBootstrapRegister() string {
	return "bootstrap/register"
}

// TopicBootstrapResponse returns the topic the server responds to with credentials.
func TopicBootstrapResponse(tmpID string) string {
	return fmt.Sprintf("bootstrap/%s/response", tmpID)
}

// TopicStateRequest returns the topic the server publishes on-demand state requests to.
func TopicStateRequest(deviceID string) string {
	return fmt.Sprintf("device/%s/state/request", deviceID)
}

// TopicInfoRequest returns the topic the server publishes on-demand info/heartbeat requests to.
func TopicInfoRequest(deviceID string) string {
	return fmt.Sprintf("device/%s/info/request", deviceID)
}

// TopicState returns the topic the agent publishes actual UCI state reports to.
func TopicState(deviceID string) string {
	return fmt.Sprintf("device/%s/state", deviceID)
}

// TopicLiveLogsControl returns the topic the server publishes live-log streaming toggles to (retain: true).
func TopicLiveLogsControl(deviceID string) string {
	return fmt.Sprintf("device/%s/live-logs/control", deviceID)
}

// TopicLiveLogsLog returns the topic the agent publishes live log entries to (QoS 0, no retain).
func TopicLiveLogsLog(deviceID string) string {
	return fmt.Sprintf("device/%s/live-logs/log", deviceID)
}

// TopicLogLevelControl returns the topic the server publishes debug-level toggles to (retain: true).
func TopicLogLevelControl(deviceID string) string {
	return fmt.Sprintf("device/%s/log-level/control", deviceID)
}

// TopicUbusStatus returns the topic the agent publishes periodic ubus_watch results to (QoS 1, no retain).
func TopicUbusStatus(deviceID string) string {
	return fmt.Sprintf("device/%s/ubus-status", deviceID)
}
