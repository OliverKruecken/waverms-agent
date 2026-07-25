package hardware

import (
	"os"
	"strings"
)

// GetOpenWrtVersion reads the release version from /etc/openwrt_release.
// Returns "unknown" if the file is missing or the field is not found.
func GetOpenWrtVersion() string {
	return getOpenWrtVersion("/etc/openwrt_release")
}

func getOpenWrtVersion(path string) string {
	return readReleaseField(path, "DISTRIB_RELEASE=")
}

// GetTarget reads the OpenWrt build target (e.g. "ath79/generic") from
// /etc/openwrt_release. Returns "unknown" if the file is missing or the
// field is not found.
func GetTarget() string {
	return getTarget("/etc/openwrt_release")
}

func getTarget(path string) string {
	return readReleaseField(path, "DISTRIB_TARGET=")
}

// GetVersionCode reads the release revision (e.g. "r23809-234f1a2efa") from
// /etc/openwrt_release. Returns "unknown" if the file is missing or the
// field is not found.
func GetVersionCode() string {
	return getVersionCode("/etc/openwrt_release")
}

func getVersionCode(path string) string {
	return readReleaseField(path, "DISTRIB_REVISION=")
}

// readReleaseField reads path (an /etc/openwrt_release-formatted file) and
// returns the value of the first line starting with prefix, with quotes
// trimmed. Returns "unknown" if the file is missing or the field is absent
// or empty.
func readReleaseField(path string, prefix string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		val := strings.TrimPrefix(line, prefix)
		val = strings.Trim(val, `"'`)
		if val != "" {
			return val
		}
	}
	return "unknown"
}

// GetModel reads the hardware model string from /tmp/sysinfo/model (OpenWrt standard).
// Returns "unknown" if the file is missing or empty.
func GetModel() string {
	return getModel("/tmp/sysinfo/model")
}

func getModel(path string) string {
	return readSysinfoFile(path)
}

// GetBoardName reads the board name (the ImageBuilder PROFILE, e.g.
// "8dev_carambola2") from /tmp/sysinfo/board_name (OpenWrt standard).
// Returns "unknown" if the file is missing or empty.
func GetBoardName() string {
	return getBoardName("/tmp/sysinfo/board_name")
}

func getBoardName(path string) string {
	return readSysinfoFile(path)
}

// readSysinfoFile reads a single-value file under /tmp/sysinfo (procd's
// runtime hardware-identity files). Returns "unknown" if the file is
// missing or empty.
func readSysinfoFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	val := strings.TrimSpace(string(data))
	if val == "" {
		return "unknown"
	}
	return val
}
