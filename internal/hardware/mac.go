// Package hardware provides access to hardware information such as MAC addresses.
package hardware

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GetFirstPhysicalMAC returns the MAC address of the first physical Ethernet
// device. Physical devices have a /sys/class/net/{iface}/device symlink;
// virtual interfaces (bridges, vlans, loopback) do not.
func GetFirstPhysicalMAC() (string, error) {
	return getFirstPhysicalMAC("/sys/class/net")
}

// getFirstPhysicalMAC is the testable inner function that accepts a sysDir
// so tests can point it at a fake sysfs tree in a temp directory.
func getFirstPhysicalMAC(sysDir string) (string, error) {
	entries, err := os.ReadDir(sysDir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sysDir, err)
	}

	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}

		// Physical devices have a /sys/class/net/{iface}/device symlink.
		deviceLink := filepath.Join(sysDir, name, "device")
		if _, err := os.Lstat(deviceLink); os.IsNotExist(err) {
			continue
		}

		// Read the MAC address.
		addrPath := filepath.Join(sysDir, name, "address")
		data, err := os.ReadFile(addrPath)
		if err != nil {
			continue
		}

		mac := strings.TrimSpace(string(data))
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}

		return mac, nil
	}

	return "", fmt.Errorf("no physical ethernet device found")
}
