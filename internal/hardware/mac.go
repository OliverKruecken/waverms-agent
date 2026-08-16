// Package hardware provides access to hardware information such as MAC addresses.
package hardware

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GetFirstPhysicalMAC returns the device's burned-in/label MAC address.
// Boards with more than one physical Ethernet MAC and no DSA switch between
// them (e.g. MediaTek filogic SoCs like the GL.iNet GL-MT6000, which has
// separate gmac0/gmac1 controllers) declare an OpenWrt "label-mac-device"
// device-tree alias saying which one carries the address printed on the
// device's label -- eth0/eth1 kernel probe order doesn't reliably match it
// and can vary across firmware/kernel versions. That alias is tried first;
// if the board's device tree doesn't set it, this falls back to the first
// interface with a /sys/class/net/{iface}/device symlink (physical devices
// have one; virtual interfaces -- bridges, vlans, loopback -- do not).
func GetFirstPhysicalMAC() (string, error) {
	return getBurnedInMAC("/sys/class/net", "/sys/firmware/devicetree/base")
}

// getBurnedInMAC is the testable inner function that accepts sysDir and
// dtBase so tests can point them at fake sysfs/devicetree trees in a temp
// directory.
func getBurnedInMAC(sysDir, dtBase string) (string, error) {
	if mac, err := getLabelMAC(sysDir, dtBase); err == nil {
		return mac, nil
	}
	return getFirstPhysicalMAC(sysDir)
}

// getLabelMAC resolves the MAC via the label-mac-device device-tree alias:
// it names the DT node of the interface whose address is the device's label
// MAC, so we read that alias and find which /sys/class/net interface's
// of_node symlink points at the same node.
func getLabelMAC(sysDir, dtBase string) (string, error) {
	aliasPath := filepath.Join(dtBase, "aliases", "label-mac-device")
	data, err := os.ReadFile(aliasPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", aliasPath, err)
	}

	labelNode := strings.TrimRight(string(data), "\x00\n")
	if labelNode == "" {
		return "", fmt.Errorf("empty label-mac-device alias")
	}

	entries, err := os.ReadDir(sysDir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sysDir, err)
	}

	const dtMarker = "devicetree/base"
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(sysDir, e.Name(), "device", "of_node"))
		if err != nil {
			continue
		}

		_, nodePath, found := strings.Cut(target, dtMarker)
		if !found || nodePath != labelNode {
			continue
		}

		addrPath := filepath.Join(sysDir, e.Name(), "address")
		addr, err := os.ReadFile(addrPath)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", addrPath, err)
		}

		mac := strings.TrimSpace(string(addr))
		if mac == "" || mac == "00:00:00:00:00:00" {
			return "", fmt.Errorf("label-mac-device interface %s has no usable MAC", e.Name())
		}
		return mac, nil
	}

	return "", fmt.Errorf("no interface matches label-mac-device alias %s", labelNode)
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
