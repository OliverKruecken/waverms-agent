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

// macCandidate is a physical interface whose of_node places it in the same
// device-tree family as the label-mac-device node.
type macCandidate struct {
	name string
	mac  string
}

// getLabelMAC resolves the MAC via the label-mac-device device-tree alias:
// it names the DT node of the interface whose address is the device's label
// MAC, so we read that alias and find which /sys/class/net interface's
// of_node symlink points at the same node.
//
// Some drivers (e.g. MediaTek's mtk_eth_soc, used on GL.iNet GL-MT6000 and
// other filogic boards) register every physical port as a separate netdev
// under one shared platform device, so /sys/class/net/{iface}/device/of_node
// resolves to the parent Ethernet controller node for all of them -- it
// can't identify one specific gmac sub-node. When no interface's of_node
// matches the label node exactly, we fall back to the interfaces whose
// of_node is an ancestor of it (i.e. share the labeled port's controller)
// and pick the smallest same-OUI address among them: per this SoC family's
// nvmem-cells convention, the label port is always the unmodified factory
// base address (nvmem-cells offset 0), and every sibling port is that base
// plus a positive per-port offset -- the same "base + N" convention this
// project's own ${LOCAL_MAC} derivation relies on (see
// docs/mac_address_derivation.md).
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
	var family []macCandidate
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(sysDir, e.Name(), "device", "of_node"))
		if err != nil {
			continue
		}

		_, nodePath, found := strings.Cut(target, dtMarker)
		if !found {
			continue
		}
		if nodePath != labelNode && !strings.HasPrefix(labelNode, nodePath+"/") {
			continue
		}

		addrPath := filepath.Join(sysDir, e.Name(), "address")
		addr, err := os.ReadFile(addrPath)
		if err != nil {
			continue
		}

		mac := strings.TrimSpace(string(addr))
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}

		if nodePath == labelNode {
			return mac, nil
		}
		family = append(family, macCandidate{name: e.Name(), mac: mac})
	}

	if len(family) == 0 {
		return "", fmt.Errorf("no interface's of_node is the label-mac-device node %s or an ancestor of it", labelNode)
	}

	best := family[0]
	for _, c := range family[1:] {
		if c.mac[:8] != best.mac[:8] {
			return "", fmt.Errorf("label-mac-device family has mismatched OUIs (%s vs %s), refusing to guess", c.mac, best.mac)
		}
		if c.mac < best.mac {
			best = c
		}
	}
	return best.mac, nil
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
