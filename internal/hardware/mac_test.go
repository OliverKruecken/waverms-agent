package hardware

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetFirstPhysicalMAC_SkipsLoopback(t *testing.T) {
	sysDir := t.TempDir()

	// loopback only – no device symlink
	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "lo"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "lo", "address"), []byte("00:00:00:00:00:00\n"), 0644))

	_, err := getFirstPhysicalMAC(sysDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no physical ethernet device found")
}

func TestGetFirstPhysicalMAC_SkipsVirtual(t *testing.T) {
	sysDir := t.TempDir()

	// virtual bridge – no device symlink
	brDir := filepath.Join(sysDir, "br-lan")
	require.NoError(t, os.MkdirAll(brDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(brDir, "address"), []byte("aa:bb:cc:dd:ee:01\n"), 0644))

	_, err := getFirstPhysicalMAC(sysDir)
	assert.Error(t, err)
}

func TestGetFirstPhysicalMAC_FindsPhysical(t *testing.T) {
	sysDir := t.TempDir()

	// loopback
	loDir := filepath.Join(sysDir, "lo")
	require.NoError(t, os.MkdirAll(loDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(loDir, "address"), []byte("00:00:00:00:00:00\n"), 0644))

	// virtual bridge – no device symlink
	brDir := filepath.Join(sysDir, "br-lan")
	require.NoError(t, os.MkdirAll(brDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(brDir, "address"), []byte("aa:bb:cc:dd:ee:01\n"), 0644))

	// physical ethernet – has device symlink
	eth0Dir := filepath.Join(sysDir, "eth0")
	require.NoError(t, os.MkdirAll(eth0Dir, 0755))
	require.NoError(t, os.Symlink("/sys/devices/platform/eth0", filepath.Join(eth0Dir, "device")))
	require.NoError(t, os.WriteFile(filepath.Join(eth0Dir, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0644))

	mac, err := getFirstPhysicalMAC(sysDir)
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
}

func TestGetFirstPhysicalMAC_SkipsZeroMAC(t *testing.T) {
	sysDir := t.TempDir()

	// physical interface but zero MAC
	eth0Dir := filepath.Join(sysDir, "eth0")
	require.NoError(t, os.MkdirAll(eth0Dir, 0755))
	require.NoError(t, os.Symlink("/sys/devices/platform/eth0", filepath.Join(eth0Dir, "device")))
	require.NoError(t, os.WriteFile(filepath.Join(eth0Dir, "address"), []byte("00:00:00:00:00:00\n"), 0644))

	_, err := getFirstPhysicalMAC(sysDir)
	assert.Error(t, err)
}

// makeOfNodeLink creates a /sys/class/net/{iface}/device/of_node symlink
// whose target string contains the given devicetree node path, mimicking
// the real sysfs layout without needing the target to actually exist.
func makeOfNodeLink(t *testing.T, sysDir, iface, dtNodePath string) {
	t.Helper()
	deviceDir := filepath.Join(sysDir, iface, "device")
	require.NoError(t, os.MkdirAll(deviceDir, 0755))
	require.NoError(t, os.Symlink(
		filepath.Join("../../../../firmware/devicetree/base", dtNodePath),
		filepath.Join(deviceDir, "of_node"),
	))
}

func TestGetBurnedInMAC_PrefersLabelMacDevice(t *testing.T) {
	sysDir := t.TempDir()
	dtBase := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dtBase, "aliases"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dtBase, "aliases", "label-mac-device"),
		[]byte("/soc/ethernet@15100000/mac@1\x00"), 0644))

	// eth0 is discovered first by directory order but is NOT the label MAC.
	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth0"), 0755))
	makeOfNodeLink(t, sysDir, "eth0", "/soc/ethernet@15100000/mac@0")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth0", "address"), []byte("94:83:c4:d4:ca:46\n"), 0644))

	// eth1 matches the label-mac-device alias.
	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth1"), 0755))
	makeOfNodeLink(t, sysDir, "eth1", "/soc/ethernet@15100000/mac@1")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth1", "address"), []byte("94:83:c4:d4:ca:48\n"), 0644))

	mac, err := getBurnedInMAC(sysDir, dtBase)
	require.NoError(t, err)
	assert.Equal(t, "94:83:c4:d4:ca:48", mac)
}

func TestGetBurnedInMAC_FallsBackWhenAliasAbsent(t *testing.T) {
	sysDir := t.TempDir()
	dtBase := t.TempDir() // no aliases directory at all

	eth0Dir := filepath.Join(sysDir, "eth0")
	require.NoError(t, os.MkdirAll(eth0Dir, 0755))
	require.NoError(t, os.Symlink("/sys/devices/platform/eth0", filepath.Join(eth0Dir, "device")))
	require.NoError(t, os.WriteFile(filepath.Join(eth0Dir, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0644))

	mac, err := getBurnedInMAC(sysDir, dtBase)
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
}

func TestGetBurnedInMAC_FallsBackWhenNoInterfaceMatchesAlias(t *testing.T) {
	sysDir := t.TempDir()
	dtBase := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dtBase, "aliases"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dtBase, "aliases", "label-mac-device"),
		[]byte("/soc/ethernet@15100000/mac@9\x00"), 0644)) // no interface has this node

	eth0Dir := filepath.Join(sysDir, "eth0")
	require.NoError(t, os.MkdirAll(eth0Dir, 0755))
	makeOfNodeLink(t, sysDir, "eth0", "/soc/ethernet@15100000/mac@0")
	require.NoError(t, os.WriteFile(filepath.Join(eth0Dir, "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0644))

	mac, err := getBurnedInMAC(sysDir, dtBase)
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
}

// TestGetBurnedInMAC_SharedOfNode reproduces the real GL.iNet GL-MT6000
// scenario: mtk_eth_soc registers both gmac0 and gmac1 as separate netdevs
// under one shared platform device, so both eth0 and eth1 report the parent
// controller node as their of_node -- neither matches the label-mac-device
// leaf node (mac@1) exactly. The label is resolved by falling back to the
// smallest same-OUI address among the interfaces sharing that ancestor node.
func TestGetBurnedInMAC_SharedOfNode(t *testing.T) {
	sysDir := t.TempDir()
	dtBase := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dtBase, "aliases"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dtBase, "aliases", "label-mac-device"),
		[]byte("/soc/ethernet@15100000/mac@1\x00"), 0644))

	// Both interfaces share the parent controller node as their of_node --
	// neither is the mac@1 leaf itself.
	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth0"), 0755))
	makeOfNodeLink(t, sysDir, "eth0", "/soc/ethernet@15100000")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth0", "address"), []byte("94:83:c4:d4:ca:48\n"), 0644))

	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth1"), 0755))
	makeOfNodeLink(t, sysDir, "eth1", "/soc/ethernet@15100000")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth1", "address"), []byte("94:83:c4:d4:ca:46\n"), 0644))

	mac, err := getBurnedInMAC(sysDir, dtBase)
	require.NoError(t, err)
	assert.Equal(t, "94:83:c4:d4:ca:46", mac)
}

func TestGetBurnedInMAC_RefusesMismatchedOUIFamily(t *testing.T) {
	sysDir := t.TempDir()
	dtBase := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(dtBase, "aliases"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(dtBase, "aliases", "label-mac-device"),
		[]byte("/soc/ethernet@15100000/mac@1\x00"), 0644))

	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth0"), 0755))
	makeOfNodeLink(t, sysDir, "eth0", "/soc/ethernet@15100000")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth0", "address"), []byte("94:83:c4:d4:ca:48\n"), 0644))

	// Different OUI entirely -- not a real per-port sibling, so the family
	// heuristic must refuse to guess rather than pick one arbitrarily.
	require.NoError(t, os.MkdirAll(filepath.Join(sysDir, "eth1"), 0755))
	makeOfNodeLink(t, sysDir, "eth1", "/soc/ethernet@15100000")
	require.NoError(t, os.WriteFile(filepath.Join(sysDir, "eth1", "address"), []byte("aa:bb:cc:dd:ee:ff\n"), 0644))

	// Falls all the way back to the plain first-physical-device scan.
	mac, err := getBurnedInMAC(sysDir, dtBase)
	require.NoError(t, err)
	assert.Equal(t, "94:83:c4:d4:ca:48", mac)
}

func TestGetFirstPhysicalMAC_MissingAddressFile(t *testing.T) {
	sysDir := t.TempDir()

	// physical interface – has device symlink but no address file → skip
	eth0Dir := filepath.Join(sysDir, "eth0")
	require.NoError(t, os.MkdirAll(eth0Dir, 0755))
	require.NoError(t, os.Symlink("/sys/devices/platform/eth0", filepath.Join(eth0Dir, "device")))
	// no address file written

	// second physical interface that does have an address
	eth1Dir := filepath.Join(sysDir, "eth1")
	require.NoError(t, os.MkdirAll(eth1Dir, 0755))
	require.NoError(t, os.Symlink("/sys/devices/platform/eth1", filepath.Join(eth1Dir, "device")))
	require.NoError(t, os.WriteFile(filepath.Join(eth1Dir, "address"), []byte("11:22:33:44:55:66\n"), 0644))

	mac, err := getFirstPhysicalMAC(sysDir)
	require.NoError(t, err)
	assert.Equal(t, "11:22:33:44:55:66", mac)
}
