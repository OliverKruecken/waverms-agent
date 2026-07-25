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
