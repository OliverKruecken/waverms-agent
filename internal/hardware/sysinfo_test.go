package hardware

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeReleaseFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "openwrt_release")
	require.NoError(t, os.WriteFile(f, []byte(contents), 0644))
	return f
}

func TestGetOpenWrtVersion_ParsesRelease(t *testing.T) {
	f := writeReleaseFile(t, `
DISTRIB_ID="OpenWrt"
DISTRIB_RELEASE="23.05.3"
DISTRIB_REVISION="r23809-234f1a2efa"
DISTRIB_TARGET="ath79/generic"
`)
	assert.Equal(t, "23.05.3", getOpenWrtVersion(f))
}

func TestGetOpenWrtVersion_MissingFile(t *testing.T) {
	assert.Equal(t, "unknown", getOpenWrtVersion("/nonexistent/path"))
}

func TestGetOpenWrtVersion_MissingField(t *testing.T) {
	f := writeReleaseFile(t, "DISTRIB_ID=\"OpenWrt\"\n")
	assert.Equal(t, "unknown", getOpenWrtVersion(f))
}

func TestGetTarget_ParsesRelease(t *testing.T) {
	f := writeReleaseFile(t, `
DISTRIB_ID="OpenWrt"
DISTRIB_RELEASE="23.05.3"
DISTRIB_TARGET="ath79/generic"
`)
	assert.Equal(t, "ath79/generic", getTarget(f))
}

func TestGetTarget_MissingFile(t *testing.T) {
	assert.Equal(t, "unknown", getTarget("/nonexistent/path"))
}

func TestGetTarget_MissingField(t *testing.T) {
	f := writeReleaseFile(t, "DISTRIB_ID=\"OpenWrt\"\n")
	assert.Equal(t, "unknown", getTarget(f))
}

func TestGetVersionCode_ParsesRelease(t *testing.T) {
	f := writeReleaseFile(t, `
DISTRIB_ID="OpenWrt"
DISTRIB_RELEASE="23.05.3"
DISTRIB_REVISION="r23809-234f1a2efa"
`)
	assert.Equal(t, "r23809-234f1a2efa", getVersionCode(f))
}

func TestGetVersionCode_MissingFile(t *testing.T) {
	assert.Equal(t, "unknown", getVersionCode("/nonexistent/path"))
}

func TestGetVersionCode_MissingField(t *testing.T) {
	f := writeReleaseFile(t, "DISTRIB_ID=\"OpenWrt\"\n")
	assert.Equal(t, "unknown", getVersionCode(f))
}

func TestGetModel_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "model")
	require.NoError(t, os.WriteFile(f, []byte("GL.iNet GL-MT3000\n"), 0644))
	assert.Equal(t, "GL.iNet GL-MT3000", getModel(f))
}

func TestGetModel_MissingFile(t *testing.T) {
	assert.Equal(t, "unknown", getModel("/nonexistent/path"))
}

func TestGetBoardName_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "board_name")
	require.NoError(t, os.WriteFile(f, []byte("8dev_carambola2\n"), 0644))
	assert.Equal(t, "8dev_carambola2", getBoardName(f))
}

func TestGetBoardName_MissingFile(t *testing.T) {
	assert.Equal(t, "unknown", getBoardName("/nonexistent/path"))
}

func TestGetBoardName_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "board_name")
	require.NoError(t, os.WriteFile(f, []byte("\n"), 0644))
	assert.Equal(t, "unknown", getBoardName(f))
}
