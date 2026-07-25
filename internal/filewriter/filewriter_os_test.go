package filewriter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSFileAccess_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	w := &OSFileAccess{}
	err := w.WriteFile(path, []byte("hello"), 0600)
	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
}

func TestOSFileAccess_CreatesParentDirectories(t *testing.T) {
	// The parent directories do not exist yet — OSFileAccess must create them.
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "file.txt")

	w := &OSFileAccess{}
	err := w.WriteFile(path, []byte("data"), 0600)
	require.NoError(t, err, "WriteFile should succeed even when parent dirs are missing")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

func TestOSFileAccess_RespectsFilePermission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")

	w := &OSFileAccess{}
	require.NoError(t, w.WriteFile(path, []byte("s3cr3t"), 0600))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestOSFileAccess_ReadFile_ReturnsContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(path, []byte("binary\x00data"), 0600))

	w := &OSFileAccess{}
	got, err := w.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("binary\x00data"), got)
}

func TestOSFileAccess_ReadFile_MissingFileReturnsNotExist(t *testing.T) {
	w := &OSFileAccess{}
	_, err := w.ReadFile("/nonexistent/path/key")
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}