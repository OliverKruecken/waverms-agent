// Package filewriter provides the FileAccess interface and implementations for
// reading and writing files on the device filesystem.
package filewriter

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileAccess abstracts filesystem reads and writes so that command handlers
// can be tested without touching the real filesystem.
type FileAccess interface {
	WriteFile(path string, content []byte, perm os.FileMode) error
	ReadFile(path string) ([]byte, error)
}

// OSFileAccess is the production implementation backed by os.WriteFile / os.ReadFile.
type OSFileAccess struct{}

// WriteFile creates all parent directories (with mode 0755) and then writes
// content to path with the given permission bits. This ensures that paths like
// /etc/dropbear/authorized_keys succeed even when the parent directory does not
// yet exist on the device.
func (w *OSFileAccess) WriteFile(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return os.WriteFile(path, content, perm)
}

// ReadFile returns the contents of path, or an error (including os.ErrNotExist
// when the file does not exist).
func (w *OSFileAccess) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
