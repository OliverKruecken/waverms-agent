package filewriter

import "os"

// WriteCall records a single call to MockFileAccess.WriteFile.
type WriteCall struct {
	Path    string
	Content []byte
	Perm    os.FileMode
}

// MockFileAccess records all WriteFile calls and can inject errors per path.
// ReadFiles maps path → content for ReadFile responses.
// ReadErrors maps path → error for ReadFile error injection.
// Errors maps path → error for WriteFile error injection.
// RemoveErrors maps path → error for Remove error injection.
// ExistsPaths maps path → return value for Exists (absent path defaults to false).
// ListDirs maps path → entries for ListDir responses; ListDirErrors maps path → error.
type MockFileAccess struct {
	Calls         []WriteCall
	Errors        map[string]error
	ReadFiles     map[string][]byte
	ReadErrors    map[string]error
	RemoveCalls   []string
	RemoveErrors  map[string]error
	ExistsPaths   map[string]bool
	ListDirs      map[string][]DirEntry
	ListDirErrors map[string]error
}

// WriteFile records the call and returns any injected error for path.
func (m *MockFileAccess) WriteFile(path string, content []byte, perm os.FileMode) error {
	m.Calls = append(m.Calls, WriteCall{Path: path, Content: content, Perm: perm})
	if m.Errors != nil {
		if err, ok := m.Errors[path]; ok {
			return err
		}
	}
	return nil
}

// ReadFile returns the injected content for path, or os.ErrNotExist if not configured.
func (m *MockFileAccess) ReadFile(path string) ([]byte, error) {
	if m.ReadErrors != nil {
		if err, ok := m.ReadErrors[path]; ok {
			return nil, err
		}
	}
	if m.ReadFiles != nil {
		if content, ok := m.ReadFiles[path]; ok {
			return content, nil
		}
	}
	return nil, os.ErrNotExist
}

// Remove records the call and returns any injected error for path. Matches
// OSFileAccess's "missing path is success" contract by default.
func (m *MockFileAccess) Remove(path string) error {
	m.RemoveCalls = append(m.RemoveCalls, path)
	if m.RemoveErrors != nil {
		if err, ok := m.RemoveErrors[path]; ok {
			return err
		}
	}
	return nil
}

// Exists returns the injected value for path (or false if not configured),
// and never an error — MockFileAccess has no notion of a failed existence
// check distinct from "doesn't exist" (see OSFileAccess for that distinction
// against a real device).
func (m *MockFileAccess) Exists(path string) (bool, error) {
	if m.ExistsPaths == nil {
		return false, nil
	}
	return m.ExistsPaths[path], nil
}

// ListDir returns the injected entries for path, or an empty list if not configured.
func (m *MockFileAccess) ListDir(path string) ([]DirEntry, error) {
	if m.ListDirErrors != nil {
		if err, ok := m.ListDirErrors[path]; ok {
			return nil, err
		}
	}
	return m.ListDirs[path], nil
}
