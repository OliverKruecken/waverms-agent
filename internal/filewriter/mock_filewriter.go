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
type MockFileAccess struct {
	Calls      []WriteCall
	Errors     map[string]error
	ReadFiles  map[string][]byte
	ReadErrors map[string]error
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
