package agent

import (
	"fmt"
	"os"
	"strings"
)

// PasswordSetter abstracts the system call for updating a user's password so
// that the set_password command handler can be tested without touching the real
// shadow database.
type PasswordSetter interface {
	SetPassword(user, hash string) error
}

const shadowPath = "/etc/shadow"

// OSPasswordSetter is the production implementation. It updates /etc/shadow
// directly in Go — no dependency on chpasswd, passwd, or openssl.
// The write is atomic: a temp file is written first, then renamed over shadow.
type OSPasswordSetter struct{}

func (p *OSPasswordSetter) SetPassword(user, hash string) error {
	data, err := os.ReadFile(shadowPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", shadowPath, err)
	}

	info, err := os.Stat(shadowPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", shadowPath, err)
	}

	lines := strings.Split(string(data), "\n")
	found := false
	prefix := user + ":"
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			fields := strings.SplitN(line, ":", 9)
			if len(fields) < 2 {
				return fmt.Errorf("malformed shadow entry for %s", user)
			}
			fields[1] = hash
			lines[i] = strings.Join(fields, ":")
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("user %s not found in %s", user, shadowPath)
	}

	tmp := shadowPath + ".new"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), info.Mode()); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, shadowPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", shadowPath, err)
	}
	return nil
}

// MockPasswordSetter records calls and returns a configurable error.
type MockPasswordSetter struct {
	Calls []string
	Err   error
}

func (m *MockPasswordSetter) SetPassword(user, hash string) error {
	m.Calls = append(m.Calls, fmt.Sprintf("set_password %s", user))
	return m.Err
}
