package uci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePackageFile_CreatesMissingPackage(t *testing.T) {
	dir := t.TempDir()
	if err := EnsurePackageFile(dir, "luci"); err != nil {
		t.Fatalf("EnsurePackageFile: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "luci"))
	if err != nil {
		t.Fatalf("package file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("new package file should be empty, size = %d", info.Size())
	}
}

func TestEnsurePackageFile_LeavesExistingPackageUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network")
	if err := os.WriteFile(path, []byte("config interface 'lan'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePackageFile(dir, "network"); err != nil {
		t.Fatalf("EnsurePackageFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "config interface 'lan'\n" {
		t.Errorf("existing package was modified: %q", got)
	}
}

func TestEnsurePackageFile_RejectsUnsafeNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "../evil", "a/b", "usteer.apk-new", "net work", "/etc/passwd"} {
		if err := EnsurePackageFile(dir, name); err == nil {
			t.Errorf("EnsurePackageFile(%q) = nil, want error", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("rejected names must not create files, found %d", len(entries))
	}
}

func TestEnsurePackageFile_MissingDirectory(t *testing.T) {
	if err := EnsurePackageFile(filepath.Join(t.TempDir(), "nope"), "luci"); err == nil {
		t.Error("want error when the config directory doesn't exist")
	}
}

func TestMockUCIRunner_EnsurePackage(t *testing.T) {
	m := &MockUCIRunner{}
	if err := m.EnsurePackage("luci"); err != nil {
		t.Fatal(err)
	}
	if len(m.Calls) != 1 || m.Calls[0] != "ensure luci" {
		t.Errorf("Calls = %v, want [ensure luci]", m.Calls)
	}
}
