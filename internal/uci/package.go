package uci

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// configDir is where UCI keeps its package files on OpenWrt.
const configDir = "/etc/config"

// packageNameRe matches a valid UCI package name. It is also what keeps a name
// taken from a payload from escaping the config directory.
var packageNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// EnsurePackageFile creates an empty UCI package file dir/pkg if it doesn't
// exist yet; an existing file is left untouched. libuci (and so both the
// `uci` CLI and rpcd's uci ubus object) refuses to add a section to a package
// that has no file — "uci: Entry not found", ubus exit status 252 — so a
// package the device doesn't ship (e.g. luci on an image without LuCI) has to
// be created before anything can be staged into it.
func EnsurePackageFile(dir, pkg string) error {
	if !packageNameRe.MatchString(pkg) {
		return fmt.Errorf("invalid UCI package name %q", pkg)
	}
	f, err := os.OpenFile(filepath.Join(dir, pkg), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("create package %s: %w", pkg, err)
	}
	return f.Close()
}
