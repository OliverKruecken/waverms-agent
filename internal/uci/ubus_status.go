package uci

import (
	"errors"
	"os/exec"
)

// ubusStatusNotFoundExitCode is the process exit code the `ubus` CLI produces
// for UBUS_STATUS_NOT_FOUND, one of the fixed status codes ubus core itself
// defines (libubus/ubus.h) — not rpcd-specific. UBUS_STATUS_NOT_FOUND's own
// numeric value is 4, but the CLI does not exit with that raw value: on real
// hardware it exits 252 instead. This was confirmed directly from a live
// device's failed host_key_fetch/config_apply command results (every
// candidate host-key filename, and a "commit" for a package with nothing
// staged, all failed with "exit status 252") — not from documentation, which
// had assumed 4 and was wrong.
const ubusStatusNotFoundExitCode = 252

// IsNotFound reports whether err represents a `ubus call` process exiting
// with UBUS_STATUS_NOT_FOUND specifically, as opposed to any other invocation
// failure (rpcd unreachable, timeout, permission denied, malformed args, ...).
// Shared by internal/filewriter (file read/stat: "file absent") and
// RealUCIRunner.Commit (nothing staged for a package is a legitimate no-op).
func IsNotFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == ubusStatusNotFoundExitCode
}
