package uci

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exitErrorWithCode runs a trivial shell command that exits with code,
// returning the resulting *exec.ExitError — the same concrete error type a
// real `ubus` invocation produces on failure, so IsNotFound's errors.As check
// exercises the real type rather than an opaque sentinel.
func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	require.Error(t, err)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, code, exitErr.ExitCode())
	return err
}

func TestIsNotFound_ExitCode252IsNotFound(t *testing.T) {
	// The real ubus CLI's observed exit code for UBUS_STATUS_NOT_FOUND —
	// see ubus_status.go's doc comment for how this was confirmed.
	assert.True(t, IsNotFound(exitErrorWithCode(t, 252)))
}

func TestIsNotFound_RawStatusValueIsNotMisidentified(t *testing.T) {
	// UBUS_STATUS_NOT_FOUND's raw numeric value (4) is NOT the CLI's exit
	// code — this guards against reintroducing that wrong assumption.
	assert.False(t, IsNotFound(exitErrorWithCode(t, 4)))
}

func TestIsNotFound_OtherExitCodeIsNotMisreported(t *testing.T) {
	// e.g. UBUS_STATUS_PERMISSION_DENIED or any other failure must not be
	// misreported as "not found".
	assert.False(t, IsNotFound(exitErrorWithCode(t, 6)))
}

func TestIsNotFound_NonExitError(t *testing.T) {
	assert.False(t, IsNotFound(assert.AnError))
	assert.False(t, IsNotFound(nil))
}
