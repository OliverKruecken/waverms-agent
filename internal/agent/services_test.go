package agent

import (
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/filewriter"
	"github.com/OliverKruecken/waverms-agent/internal/uci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const initdDir = "/etc/init.d"

func initdEntries(names ...string) []filewriter.DirEntry {
	entries := make([]filewriter.DirEntry, 0, len(names))
	for _, n := range names {
		entries = append(entries, filewriter.DirEntry{Name: n, IsRegular: true})
	}
	return entries
}

func rcdEntry(name string) filewriter.DirEntry {
	return filewriter.DirEntry{Name: name, IsSymlink: true}
}

func ubusServiceListResult(body string) *uci.MockUCIRunner {
	return &uci.MockUCIRunner{
		Results: map[string]string{
			`cmd ubus call service list {"verbose":true}`: body,
		},
	}
}

func TestDiscoverServices_ReturnsEnabledAndRunningState(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("sshd", "uhttpd"),
			rcdDir:   {rcdEntry("S50sshd"), rcdEntry("K90uhttpd")},
		},
	}
	runner := ubusServiceListResult(`{"sshd":{"instances":{"instance1":{"running":true}}},"uhttpd":{"instances":{"instance1":{"running":false}}}}`)

	services := discoverServices(fw, runner, initdDir)

	byName := make(map[string]ServiceInfo)
	for _, s := range services {
		byName[s.Name] = s
	}

	require.Contains(t, byName, "sshd")
	assert.True(t, byName["sshd"].Enabled)
	assert.True(t, byName["sshd"].Running)

	require.Contains(t, byName, "uhttpd")
	assert.False(t, byName["uhttpd"].Enabled)
	assert.False(t, byName["uhttpd"].Running)
}

func TestDiscoverServices_PresentInRcdOnly(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("cron"),
			rcdDir:   {rcdEntry("S99cron")},
		},
	}
	runner := ubusServiceListResult(`{}`)

	services := discoverServices(fw, runner, initdDir)

	require.Len(t, services, 1)
	assert.True(t, services[0].Enabled)
	assert.False(t, services[0].Running)
}

func TestDiscoverServices_PresentInUbusOnly(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("usteer"),
			rcdDir:   {},
		},
	}
	runner := ubusServiceListResult(`{"usteer":{"instances":{"instance1":{"running":true}}}}`)

	services := discoverServices(fw, runner, initdDir)

	require.Len(t, services, 1)
	assert.False(t, services[0].Enabled)
	assert.True(t, services[0].Running)
}

func TestDiscoverServices_MalformedUbusJSON_RunningFalseButEnabledStillCorrect(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("sshd"),
			rcdDir:   {rcdEntry("S50sshd")},
		},
	}
	runner := ubusServiceListResult(`not json`)

	services := discoverServices(fw, runner, initdDir)

	require.Len(t, services, 1)
	assert.True(t, services[0].Enabled)
	assert.False(t, services[0].Running)
}

func TestDiscoverServices_UbusExecError_DegradesRunningOnly(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("sshd"),
			rcdDir:   {rcdEntry("S50sshd")},
		},
	}
	runner := &uci.MockUCIRunner{
		Errors: map[string]error{
			`cmd ubus call service list {"verbose":true}`: assert.AnError,
		},
	}

	services := discoverServices(fw, runner, initdDir)

	require.Len(t, services, 1)
	assert.True(t, services[0].Enabled)
	assert.False(t, services[0].Running)
}

func TestDiscoverServices_RcdSymlinkExactMatch_NoPrefixFalsePositive(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirs: map[string][]filewriter.DirEntry{
			initdDir: initdEntries("dnsmasq", "dnsmasq-full"),
			rcdDir:   {rcdEntry("S50dnsmasq-full")},
		},
	}
	runner := ubusServiceListResult(`{}`)

	services := discoverServices(fw, runner, initdDir)

	byName := make(map[string]ServiceInfo)
	for _, s := range services {
		byName[s.Name] = s
	}

	assert.False(t, byName["dnsmasq"].Enabled, "a dnsmasq-full symlink must not enable dnsmasq")
	assert.True(t, byName["dnsmasq-full"].Enabled)
}

func TestDiscoverServices_InitdDirUnreadable_ReturnsNil(t *testing.T) {
	fw := &filewriter.MockFileAccess{
		ListDirErrors: map[string]error{initdDir: assert.AnError},
	}

	services := discoverServices(fw, &uci.MockUCIRunner{}, initdDir)

	assert.Nil(t, services)
}

func TestParseUbusServiceRunning(t *testing.T) {
	t.Run("no instances is not running", func(t *testing.T) {
		result := parseUbusServiceRunning([]byte(`{"cron":{}}`))
		assert.False(t, result["cron"])
	})

	t.Run("any running instance marks the service running", func(t *testing.T) {
		result := parseUbusServiceRunning([]byte(`{"wpad":{"instances":{"hostapd":{"running":false},"supplicant":{"running":true}}}}`))
		assert.True(t, result["wpad"])
	})

	t.Run("malformed JSON yields empty map", func(t *testing.T) {
		result := parseUbusServiceRunning([]byte(`not json`))
		assert.Empty(t, result)
	})
}

func TestRcdEnabledSet(t *testing.T) {
	t.Run("K without S is not enabled", func(t *testing.T) {
		result := rcdEnabledSet([]filewriter.DirEntry{rcdEntry("K90dropbear")})
		assert.False(t, result["dropbear"])
	})

	t.Run("S entry marks enabled", func(t *testing.T) {
		result := rcdEnabledSet([]filewriter.DirEntry{rcdEntry("S50dnsmasq")})
		assert.True(t, result["dnsmasq"])
	})

	t.Run("non-symlink non-regular entries are ignored", func(t *testing.T) {
		result := rcdEnabledSet([]filewriter.DirEntry{{Name: "S50dnsmasq"}})
		assert.False(t, result["dnsmasq"])
	})
}
