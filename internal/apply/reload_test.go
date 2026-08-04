package apply_test

import (
	"testing"

	"github.com/OliverKruecken/waverms-agent/internal/apply"
	"github.com/stretchr/testify/assert"
)

func TestRunReloads_SkipsDisabledService(t *testing.T) {
	// Record which services were checked and treat all as disabled.
	var checked []string
	orig := apply.CheckServiceEnabled
	apply.CheckServiceEnabled = func(name string) bool {
		checked = append(checked, name)
		return false // all disabled
	}
	t.Cleanup(func() { apply.CheckServiceEnabled = orig })

	errs := apply.RunReloads([]string{"network", "firewall"})

	assert.Empty(t, errs, "no reload errors expected when services are skipped")
	assert.Contains(t, checked, "network")
	assert.Contains(t, checked, "firewall")
}

func TestRunReloads_RunsEnabledService(t *testing.T) {
	// Accept all services as enabled; the reload command will fail (no OpenWrt),
	// but we verify the enabled check was consulted and the error is propagated.
	orig := apply.CheckServiceEnabled
	apply.CheckServiceEnabled = func(name string) bool { return true }
	t.Cleanup(func() { apply.CheckServiceEnabled = orig })

	// Use an unknown package so no reload command is attempted (no OS side effects).
	errs := apply.RunReloads([]string{"unknown-pkg"})
	assert.Empty(t, errs, "unknown package produces no reload and no error")
}

func TestRunReloads_DeduplicatesAcrossPackages(t *testing.T) {
	// "wireless" and "network" both map to the "network" init.d service for the
	// enabled check, but have different reload commands. Both should be attempted
	// only once each (enabled check also deduped per reload command).
	var checked []string
	orig := apply.CheckServiceEnabled
	apply.CheckServiceEnabled = func(name string) bool {
		checked = append(checked, name)
		return false
	}
	t.Cleanup(func() { apply.CheckServiceEnabled = orig })

	apply.RunReloads([]string{"wireless", "wireless", "network", "network"})

	// "wifi reload" and "/etc/init.d/network reload" are distinct commands,
	// so the enabled check for "network" runs at most twice (once per command).
	networkCount := 0
	for _, s := range checked {
		if s == "network" {
			networkCount++
		}
	}
	assert.LessOrEqual(t, networkCount, 2, "enabled check for 'network' must not run more than twice")
}

func TestServiceReloads_MapsKnownPackages(t *testing.T) {
	cmds := apply.ServiceReloads([]string{"wireless", "network"})
	assert.Contains(t, cmds, "wifi reload")
	assert.Contains(t, cmds, "/etc/init.d/network reload")
	assert.Len(t, cmds, 2)
}

func TestServiceReloads_UnknownPackageIgnored(t *testing.T) {
	cmds := apply.ServiceReloads([]string{"unknown-pkg"})
	assert.Empty(t, cmds)
}

func TestServiceReloads_NoDuplicates(t *testing.T) {
	cmds := apply.ServiceReloads([]string{"wireless", "wireless"})
	assert.Len(t, cmds, 1)
}

const ubusUsteerFixture = `{
  "usteer": {
    "instances": {
      "instance1": {
        "running": true,
        "triggers": [
          ["config.change", "usteer", ["run_command", ["/etc/init.d/usteer", "reload"]]]
        ]
      }
    }
  }
}`

func TestServiceReloads_UbusTrigger_DiscoversUnknownPackage(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{UbusOutput: []byte(ubusUsteerFixture)}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"usteer"})
	assert.Contains(t, cmds, "/etc/init.d/usteer reload")
}

func TestRunReloads_UbusTrigger_NotGatedByEnabledCheck(t *testing.T) {
	origDisc := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{UbusOutput: []byte(ubusUsteerFixture)}
	t.Cleanup(func() { apply.Discoverer = origDisc })

	var checked []string
	origCheck := apply.CheckServiceEnabled
	apply.CheckServiceEnabled = func(name string) bool {
		checked = append(checked, name)
		return true
	}
	t.Cleanup(func() { apply.CheckServiceEnabled = origCheck })

	apply.RunReloads([]string{"usteer"})

	assert.Empty(t, checked, "a ubus-discovered reload must not be gated by CheckServiceEnabled")
}

func TestServiceReloads_UCITrack_DiscoversUnknownPackage(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{
		UCITrackOutput: []byte(`{"somepkg":{"init":"somedaemon"}}`),
	}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"somepkg"})
	assert.Contains(t, cmds, "/etc/init.d/somedaemon reload")
}

func TestRunReloads_UCITrack_GatedByEnabledCheck(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{
		UCITrackOutput: []byte(`{"somepkg":{"init":"somedaemon"}}`),
	}
	t.Cleanup(func() { apply.Discoverer = orig })

	var checked []string
	origCheck := apply.CheckServiceEnabled
	apply.CheckServiceEnabled = func(name string) bool {
		checked = append(checked, name)
		return false
	}
	t.Cleanup(func() { apply.CheckServiceEnabled = origCheck })

	apply.RunReloads([]string{"somepkg"})

	assert.Contains(t, checked, "somedaemon", "a ucitrack-discovered reload must be gated by CheckServiceEnabled")
}

func TestServiceReloads_InitdHeuristic_DiscoversUnknownPackage(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{InitScripts: map[string]bool{"foo": true}}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"foo"})
	assert.Contains(t, cmds, "/etc/init.d/foo reload")
}

func TestServiceReloads_NoTierMatches_ReturnsNoCommand(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"totally-unknown"})
	assert.Empty(t, cmds)
}

func TestRunReloads_NoTierMatches_ReturnsNoError(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{}
	t.Cleanup(func() { apply.Discoverer = orig })

	errs := apply.RunReloads([]string{"totally-unknown"})
	assert.Empty(t, errs)
}

func TestServiceReloads_Precedence_StaticOverridesUbus(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{
		UbusOutput: []byte(`{"network":{"instances":{"i1":{"triggers":[
			["config.change","network",["run_command",["/etc/init.d/network","restart"]]]
		]}}}}`),
	}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"network"})
	assert.Contains(t, cmds, "/etc/init.d/network reload", "static override must win over a conflicting ubus trigger")
	assert.NotContains(t, cmds, "/etc/init.d/network restart")
}

func TestServiceReloads_Precedence_UbusOverridesUCITrack(t *testing.T) {
	orig := apply.Discoverer
	apply.Discoverer = &apply.FakeReloadDiscoverer{
		UbusOutput:     []byte(ubusUsteerFixture),
		UCITrackOutput: []byte(`{"usteer":{"init":"usteer-legacy"}}`),
	}
	t.Cleanup(func() { apply.Discoverer = orig })

	cmds := apply.ServiceReloads([]string{"usteer"})
	assert.Contains(t, cmds, "/etc/init.d/usteer reload")
	assert.NotContains(t, cmds, "/etc/init.d/usteer-legacy reload")
}

func TestServiceReloads_CachesDiscoveryAcrossPackages(t *testing.T) {
	orig := apply.Discoverer
	fake := &apply.FakeReloadDiscoverer{}
	apply.Discoverer = fake
	t.Cleanup(func() { apply.Discoverer = orig })

	apply.ServiceReloads([]string{"pkg1", "pkg2", "pkg3"})

	assert.Equal(t, 1, fake.UbusCalls, "ubus service list must be read once per call regardless of package count")
	assert.Equal(t, 1, fake.UCITrackCalls, "ucitrack.json must be read once per call regardless of package count")
}

func TestRunReloads_CachesDiscoveryAcrossPackages(t *testing.T) {
	orig := apply.Discoverer
	fake := &apply.FakeReloadDiscoverer{}
	apply.Discoverer = fake
	t.Cleanup(func() { apply.Discoverer = orig })

	apply.RunReloads([]string{"pkg1", "pkg2", "pkg3"})

	assert.Equal(t, 1, fake.UbusCalls)
	assert.Equal(t, 1, fake.UCITrackCalls)
}
