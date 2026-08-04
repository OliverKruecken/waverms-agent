// Package apply implements two-phase atomic UCI config apply for the WaveRMS agent.
package apply

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// Applier stages and commits a desired UCI config payload using a UCIRunner.
type Applier struct {
	runner uci.UCIRunner
}

// New creates an Applier backed by the given UCIRunner.
func New(runner uci.UCIRunner) *Applier {
	return &Applier{runner: runner}
}

// Apply applies the desired config payload in two phases:
//  1. Stage: run all UCI set/add/delete operations without committing.
//     On any staging error, revert all staged packages and return an error.
//  2. Commit: commit each staged package in order.
//
// Returns the list of committed package names so the caller can run service reloads.
func (a *Applier) Apply(payload json.RawMessage) ([]string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal config payload: %w", err)
	}

	// Collect UCI package names; skip meta-keys.
	var pkgNames []string
	pkgConfigs := make(map[string]map[string]json.RawMessage)
	for key, val := range raw {
		if key == "packages" || key == "reboot" {
			continue
		}
		var pkgCfg map[string]json.RawMessage
		if err := json.Unmarshal(val, &pkgCfg); err != nil {
			return nil, fmt.Errorf("unmarshal package config %q: %w", key, err)
		}
		pkgNames = append(pkgNames, key)
		pkgConfigs[key] = pkgCfg
	}
	sort.Strings(pkgNames)

	// Phase 1: stage all packages.
	staged := make([]string, 0, len(pkgNames))
	for _, pkg := range pkgNames {
		if err := a.stagePackage(pkg, pkgConfigs[pkg]); err != nil {
			// Revert everything staged so far (plus the partially-staged current package).
			for _, s := range staged {
				_ = a.runner.Revert(s)
			}
			_ = a.runner.Revert(pkg)
			return nil, fmt.Errorf("stage %s: %w", pkg, err)
		}
		staged = append(staged, pkg)
	}

	// Phase 2: commit each staged package.
	// On commit failure, revert this package and all remaining uncommitted
	// packages to prevent leaving the UCI transaction cache in a mixed state
	// (some packages committed, others still staged with unapplied changes).
	committed := make([]string, 0, len(staged))
	for i, pkg := range staged {
		if err := a.runner.Commit(pkg); err != nil {
			_ = a.runner.Revert(pkg)
			for _, remaining := range staged[i+1:] {
				_ = a.runner.Revert(remaining)
			}
			return committed, fmt.Errorf("commit %s: %w", pkg, err)
		}
		committed = append(committed, pkg)
	}
	return committed, nil
}

// stagePackage stages all UCI changes for one package without committing.
func (a *Applier) stagePackage(pkgName string, pkgCfg map[string]json.RawMessage) error {
	mode := "merge"
	if v, ok := pkgCfg[".mode"]; ok {
		_ = json.Unmarshal(v, &mode)
	}

	// Collect and sort section-type keys for deterministic ordering.
	// Firewall rules, DHCP pools, and other order-sensitive UCI sections
	// must be staged in the same sequence on every apply call; a random
	// map iteration order would otherwise produce different device configs.
	sectionTypes := make([]string, 0, len(pkgCfg))
	for k := range pkgCfg {
		if !strings.HasPrefix(k, ".") {
			sectionTypes = append(sectionTypes, k)
		}
	}
	sort.Strings(sectionTypes)

	parsedSections := make(map[string][]map[string]interface{}, len(sectionTypes))
	for _, sectionType := range sectionTypes {
		sections, err := parseSections(pkgCfg[sectionType])
		if err != nil {
			return fmt.Errorf("parse sections for type %q: %w", sectionType, err)
		}
		parsedSections[sectionType] = sections
	}

	if mode == "replace" {
		// Whole-package replace ("wipe + rewrite", docs/config-format.md): delete every
		// current section in the package — of ANY section type, not just the types this
		// payload happens to list — except named sections the payload keeps. Without this,
		// a section type the template never mentions (e.g. firewall.rule when only
		// firewall.defaults is templated) would survive untouched even under ".mode":"replace",
		// since the per-type loop below only ever visits types present in the payload.
		keepNames := make(map[string]bool)
		for _, sections := range parsedSections {
			for _, s := range sections {
				if name, ok := s[".name"].(string); ok {
					keepNames[name] = true
				}
			}
		}
		for _, existingType := range a.existingSectionTypes(pkgName) {
			if err := a.deleteUnwantedSections(pkgName, existingType, keepNames); err != nil {
				return err
			}
		}
	}

	for _, sectionType := range sectionTypes {
		sections := parsedSections[sectionType]

		// In merge mode, pre-fetch existing anonymous section IDs so we can
		// reuse them instead of always appending a new section via Add().
		// This prevents duplicate anonymous sections (e.g. config system) on
		// repeated apply calls.
		var existingAnonIDs []string
		if mode == "merge" {
			existingAnonIDs = a.listUnnamedSections(pkgName, sectionType)
		}

		anonIdx := 0
		for _, section := range sections {
			reuseID := ""
			if _, hasName := section[".name"].(string); !hasName {
				if anonIdx < len(existingAnonIDs) {
					reuseID = existingAnonIDs[anonIdx]
				}
				anonIdx++
			}
			if err := a.applySection(pkgName, sectionType, section, mode, reuseID); err != nil {
				return err
			}
		}
	}
	return nil
}

// showEntry is one parsed "id=value" line from `uci show <pkg>` output, with
// prefix already stripped from id.
type showEntry struct {
	id    string
	value string
}

// parseShowLines splits uci show output into entries whose line starts with
// prefix (stripped from id before returning). Lines without "=" are skipped.
func parseShowLines(out, prefix string) []showEntry {
	var entries []showEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		eqIdx := strings.Index(rest, "=")
		if eqIdx < 0 {
			continue
		}
		entries = append(entries, showEntry{id: rest[:eqIdx], value: strings.TrimSpace(rest[eqIdx+1:])})
	}
	return entries
}

// listUnnamedSections returns the @type[index] identifiers for all existing
// anonymous sections of sectionType in pkgName. Returns nil if the package
// doesn't exist yet or has no anonymous sections of that type.
func (a *Applier) listUnnamedSections(pkgName, sectionType string) []string {
	out, err := a.runner.Show(pkgName)
	if err != nil {
		return nil
	}
	var ids []string
	for _, entry := range parseShowLines(out, pkgName+".") {
		// Anonymous sections start with '@'; skip option lines (contain ".").
		if !strings.HasPrefix(entry.id, "@") || strings.Contains(entry.id, ".") {
			continue
		}
		if entry.value == sectionType {
			ids = append(ids, entry.id)
		}
	}
	return ids
}

// existingSectionTypes returns the distinct section types currently present in pkgName
// on the device (e.g. "rule", "zone", "defaults" for the firewall package), regardless
// of what the desired payload lists. Returns nil if the package doesn't exist yet.
func (a *Applier) existingSectionTypes(pkgName string) []string {
	out, err := a.runner.Show(pkgName)
	if err != nil {
		return nil
	}
	var types []string
	seen := make(map[string]bool)
	for _, entry := range parseShowLines(out, pkgName+".") {
		if strings.Contains(entry.id, ".") {
			continue // option line, not a section
		}
		if !seen[entry.value] {
			seen[entry.value] = true
			types = append(types, entry.value)
		}
	}
	return types
}

// deleteUnwantedSections deletes all current sections of sectionType in pkgName that are
// not listed in keepNames. Uses `uci show` to enumerate existing sections.
//
// Anonymous sections (@type[N]) are deleted in reverse index order so that earlier
// deletions do not shift the indices of sections still to be deleted.
func (a *Applier) deleteUnwantedSections(pkgName, sectionType string, keepNames map[string]bool) error {
	out, err := a.runner.Show(pkgName)
	if err != nil {
		// Package doesn't exist yet — nothing to delete.
		return nil
	}
	var toDelete []string
	for _, entry := range parseShowLines(out, pkgName+".") {
		// Skip option lines — they contain a "." in the id (e.g. "wan.proto").
		if strings.Contains(entry.id, ".") {
			continue
		}
		if entry.value != sectionType {
			continue
		}
		if !keepNames[entry.id] {
			toDelete = append(toDelete, entry.id)
		}
	}
	// Delete in reverse order: removing @type[0] would shift @type[1] → @type[0],
	// invalidating all subsequent index-based references. Deleting from the highest
	// index downward keeps lower indices stable throughout.
	for i := len(toDelete) - 1; i >= 0; i-- {
		if err := a.runner.Delete(pkgName, toDelete[i]); err != nil {
			return fmt.Errorf("delete %s.%s: %w", pkgName, toDelete[i], err)
		}
	}
	return nil
}

// applySection stages UCI changes for a single section instance.
// reuseID, when non-empty, is an existing @type[index] identifier that should
// be updated in place rather than creating a new anonymous section via Add().
func (a *Applier) applySection(pkgName, sectionType string, section map[string]interface{}, mode string, reuseID string) error {
	name, hasName := section[".name"].(string)

	var sectionID string
	if hasName {
		sectionID = name
		// SetType creates the section if it doesn't exist, or updates its type.
		// In replace mode the section was already deleted by deleteUnwantedSections.
		if err := a.runner.SetType(pkgName, sectionID, sectionType); err != nil {
			return fmt.Errorf("set type %s.%s=%s: %w", pkgName, sectionID, sectionType, err)
		}
	} else if reuseID != "" {
		// Reuse an existing anonymous section instead of appending a new one.
		sectionID = reuseID
	} else {
		id, err := a.runner.Add(pkgName, sectionType)
		if err != nil {
			return fmt.Errorf("add %s %s: %w", pkgName, sectionType, err)
		}
		sectionID = id
	}

	desiredKeys := make(map[string]bool)
	for key, val := range section {
		if strings.HasPrefix(key, ".") {
			continue
		}
		desiredKeys[key] = true
		switch v := val.(type) {
		case []interface{}:
			// List option: clear existing entries, then add each new value.
			_ = a.runner.DeleteOption(pkgName, sectionID, key)
			for _, item := range v {
				if err := a.runner.AddList(pkgName, sectionID, key, fmt.Sprintf("%v", item)); err != nil {
					return fmt.Errorf("add_list %s.%s.%s: %w", pkgName, sectionID, key, err)
				}
			}
		default:
			if err := a.runner.Set(pkgName, sectionID, key, fmt.Sprintf("%v", val)); err != nil {
				return fmt.Errorf("set %s.%s.%s: %w", pkgName, sectionID, key, err)
			}
		}
	}

	// For named sections or reused anonymous sections: remove options present on the
	// device but absent from desired. This gives exact-match semantics for the section
	// content while package-level merge still leaves unmentioned sections untouched.
	// Newly-created anonymous sections (reuseID=="") have no prior options to clean.
	if hasName || reuseID != "" {
		if err := a.cleanStaleOptions(pkgName, sectionID, desiredKeys); err != nil {
			return err
		}
	}
	return nil
}

// cleanStaleOptions deletes UCI options that exist on the device for the given named
// section but are not present in the desired config. Uses the existing Show() output.
func (a *Applier) cleanStaleOptions(pkgName, sectionID string, desiredKeys map[string]bool) error {
	out, err := a.runner.Show(pkgName)
	if err != nil {
		return nil // package not committed yet — nothing to clean
	}
	for _, entry := range parseShowLines(out, pkgName+"."+sectionID+".") {
		optKey := entry.id
		// Skip dot-prefixed meta-keys and nested paths (sub-option lines).
		if strings.HasPrefix(optKey, ".") || strings.Contains(optKey, ".") {
			continue
		}
		if !desiredKeys[optKey] {
			if err := a.runner.DeleteOption(pkgName, sectionID, optKey); err != nil {
				return fmt.Errorf("delete stale option %s.%s.%s: %w", pkgName, sectionID, optKey, err)
			}
		}
	}
	return nil
}

// parseSections unmarshals a JSON value that is either a single object or an array of objects.
func parseSections(raw json.RawMessage) ([]map[string]interface{}, error) {
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var single map[string]interface{}
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	return []map[string]interface{}{single}, nil
}
