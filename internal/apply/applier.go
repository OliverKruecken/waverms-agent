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

	// Fetch the package's current on-device sections once; every helper below
	// reads from this snapshot instead of re-fetching (the old Show()-based
	// code re-fetched and re-parsed the same package once per section type,
	// per existing type, and per section touched). A fetch error (package
	// doesn't exist yet) is treated as "no sections" — the same contract
	// Show()/Export() had.
	existing, err := a.runner.GetSections(pkgName)
	if err != nil {
		existing = nil
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
		for _, existingType := range existingSectionTypes(existing) {
			if err := a.deleteUnwantedSections(pkgName, existing, existingType, keepNames); err != nil {
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
			existingAnonIDs = anonymousSectionIDs(existing, sectionType)
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
			if err := a.applySection(pkgName, sectionType, section, existing, reuseID); err != nil {
				return err
			}
		}
	}
	return nil
}

// existingSectionTypes returns the distinct section types currently present
// in sections, regardless of what the desired payload lists.
func existingSectionTypes(sections []uci.Section) []string {
	var types []string
	seen := make(map[string]bool)
	for _, s := range sections {
		if !seen[s.Type] {
			seen[s.Type] = true
			types = append(types, s.Type)
		}
	}
	return types
}

// anonymousSectionIDs returns the ids of every anonymous section of
// sectionType, in on-device order.
func anonymousSectionIDs(sections []uci.Section, sectionType string) []string {
	var ids []string
	for _, s := range sections {
		if s.Anonymous && s.Type == sectionType {
			ids = append(ids, s.ID)
		}
	}
	return ids
}

// deleteUnwantedSections deletes every current section of sectionType not listed in keepNames.
// Sections carry their real UCI id (name, or a stable cfgXXXXXX for anonymous sections), which
// never shifts when a sibling section is deleted — unlike the CLI's positional @type[N]
// addressing, deletion order here doesn't matter.
func (a *Applier) deleteUnwantedSections(pkgName string, sections []uci.Section, sectionType string, keepNames map[string]bool) error {
	for _, s := range sections {
		if s.Type != sectionType {
			continue
		}
		if !s.Anonymous && keepNames[s.Name] {
			continue
		}
		if err := a.runner.Delete(pkgName, s.ID); err != nil {
			return fmt.Errorf("delete %s.%s: %w", pkgName, s.ID, err)
		}
	}
	return nil
}

// applySection stages UCI changes for a single section instance.
// existing is the package's prefetched on-device snapshot (see stagePackage).
// reuseID, when non-empty, is an existing anonymous section id that should be
// updated in place rather than creating a new one via Add().
func (a *Applier) applySection(pkgName, sectionType string, section map[string]interface{}, existing []uci.Section, reuseID string) error {
	name, hasName := section[".name"].(string)

	var sectionID string
	var existingSec *uci.Section
	switch {
	case hasName:
		sectionID = name
		existingSec = uci.FindSectionByName(existing, name)
		if err := uci.CreateOrRetype(a.runner, pkgName, sectionID, sectionType, existingSec); err != nil {
			return err
		}
	case reuseID != "":
		// Reuse an existing anonymous section instead of appending a new one.
		sectionID = reuseID
		existingSec = uci.FindSectionByID(existing, reuseID)
	default:
		id, err := a.runner.Add(pkgName, sectionType, "")
		if err != nil {
			return fmt.Errorf("add %s %s: %w", pkgName, sectionType, err)
		}
		sectionID = id
	}

	values := make(map[string]interface{}, len(section))
	desiredKeys := make(map[string]bool, len(section))
	for key, val := range section {
		if strings.HasPrefix(key, ".") {
			continue
		}
		desiredKeys[key] = true
		switch v := val.(type) {
		case []interface{}:
			// A UCI list option: the full desired list replaces whatever the
			// section currently has in one batched call, no separate clear step.
			list := make([]string, len(v))
			for i, item := range v {
				list[i] = fmt.Sprintf("%v", item)
			}
			values[key] = list
		default:
			values[key] = fmt.Sprintf("%v", val)
		}
	}
	if len(values) > 0 {
		if err := a.runner.SetValues(pkgName, sectionID, values); err != nil {
			return fmt.Errorf("set values %s.%s: %w", pkgName, sectionID, err)
		}
	}

	// For named sections or reused anonymous sections: remove options present on the
	// device but absent from desired. This gives exact-match semantics for the section
	// content while package-level merge still leaves unmentioned sections untouched.
	// Newly-created sections (existingSec==nil) have no prior options to clean.
	if hasName || reuseID != "" {
		if err := a.cleanStaleOptions(pkgName, sectionID, existingSec, desiredKeys); err != nil {
			return err
		}
	}
	return nil
}

// cleanStaleOptions deletes options that exist on the device for the given section but are not
// present in the desired config, using the already-fetched snapshot rather than a fresh read.
func (a *Applier) cleanStaleOptions(pkgName, sectionID string, existingSec *uci.Section, desiredKeys map[string]bool) error {
	if existingSec == nil {
		return nil // freshly created section — nothing to clean
	}
	var stale []string
	for opt := range existingSec.Options {
		if !desiredKeys[opt] {
			stale = append(stale, opt)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale) // deterministic call order
	if err := a.runner.DeleteOptions(pkgName, sectionID, stale); err != nil {
		return fmt.Errorf("delete stale options %s.%s %v: %w", pkgName, sectionID, stale, err)
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
