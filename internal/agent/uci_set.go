package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OliverKruecken/waverms-agent/internal/uci"
)

// uciAddress is a parsed UCI CLI-style address: <config>.<section>[.<option>].
// Section is either a literal name/id or `@type[N]` positional addressing —
// resolved against a live GetSections snapshot by resolveUCISection below.
type uciAddress struct {
	Config  string
	Section string
	Option  string
}

// parseUCIAddress splits a uci CLI-style address into config/section/option.
// Option names never contain dots, so splitting into at most 3 parts is exact.
func parseUCIAddress(s string) (uciAddress, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return uciAddress{}, fmt.Errorf("invalid uci address %q: want config.section[.option]", s)
	}
	addr := uciAddress{Config: parts[0], Section: parts[1]}
	if len(parts) == 3 {
		addr.Option = parts[2]
	}
	return addr, nil
}

// positionalSectionRe matches uci's `@type[N]` positional anonymous-section
// addressing (e.g. "@system[0]", "@wifi-iface[-1]").
var positionalSectionRe = regexp.MustCompile(`^@([a-zA-Z0-9_-]+)\[(-?\d+)\]$`)

// resolveUCISection resolves addr.Section to a concrete on-device section id
// against an already-fetched sections snapshot (see runUCISetCommand — every
// subcommand needing this fetches once, not per call). A literal name/id is
// returned unchanged; `@type[N]` is resolved by filtering to anonymous
// sections of that type in on-device order (the same order GetSections
// already returns) and indexing N, supporting a negative N the way uci
// itself does (N < 0 -> len+N).
func resolveUCISection(sections []uci.Section, addr uciAddress) (string, error) {
	m := positionalSectionRe.FindStringSubmatch(addr.Section)
	if m == nil {
		return addr.Section, nil
	}
	sectionType, idxStr := m[1], m[2]
	idx, _ := strconv.Atoi(idxStr) // regex guarantees a valid integer

	var ids []string
	for _, s := range sections {
		if s.Anonymous && s.Type == sectionType {
			ids = append(ids, s.ID)
		}
	}
	if idx < 0 {
		idx += len(ids)
	}
	if idx < 0 || idx >= len(ids) {
		return "", fmt.Errorf("%s.@%s[%s]: index out of range (found %d anonymous %s section(s))", addr.Config, sectionType, idxStr, len(ids), sectionType)
	}
	return ids[idx], nil
}

// findUCISection finds a section matching key by name (for a named section)
// or by id (for an id, or a positionally-resolved reference) — uci addressing
// allows either, e.g. "network.lan" (name) or "network.cfg01a2b3" (id).
// Mirrors apply/applier.go's findSectionByName/findSectionByID, combined into
// one lookup since uci_set doesn't know upfront which kind of key it has.
func findUCISection(sections []uci.Section, key string) *uci.Section {
	if s := findFirst(sections, func(s uci.Section) bool { return !s.Anonymous && s.Name == key }); s != nil {
		return s
	}
	return findFirst(sections, func(s uci.Section) bool { return s.ID == key })
}

// findFirst returns a pointer to the first element of items matching pred, or
// nil. Same small generic helper apply/applier.go defines for the same
// purpose — kept as its own unexported copy here rather than exported from
// apply, since internal/agent doesn't otherwise depend on internal/apply's
// UCI-payload-staging package for anything this narrow.
func findFirst[T any](items []T, pred func(T) bool) *T {
	for i := range items {
		if pred(items[i]) {
			return &items[i]
		}
	}
	return nil
}

// runUCISetCommand executes one parsed uci_set subcommand against runner,
// returning text output (mirroring the uci CLI's own stdout convention where
// applicable — e.g. "add" returns the new section id, "get" returns the
// resolved value) for handleUCISet to fold into its per-line output/status
// accumulation, exactly as the ExecRaw passthrough this replaces did.
func runUCISetCommand(runner uci.UCIRunner, subcmd string, rest []string) (string, error) {
	switch subcmd {
	case "add":
		if len(rest) != 2 {
			return "", fmt.Errorf("add: want \"<config> <type>\", got %d arg(s)", len(rest))
		}
		return runner.Add(rest[0], rest[1], "")
	case "commit":
		if len(rest) != 1 {
			return "", fmt.Errorf("commit: want a single config name, got %d arg(s)", len(rest))
		}
		return "", runner.Commit(rest[0])
	case "revert":
		if len(rest) != 1 {
			return "", fmt.Errorf("revert: want a single config name, got %d arg(s)", len(rest))
		}
		return "", runner.Revert(rest[0])
	case "get":
		return runUCIGet(runner, rest)
	case "set":
		return "", runUCISet(runner, rest)
	case "delete":
		return "", runUCIDelete(runner, rest)
	case "add_list":
		return "", modifyUCIList(runner, rest, "add_list", func(cur []string, value string) []string {
			return append(cur, value) // uci allows duplicates in a list; don't dedupe
		})
	case "del_list":
		return "", modifyUCIList(runner, rest, "del_list", func(cur []string, value string) []string {
			out := make([]string, 0, len(cur))
			for _, v := range cur {
				if v != value {
					out = append(out, v)
				}
			}
			return out
		})
	default:
		return "", fmt.Errorf("unsupported uci subcommand: %s", subcmd)
	}
}

// splitAddressValue splits a "<address>=<value>" argument (the shape `set`,
// `add_list`, and `del_list` all take) on the first '=' and parses the
// address half.
func splitAddressValue(verb, arg string) (addr uciAddress, value string, err error) {
	eq := strings.IndexByte(arg, '=')
	if eq < 0 {
		return uciAddress{}, "", fmt.Errorf("%s %s: missing '='", verb, arg)
	}
	addr, err = parseUCIAddress(arg[:eq])
	if err != nil {
		return uciAddress{}, "", err
	}
	return addr, arg[eq+1:], nil
}

// runUCIGet handles `uci get config.section[.option]`: with no option,
// returns the section's type (mirrors `uci get` on a bare section); with an
// option, returns its value — a scalar as-is, a list joined one-per-line
// (mirrors `uci get`'s own list output).
func runUCIGet(runner uci.UCIRunner, rest []string) (string, error) {
	if len(rest) != 1 {
		return "", fmt.Errorf("get: want a single address, got %d arg(s)", len(rest))
	}
	addr, err := parseUCIAddress(rest[0])
	if err != nil {
		return "", err
	}
	sections, err := runner.GetSections(addr.Config)
	if err != nil {
		return "", fmt.Errorf("get %s: %w", rest[0], err)
	}
	sectionID, err := resolveUCISection(sections, addr)
	if err != nil {
		return "", err
	}
	sec := findUCISection(sections, sectionID)
	if sec == nil {
		return "", fmt.Errorf("get %s: section not found", rest[0])
	}
	if addr.Option == "" {
		return sec.Type, nil
	}
	val, ok := sec.Options[addr.Option]
	if !ok {
		return "", fmt.Errorf("get %s: option not found", rest[0])
	}
	switch v := val.(type) {
	case []string:
		return strings.Join(v, "\n"), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// runUCISet handles `uci set config.section=type` (create-or-retype: Add if
// the named section doesn't exist yet, RetypeExisting if it exists under a
// different type, no-op if the type already matches — mirrors
// apply/applier.go's applySection create-vs-retype branch) and
// `uci set config.section.option=value` (SetValues).
func runUCISet(runner uci.UCIRunner, rest []string) error {
	if len(rest) != 1 {
		return fmt.Errorf("set: want \"<address>=<value>\", got %d arg(s)", len(rest))
	}
	addr, value, err := splitAddressValue("set", rest[0])
	if err != nil {
		return err
	}
	sections, err := runner.GetSections(addr.Config)
	if err != nil {
		return fmt.Errorf("set %s: %w", rest[0], err)
	}
	sectionID, err := resolveUCISection(sections, addr)
	if err != nil {
		return err
	}

	if addr.Option == "" {
		existing := findUCISection(sections, sectionID)
		switch {
		case existing == nil:
			_, err := runner.Add(addr.Config, value, sectionID)
			return err
		case existing.Type != value:
			return runner.RetypeExisting(addr.Config, sectionID, value)
		default:
			return nil
		}
	}
	return runner.SetValues(addr.Config, sectionID, map[string]interface{}{addr.Option: value})
}

// runUCIDelete handles `uci delete config.section` (Delete) and
// `uci delete config.section.option` (DeleteOptions).
func runUCIDelete(runner uci.UCIRunner, rest []string) error {
	if len(rest) != 1 {
		return fmt.Errorf("delete: want a single address, got %d arg(s)", len(rest))
	}
	addr, err := parseUCIAddress(rest[0])
	if err != nil {
		return err
	}
	sections, err := runner.GetSections(addr.Config)
	if err != nil {
		return fmt.Errorf("delete %s: %w", rest[0], err)
	}
	sectionID, err := resolveUCISection(sections, addr)
	if err != nil {
		return err
	}
	if addr.Option == "" {
		return runner.Delete(addr.Config, sectionID)
	}
	return runner.DeleteOptions(addr.Config, sectionID, []string{addr.Option})
}

// modifyUCIList handles `add_list`/`del_list config.section.option=value` —
// UCIRunner has no incremental list-mutation method (only SetValues'
// whole-list overwrite), so this reads the option's current list (absent ->
// empty), applies mutate, and writes the result back. An empty result after
// mutation calls DeleteOptions instead of SetValues with an empty slice,
// matching uci's own "empty list == absent option" semantics.
func modifyUCIList(runner uci.UCIRunner, rest []string, verb string, mutate func(cur []string, value string) []string) error {
	if len(rest) != 1 {
		return fmt.Errorf("%s: want \"<address>=<value>\", got %d arg(s)", verb, len(rest))
	}
	addr, value, err := splitAddressValue(verb, rest[0])
	if err != nil {
		return err
	}
	if addr.Option == "" {
		return fmt.Errorf("%s %s: option required", verb, rest[0])
	}
	sections, err := runner.GetSections(addr.Config)
	if err != nil {
		return fmt.Errorf("%s %s: %w", verb, rest[0], err)
	}
	sectionID, err := resolveUCISection(sections, addr)
	if err != nil {
		return err
	}

	var cur []string
	if sec := findUCISection(sections, sectionID); sec != nil {
		switch v := sec.Options[addr.Option].(type) {
		case []string:
			cur = v
		case string:
			cur = []string{v} // a scalar option being list-mutated: treat as a 1-element list
		}
	}

	next := mutate(cur, value)
	if len(next) == 0 {
		return runner.DeleteOptions(addr.Config, sectionID, []string{addr.Option})
	}
	return runner.SetValues(addr.Config, sectionID, map[string]interface{}{addr.Option: next})
}
