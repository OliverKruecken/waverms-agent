package uci

import (
	"encoding/json"
	"fmt"
	"maps"
	"sort"
)

// Section is one UCI config section, decoded from `ubus call uci get`'s JSON
// response. Options carries every non-meta key as a string or []string —
// UCI option values are always strings on disk, so a scalar always decodes
// to string and a UCI "list" option always decodes to []string.
type Section struct {
	ID        string
	Type      string
	Name      string // empty for anonymous sections
	Anonymous bool
	Options   map[string]interface{}
}

// indexedSection carries ubus's ".index" purely to recover the on-device
// declaration order — Section itself doesn't expose it, nothing downstream
// needs the number, only the ordering it encodes.
type indexedSection struct {
	index int
	sec   Section
}

// decodeUbusUCIGet parses the JSON stdout of `ubus call uci get '{"config":"<pkg>"}'`
// into a slice of Section ordered the same way the section appears in the
// on-device config file (ubus's own ".index" field), the same ordering
// `uci show`/`uci export` text output had.
func decodeUbusUCIGet(out string) ([]Section, error) {
	var envelope struct {
		Values map[string]map[string]json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		return nil, fmt.Errorf("decode ubus uci get output: %w", err)
	}

	indexed := make([]indexedSection, 0, len(envelope.Values))
	for id, raw := range envelope.Values {
		sec := Section{ID: id, Options: make(map[string]interface{})}
		idx := 0
		for key, val := range raw {
			switch key {
			case ".anonymous":
				_ = json.Unmarshal(val, &sec.Anonymous)
			case ".type":
				_ = json.Unmarshal(val, &sec.Type)
			case ".name":
				_ = json.Unmarshal(val, &sec.Name)
			case ".index":
				_ = json.Unmarshal(val, &idx)
			default:
				var s string
				if err := json.Unmarshal(val, &s); err == nil {
					sec.Options[key] = s
					continue
				}
				var list []string
				if err := json.Unmarshal(val, &list); err == nil {
					sec.Options[key] = list
				}
			}
		}
		indexed = append(indexed, indexedSection{index: idx, sec: sec})
	}

	sort.Slice(indexed, func(i, j int) bool { return indexed[i].index < indexed[j].index })

	sections := make([]Section, len(indexed))
	for i, e := range indexed {
		sections[i] = e.sec
	}
	return sections, nil
}

// GroupByType reproduces the section-type-keyed shape the agent's `/state`
// payload has always used (named sections carry ".name", options are
// string/[]string) — publishState builds this from GetSections instead of
// the old Export+ParseUCIExport text pipeline, but the wire format to the
// backend is unchanged.
func GroupByType(sections []Section) map[string][]map[string]interface{} {
	result := make(map[string][]map[string]interface{})
	for _, sec := range sections {
		m := make(map[string]interface{}, len(sec.Options)+1)
		maps.Copy(m, sec.Options)
		if !sec.Anonymous {
			m[".name"] = sec.Name
		}
		result[sec.Type] = append(result[sec.Type], m)
	}
	return result
}
