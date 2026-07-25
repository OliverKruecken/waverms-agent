package uci

import (
	"fmt"
	"strings"
)

// ParseUCIExport parses the text output of `uci export <pkg>` into a map of
// section_type → []section_map.
//
// The uci export format is:
//
//	package <name>
//
//	config <type> ['<name>']
//		option <key> '<value>'
//		list   <key> '<value>'
//
// Named sections carry a ".name" key; anonymous sections do not.
// List options accumulate into []string. All other values are plain strings.
// The "package" line is ignored. Blank lines act as delimiters and are skipped.
func ParseUCIExport(output string) (map[string][]map[string]interface{}, error) {
	result := make(map[string][]map[string]interface{})

	if strings.TrimSpace(output) == "" {
		return result, nil
	}

	var current map[string]interface{}
	var currentType string

	flush := func() {
		if current != nil {
			result[currentType] = append(result[currentType], current)
		}
		current = nil
		currentType = ""
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "package ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "config":
			flush()
			if len(fields) < 2 {
				return nil, fmt.Errorf("malformed config line: %q", line)
			}
			currentType = fields[1]
			current = make(map[string]interface{})
			if len(fields) >= 3 {
				current[".name"] = stripQuotes(fields[2])
			}

		case "option":
			if current == nil || len(fields) < 3 {
				continue
			}
			key := fields[1]
			// Rejoin in case the value itself contains spaces (shouldn't happen in
			// well-formed UCI output, but defensive programming costs nothing here).
			val := stripQuotes(strings.Join(fields[2:], " "))
			current[key] = val

		case "list":
			if current == nil || len(fields) < 3 {
				continue
			}
			key := fields[1]
			val := stripQuotes(strings.Join(fields[2:], " "))
			existing, ok := current[key]
			if !ok {
				current[key] = []string{val}
			} else {
				switch v := existing.(type) {
				case []string:
					current[key] = append(v, val)
				default:
					// Treat a previously set scalar as the first element.
					current[key] = []string{fmt.Sprintf("%v", v), val}
				}
			}
		}
	}

	flush()
	return result, nil
}

// stripQuotes removes a single layer of surrounding single quotes from s.
func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
