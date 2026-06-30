package apt

import "strings"

// ParseDependencyGroups parses a Depends/Pre-Depends field into groups of
// alternatives. Each group is a list of candidate package names (version
// constraints and architecture qualifiers stripped). Example:
//
//	"libc6 (>= 2.34), foo | bar" -> [["libc6"], ["foo","bar"]]
func ParseDependencyGroups(s string) [][]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var groups [][]string
	for _, group := range strings.Split(s, ",") {
		var alts []string
		for _, alt := range strings.Split(group, "|") {
			name := dependencyName(alt)
			if name != "" {
				alts = append(alts, name)
			}
		}
		if len(alts) > 0 {
			groups = append(groups, alts)
		}
	}
	return groups
}

func dependencyName(s string) string {
	s = strings.TrimSpace(s)
	// Strip version constraint: "pkg (>= 1.0)".
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	// Strip architecture qualifier: "pkg:any".
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	// Strip build/arch restrictions: "pkg [amd64]".
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
