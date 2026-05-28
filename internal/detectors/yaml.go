package detectors

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// LoadWatchlist parses the minimal subset of YAML used by watch.yml.
// Supports: top-level "projects:" list, scalar keys, "distinctive_strings:" sub-list.
// Zero non-stdlib deps. If watch.yml grows, swap for gopkg.in/yaml.v3 later.
func LoadWatchlist(r io.Reader) (*Watchlist, error) {
	wl := &Watchlist{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var cur *WatchlistEntry
	inStrings := false
	for sc.Scan() {
		line := sc.Text()
		// strip comments
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		// indent count (spaces)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		switch {
		case trim == "projects:":
			continue
		case indent <= 2 && strings.HasPrefix(trim, "- name:"):
			if cur != nil {
				wl.Projects = append(wl.Projects, *cur)
			}
			c := WatchlistEntry{Name: yamlVal(trim[len("- name:"):])}
			cur = &c
			inStrings = false
		case cur != nil && strings.HasPrefix(trim, "- ") && inStrings:
			cur.DistinctiveStrings = append(cur.DistinctiveStrings, yamlVal(trim[2:]))
		case cur != nil:
			inStrings = false
			k, v, ok := splitKV(trim)
			if !ok {
				continue
			}
			switch k {
			case "name":
				cur.Name = yamlVal(v)
			case "github":
				cur.GitHub = yamlVal(v)
			case "aur":
				cur.AUR = yamlVal(v)
			case "license_path":
				cur.LicensePath = yamlVal(v)
			case "distinctive_strings":
				inStrings = true
			}
		}
	}
	if cur != nil {
		wl.Projects = append(wl.Projects, *cur)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("watch.yml: %w", err)
	}
	return wl, nil
}

func splitKV(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func yamlVal(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
