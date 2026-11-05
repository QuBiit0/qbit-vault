package cli

import (
	"regexp"
	"sort"
	"strings"
)

// Host extraction is advisory (PRD R-EXEC-08): it looks for URLs, IPv4
// addresses and bare hostnames in the command text, nothing more. It is
// deliberately loose; a false positive only adds a warning to the audit.
var (
	urlRE  = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://(?:[^\s/?#@'"]*@)?([^\s/?#:'"\\]+)[^\s'"]*`)
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostRE = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})\b`)
)

// fileExts are last labels that name files far more often than hosts.
var fileExts = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(`md txt json yaml yml go js ts mjs cjs jsx tsx py sh rs c h cc cpp hpp toml lock log csv test
		html htm css sql xml exe bat cmd ps1 zip tar gz tgz bz2 xz png jpg jpeg gif svg pdf mod sum cfg ini env conf so dll
		rb java kt swift php pl lua git bak tmp out sample example`) {
		m[e] = true
	}
	return m
}()

// commandHosts returns the distinct lowercase hosts a command mentions, in
// order of appearance.
func commandHosts(cmd string) []string {
	type hit struct {
		pos  int
		host string
	}
	var hits []hit
	rest := []byte(cmd)
	for _, m := range urlRE.FindAllStringSubmatchIndex(cmd, -1) {
		hits = append(hits, hit{m[0], strings.ToLower(cmd[m[2]:m[3]])})
		for i := m[0]; i < m[1]; i++ {
			rest[i] = ' '
		}
	}
	text := string(rest)
	for _, m := range ipv4RE.FindAllStringIndex(text, -1) {
		hits = append(hits, hit{m[0], text[m[0]:m[1]]})
	}
	for _, m := range hostRE.FindAllStringSubmatchIndex(text, -1) {
		h := strings.ToLower(text[m[2]:m[3]])
		if fileExts[h[strings.LastIndexByte(h, '.')+1:]] {
			continue
		}
		hits = append(hits, hit{m[2], h})
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	var out []string
	seen := map[string]bool{}
	for _, h := range hits {
		if !seen[h.host] {
			seen[h.host] = true
			out = append(out, h.host)
		}
	}
	return out
}

// hostsOutside reports whether cmd mentions a host that is not in allowed.
// An empty list allows everything. An entry `*.example.com` allows the
// subdomains of example.com, not example.com itself.
func hostsOutside(cmd string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, h := range commandHosts(cmd) {
		ok := false
		for _, a := range allowed {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == h || (strings.HasPrefix(a, "*.") && strings.HasSuffix(h, a[1:])) {
				ok = true
				break
			}
		}
		if !ok {
			return true
		}
	}
	return false
}
