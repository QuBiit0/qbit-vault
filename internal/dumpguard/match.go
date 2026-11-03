package dumpguard

import "strings"

// Match reports whether cmd must be refused while the secrets named in
// injected are in the child's environment. With nothing injected the guard
// does not apply (R-EXEC-03) and Match is false.
//
// Every segment is tested in up to four forms: as normalized; with input
// redirections (`< file`) folded into plain arguments; and each of those with
// wrappers and the program path resolved, the program lowercased (so
// `/usr/bin/env`, `sudo env`, `command env` and `ENV` all look like `env`).
func (g *Guard) Match(cmd string, injected []string) (refused bool) {
	if len(injected) == 0 {
		return false
	}
	res := g.compiled(injected)
	for _, seg := range Segments(cmd) {
		for _, form := range forms(seg) {
			for _, re := range res {
				if re.MatchString(form) {
					return true
				}
			}
		}
	}
	return false
}

func forms(seg Segment) []string {
	out := []string{seg.Text}
	add := func(s string) {
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	variants := [][]string{seg.Words}
	if folded := foldInput(seg.Words); folded != nil {
		variants = append(variants, folded)
		add(strings.Join(folded, " "))
	}
	for _, w := range variants {
		idx, bare := resolve(w)
		if idx < 0 {
			continue
		}
		prog := strings.ToLower(baseName(w[idx]))
		if bare {
			add(prog)
			continue
		}
		add(strings.Join(append([]string{prog}, w[idx+1:]...), " "))
	}
	return out
}

// foldInput drops `<` input redirection operators so their target reads as an
// argument; nil when there are none.
func foldInput(w []string) []string {
	var out []string
	changed := false
	for _, a := range w {
		switch {
		case a == "<":
			changed = true
		case strings.HasPrefix(a, "<") && !strings.HasPrefix(a, "<<"):
			changed = true
			out = append(out, a[1:])
		default:
			out = append(out, a)
		}
	}
	if !changed {
		return nil
	}
	return out
}
