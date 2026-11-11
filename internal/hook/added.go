package hook

import "strings"

// What pre-write scans (odd/tasks/output-guard.md S10.2): the text a call would
// add to a file, never the text it removes. Removing a stored value from a
// file is allowed; the shapes are those of the Claude Code, Pi and Codex
// write tools. A shape not listed here keeps being scanned whole.

// addedKeys carry text that ends up in the file; ignoredKeys carry text that
// only locates or removes it. Any other string member makes the call an
// unknown shape.
var (
	addedKeys   = map[string]bool{"content": true, "new_string": true, "new_source": true, "newText": true}
	ignoredKeys = map[string]bool{
		"file_path": true, "path": true, "notebook_path": true,
		"old_string": true, "oldText": true,
		"cell_id": true, "cell_type": true, "edit_mode": true,
	}
	writeTools = map[string]bool{"write": true, "edit": true, "multiedit": true, "notebookedit": true}
)

// addedText returns the strings a write would add to files. ok is false for a
// tool or shape it does not know, which the caller scans whole.
func addedText(tool string, input any) (added []string, ok bool) {
	obj, isObj := input.(map[string]any)
	if !isObj {
		return nil, false
	}
	// Codex apply_patch (also reached as Edit or Write): the patch is
	// tool_input.command.
	if cmd, isStr := obj["command"].(string); isStr && strings.HasPrefix(strings.TrimSpace(cmd), "*** Begin Patch") && len(obj) == 1 {
		return patchAdded(cmd), true
	}
	if !writeTools[strings.ToLower(tool)] {
		return nil, false
	}
	if !collectAdded(obj, &added) {
		return nil, false
	}
	return added, true
}

// collectAdded walks one write-tool object (or one entry of its edits array).
func collectAdded(obj map[string]any, added *[]string) bool {
	for k, v := range obj {
		switch x := v.(type) {
		case string:
			switch {
			case addedKeys[k]:
				*added = append(*added, x)
			case ignoredKeys[k], x == "":
			default:
				return false
			}
		case []any:
			if k != "edits" {
				if hasText(x) {
					return false
				}
				continue
			}
			for _, e := range x {
				entry, isObj := e.(map[string]any)
				if !isObj || !collectAdded(entry, added) {
					return false
				}
			}
		case map[string]any:
			if hasText(x) {
				return false
			}
		}
	}
	return true
}

// patchAdded returns, per file, the lines a V4A patch adds: the `+` lines of
// an Add File and of the hunks of an Update File, joined by newlines. Context
// lines (` `), removed lines (`-`), hunk headers and file headers are not
// added text. A line with no recognized prefix is kept (scanned) rather than
// trusted.
func patchAdded(patch string) []string {
	var files []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			files = append(files, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "*** "):
			flush()
		case strings.HasPrefix(line, "@@"), line == "":
		case line[0] == '+':
			cur = append(cur, line[1:])
		case line[0] == '-', line[0] == ' ':
		default:
			cur = append(cur, line)
		}
	}
	flush()
	return files
}
