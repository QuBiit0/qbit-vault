package filemerge

import (
	"bytes"
	"encoding/json"
	"strings"
)

// JSONEdit names one entry that qbit-vault owns inside a JSON document.
//
// With Marker empty, Path addresses an object member (for example
// {"mcpServers", "qbit-vault"}) and Value is its value.
//
// With Marker set, Path addresses an array (for example
// {"hooks", "PreToolUse"}) and the edit owns the array elements that contain
// Marker: an element is ours when its raw JSON text contains Marker or, for a
// string element, when its decoded text does (so Windows paths with escaped
// backslashes match). Value is the element to ensure and must itself contain
// Marker. An owned element is replaced as a whole; user elements are never
// touched. Choose a Marker no user entry would contain.
type JSONEdit struct {
	Path   []string
	Marker string
	Value  json.RawMessage
}

// MergeJSON applies edits to doc and returns the new bytes. Only the owned
// entries change: every other key, the key order and the user's formatting
// stay byte for byte. New entries copy the layout of their neighbours (indent
// unit, CRLF, colon spacing, one-line objects). A semantically equal existing
// entry is left alone, so applying the same edits twice gives the same bytes.
// Empty or whitespace-only doc is treated as {} and the result ends with a
// newline. Invalid JSON (comments and a BOM included) is refused with
// ErrInvalidJSON, a path that crosses a non-object with ErrJSONShape, a
// duplicate key on the path with ErrAmbiguous.
func MergeJSON(doc []byte, edits []JSONEdit) ([]byte, error) {
	for _, e := range edits {
		if err := e.validate(); err != nil {
			return nil, err
		}
	}
	created := len(bytes.TrimSpace(doc)) == 0
	out := doc
	if created {
		out = []byte("{}")
	}
	for _, e := range edits {
		var err error
		if out, err = e.apply(out); err != nil {
			return nil, err
		}
	}
	if created {
		out = append(out, '\n')
	}
	return out, nil
}

// UnmergeJSON removes the owned entries (Value is ignored) and returns the
// new bytes; entries that are absent are a no-op. A parent left empty is kept
// as {} or [] unless prune is set, which also removes parents emptied by the
// removal (never the root). Same refusals as MergeJSON.
func UnmergeJSON(doc []byte, edits []JSONEdit, prune bool) ([]byte, error) {
	for _, e := range edits {
		if len(e.Path) == 0 {
			return nil, ErrInvalidEdit
		}
	}
	out := doc
	for _, e := range edits {
		var err error
		if out, err = e.remove(out, prune); err != nil {
			return nil, err
		}
	}
	if len(bytes.TrimSpace(doc)) == 0 {
		return doc, nil
	}
	return out, nil
}

func (e JSONEdit) validate() error {
	if len(e.Path) == 0 || !json.Valid(e.Value) {
		return ErrInvalidEdit
	}
	for _, k := range e.Path {
		if k == "" {
			return ErrInvalidEdit
		}
	}
	if e.Marker != "" && !ownsElem(e.Marker, e.Value) {
		return ErrInvalidEdit
	}
	return nil
}

// ---- parsing with spans -------------------------------------------------

type jitem struct {
	start, end int // member: key start .. value end; element: value span
	key        string
	keyEnd     int
	val        *jval
}

type jval struct {
	kind       byte // 'o' object, 'a' array, 'v' scalar or string
	start, end int
	items      []jitem
}

const maxJSONDepth = 512

// parseJSON validates doc and returns its root with spans.
func parseJSON(doc []byte) (*jval, error) {
	if !json.Valid(doc) {
		return nil, ErrInvalidJSON
	}
	p := &jparser{b: doc}
	p.ws()
	v, ok := p.value(0)
	if !ok {
		return nil, ErrInvalidJSON
	}
	return v, nil
}

type jparser struct {
	b []byte
	i int
}

func (p *jparser) ws() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\n' || p.b[p.i] == '\r') {
		p.i++
	}
}

func (p *jparser) str() (string, bool) {
	start := p.i
	p.i++
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case '\\':
			p.i += 2
			continue
		case '"':
			p.i++
			var s string
			if err := json.Unmarshal(p.b[start:p.i], &s); err != nil {
				return "", false
			}
			return s, true
		}
		p.i++
	}
	return "", false
}

// value parses one value; doc was already validated, so this only tracks spans.
func (p *jparser) value(depth int) (*jval, bool) {
	if depth > maxJSONDepth || p.i >= len(p.b) {
		return nil, false
	}
	v := &jval{start: p.i}
	switch p.b[p.i] {
	case '{', '[':
		open, closer := p.b[p.i], byte('}')
		v.kind = 'o'
		if open == '[' {
			closer, v.kind = ']', 'a'
		}
		p.i++
		for {
			p.ws()
			if p.i >= len(p.b) {
				return nil, false
			}
			if p.b[p.i] == closer {
				p.i++
				break
			}
			if p.b[p.i] == ',' {
				p.i++
				continue
			}
			it := jitem{start: p.i}
			if v.kind == 'o' {
				k, ok := p.str()
				if !ok {
					return nil, false
				}
				it.key, it.keyEnd = k, p.i
				p.ws()
				p.i++ // ':'
				p.ws()
			}
			c, ok := p.value(depth + 1)
			if !ok {
				return nil, false
			}
			it.val, it.end = c, c.end
			v.items = append(v.items, it)
		}
	case '"':
		v.kind = 'v'
		if _, ok := p.str(); !ok {
			return nil, false
		}
	default:
		v.kind = 'v'
		for p.i < len(p.b) && !strings.ContainsRune(",]} \t\r\n", rune(p.b[p.i])) {
			p.i++
		}
	}
	v.end = p.i
	return v, true
}

func (v *jval) member(key string) (*jitem, error) {
	var found *jitem
	for i := range v.items {
		if v.items[i].key == key {
			if found != nil {
				return nil, ErrAmbiguous
			}
			found = &v.items[i]
		}
	}
	return found, nil
}

// ---- layout -------------------------------------------------------------

type layout struct {
	eol     string
	unit    string
	compact bool // the whole document is one line with members
}

func detectLayout(doc []byte, root *jval) layout {
	l := layout{eol: "\n", unit: "  "}
	if i := bytes.IndexByte(doc, '\n'); i > 0 && doc[i-1] == '\r' {
		l.eol = "\r\n"
	}
	l.compact = !bytes.Contains(doc, []byte("\n")) && len(root.items) > 0
	for _, line := range bytes.Split(doc, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		n := 0
		for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
			n++
		}
		if n > 0 && n < len(line) {
			l.unit = string(line[:n])
			break
		}
	}
	return l
}

// lineIndent is the leading whitespace of the line holding offset pos.
func lineIndent(doc []byte, pos int) string {
	ls := bytes.LastIndexByte(doc[:pos], '\n') + 1
	n := ls
	for n < pos && (doc[n] == ' ' || doc[n] == '\t') {
		n++
	}
	return string(doc[ls:n])
}

func oneLine(doc []byte, v *jval) bool { return !bytes.Contains(doc[v.start:v.end], []byte("\n")) }

// render formats value for insertion at an indentation of prefix.
func render(value []byte, prefix string, inline bool, l layout) []byte {
	var out bytes.Buffer
	if inline || l.compact {
		_ = json.Compact(&out, value)
		return out.Bytes()
	}
	_ = json.Indent(&out, value, prefix, l.unit)
	if l.eol != "\n" {
		return bytes.ReplaceAll(out.Bytes(), []byte("\n"), []byte(l.eol))
	}
	return out.Bytes()
}

func quote(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// nest wraps value in objects for keys: {"a":{"b":value}}.
func nest(keys []string, value []byte) []byte {
	if len(keys) == 0 {
		return value
	}
	var b bytes.Buffer
	b.WriteByte('{')
	b.Write(quote(keys[0]))
	b.WriteByte(':')
	b.Write(nest(keys[1:], value))
	b.WriteByte('}')
	return b.Bytes()
}

func splice(doc []byte, start, end int, repl []byte) []byte {
	out := make([]byte, 0, len(doc)-(end-start)+len(repl))
	out = append(out, doc[:start]...)
	out = append(out, repl...)
	return append(out, doc[end:]...)
}

// insertItem appends an item (already rendered text, with its key prefix for
// members) to a container, copying the layout of the last sibling.
func insertItem(doc []byte, c *jval, text func(prefix string, inline bool) []byte, l layout) []byte {
	if len(c.items) == 0 {
		closeIndent := lineIndent(doc, c.start)
		open, closer := doc[c.start:c.start+1], doc[c.end-1:c.end]
		if l.compact {
			return splice(doc, c.start, c.end, bytes.Join([][]byte{open, text("", true), closer}, nil))
		}
		inner := closeIndent + l.unit
		body := bytes.Join([][]byte{open, []byte(l.eol + inner), text(inner, false), []byte(l.eol + closeIndent), closer}, nil)
		return splice(doc, c.start, c.end, body)
	}
	last := c.items[len(c.items)-1]
	sepStart := c.start + 1
	if len(c.items) > 1 {
		prev := c.items[len(c.items)-2]
		sepStart = prev.end + bytes.IndexByte(doc[prev.end:], ',') + 1
	}
	gap := doc[sepStart:last.start]
	inline := oneLine(doc, c)
	indent := lineIndent(doc, last.start)
	out := append([]byte{','}, gap...)
	out = append(out, text(indent, inline)...)
	return splice(doc, last.end, last.end, out)
}

// removeItem deletes item i with exactly one comma and keeps the neighbours' layout.
func removeItem(doc []byte, c *jval, i int) []byte {
	switch {
	case len(c.items) == 1:
		open, closer := doc[c.start:c.start+1], doc[c.end-1:c.end]
		return splice(doc, c.start, c.end, append(append([]byte{}, open...), closer...))
	case i < len(c.items)-1:
		return splice(doc, c.items[i].start, c.items[i+1].start, nil)
	default:
		return splice(doc, c.items[i-1].end, c.items[i].end, nil)
	}
}

// ---- edits --------------------------------------------------------------

func ownsElem(marker string, raw []byte) bool {
	if bytes.Contains(raw, []byte(marker)) {
		return true
	}
	var s string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil {
		return strings.Contains(s, marker)
	}
	return false
}

func sameJSON(a, b []byte) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

// walk follows path from the root. It returns the deepest existing value,
// how many keys were consumed and the member holding it (nil for the root).
func walk(root *jval, path []string) (cur *jval, n int, m *jitem, err error) {
	cur = root
	for n < len(path) {
		if cur.kind != 'o' {
			return nil, 0, nil, ErrJSONShape
		}
		it, err := cur.member(path[n])
		if err != nil {
			return nil, 0, nil, err
		}
		if it == nil {
			return cur, n, m, nil
		}
		cur, m = it.val, it
		n++
	}
	return cur, n, m, nil
}

func (e JSONEdit) apply(doc []byte) ([]byte, error) {
	root, err := parseJSON(doc)
	if err != nil {
		return nil, err
	}
	if root.kind != 'o' {
		return nil, ErrJSONShape
	}
	l := detectLayout(doc, root)
	cur, n, m, err := walk(root, e.Path)
	if err != nil {
		return nil, err
	}
	value := []byte(e.Value)
	if e.Marker != "" {
		value = append(append([]byte{'['}, value...), ']')
	}
	if n < len(e.Path) { // path ends in missing keys: create them in one member
		key, rest := e.Path[n], e.Path[n+1:]
		colon := colonOf(doc, cur, l)
		return insertItem(doc, cur, func(prefix string, inline bool) []byte {
			out := append(quote(key), colon...)
			return append(out, render(nest(rest, value), prefix, inline, l)...)
		}, l), nil
	}
	if e.Marker == "" {
		if sameJSON(doc[cur.start:cur.end], e.Value) {
			return doc, nil
		}
		prefix := lineIndent(doc, m.start)
		return splice(doc, cur.start, cur.end, render(e.Value, prefix, oneLine(doc, cur) && cur.kind != 'v' || l.compact, l)), nil
	}
	return e.applyElem(doc, cur, l)
}

// applyElem ensures one owned element in array arr.
func (e JSONEdit) applyElem(doc []byte, arr *jval, l layout) ([]byte, error) {
	if arr.kind != 'a' {
		return nil, ErrJSONShape
	}
	var owned []int
	for i, it := range arr.items {
		if ownsElem(e.Marker, doc[it.start:it.end]) {
			owned = append(owned, i)
		}
	}
	if len(owned) == 0 {
		return insertItem(doc, arr, func(prefix string, inline bool) []byte {
			return render(e.Value, prefix, inline, l)
		}, l), nil
	}
	// Collapse duplicates (last first so earlier offsets stay valid), then
	// replace the first owned element unless it already says the same.
	out := doc
	for k := len(owned) - 1; k >= 1; k-- {
		root, err := parseJSON(out)
		if err != nil {
			return nil, err
		}
		cur, _, _, err := walk(root, e.Path)
		if err != nil {
			return nil, err
		}
		out = removeItem(out, cur, owned[k])
	}
	root, err := parseJSON(out)
	if err != nil {
		return nil, err
	}
	cur, _, _, err := walk(root, e.Path)
	if err != nil {
		return nil, err
	}
	it := cur.items[owned[0]]
	if sameJSON(out[it.start:it.end], e.Value) {
		return out, nil
	}
	prefix := lineIndent(out, it.start)
	return splice(out, it.start, it.end, render(e.Value, prefix, oneLine(out, it.val), l)), nil
}

// colonOf copies the ": " style of the container's last member.
func colonOf(doc []byte, c *jval, l layout) []byte {
	if len(c.items) > 0 {
		it := c.items[len(c.items)-1]
		return bytes.Clone(doc[it.keyEnd:it.val.start])
	}
	if l.compact {
		return []byte(":")
	}
	return []byte(": ")
}

func (e JSONEdit) remove(doc []byte, prune bool) ([]byte, error) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return doc, nil
	}
	root, err := parseJSON(doc)
	if err != nil {
		return nil, err
	}
	if root.kind != 'o' {
		return nil, ErrJSONShape
	}
	cur, n, _, err := walk(root, e.Path)
	if err != nil {
		return nil, err
	}
	if n < len(e.Path) {
		return doc, nil
	}
	out := doc
	if e.Marker != "" {
		if cur.kind != 'a' {
			return nil, ErrJSONShape
		}
		var owned []int
		for i, it := range cur.items {
			if ownsElem(e.Marker, doc[it.start:it.end]) {
				owned = append(owned, i)
			}
		}
		if len(owned) == 0 {
			return doc, nil
		}
		for k := len(owned) - 1; k >= 0; k-- {
			r, err := parseJSON(out)
			if err != nil {
				return nil, err
			}
			c, _, _, err := walk(r, e.Path)
			if err != nil {
				return nil, err
			}
			out = removeItem(out, c, owned[k])
		}
		if !prune {
			return out, nil
		}
		if r, err := parseJSON(out); err == nil {
			if c, _, _, err := walk(r, e.Path); err == nil && len(c.items) == 0 {
				return pruneUp(out, e.Path)
			}
		}
		return out, nil
	}
	return removeMember(doc, e.Path, prune)
}

// removeMember deletes the member at path; with prune it also deletes
// ancestors (except the root) that the removal left empty.
func removeMember(doc []byte, path []string, prune bool) ([]byte, error) {
	for len(path) > 0 {
		root, err := parseJSON(doc)
		if err != nil {
			return nil, err
		}
		parent, n, _, err := walk(root, path[:len(path)-1])
		if err != nil {
			return nil, err
		}
		if n < len(path)-1 || parent.kind != 'o' {
			return doc, nil
		}
		it, err := parent.member(path[len(path)-1])
		if err != nil {
			return nil, err
		}
		if it == nil {
			return doc, nil
		}
		idx := 0
		for i := range parent.items {
			if &parent.items[i] == it {
				idx = i
			}
		}
		wasOnly := len(parent.items) == 1
		doc = removeItem(doc, parent, idx)
		if !prune || !wasOnly || len(path) == 1 {
			return doc, nil
		}
		path = path[:len(path)-1]
	}
	return doc, nil
}

// pruneUp removes the (now empty) member at path and any ancestors it empties.
func pruneUp(doc []byte, path []string) ([]byte, error) { return removeMember(doc, path, true) }

// jsonIsEmptyObject reports whether doc is a JSON object with no members.
func jsonIsEmptyObject(doc []byte) bool {
	root, err := parseJSON(doc)
	return err == nil && root.kind == 'o' && len(root.items) == 0
}
