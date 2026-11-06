package prompt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/QuBiit0/qbit-vault/internal/secret"
)

// ErrNoForm means the backend has no multi-field form; ask the fields one
// box at a time instead (R-CAP-08).
var ErrNoForm = errors.New("prompt: this backend has no multi-field form")

// Former is a backend that can ask several fields in one dialog. Form
// returns one secret per request, in order, named like the request; the
// caller wipes them. A backend whose helper has no form returns ErrNoForm.
type Former interface {
	Form(reqs []SecretRequest) ([]secret.Secret, error)
}

// formSep separates zenity's answers: a control character no typed value
// holds (a value that did would change the count, which is refused).
const formSep = "\x1e"

const dialogForm dialogKind = 100

// formField is one box of a form dialog, its label already escaped.
type formField struct {
	label   string
	visible bool
}

// formDialog is one dialog for all of reqs: the request header once (names,
// reason, who asks, layer) and one labelled box per field.
func formDialog(reqs []SecretRequest) dialog {
	names := make([]string, len(reqs))
	fields := make([]formField, len(reqs))
	for i, r := range reqs {
		names[i] = r.Name
		label := r.Label
		if label == "" {
			label = r.Name
		}
		if r.Description != "" {
			label += " (" + r.Description + ")"
		}
		fields[i] = formField{label: escape(label), visible: r.Visible}
	}
	head := reqs[0]
	head.Name, head.Label, head.Visible, head.Field, head.Fields, head.Description = strings.Join(names, ", "), "", false, 0, 0, ""
	_, body, _ := strings.Cut(Header(head), "\n")
	return dialog{
		kind:   dialogForm,
		title:  "QBit Vault: secret request",
		text:   strings.TrimRight(body, "\n") + "\n\nFill in each field. Secret fields stay hidden and the agent never sees them:",
		fields: fields,
	}
}

// formTool is a helper with a multi-field form.
type formTool interface {
	buildForm(path string, d dialog) command
	// parseForm splits the helper's answer into exactly n values (fresh
	// buffers); anything else is false.
	parseForm(out []byte, n int) ([][]byte, bool)
}

// Form implements Former for the helpers that have forms.
func (n *native) Form(reqs []SecretRequest) ([]secret.Secret, error) {
	ft, ok := n.t.(formTool)
	if !ok || len(reqs) == 0 {
		return nil, ErrNoForm
	}
	d := formDialog(reqs)
	r, st, err := n.askWith(ft.buildForm(n.path, d), d)
	if err != nil {
		return nil, err
	}
	if st != statusOK {
		return nil, ErrCancelled
	}
	defer clear(r.Stdout)
	vals, ok := ft.parseForm(r.Stdout, len(reqs))
	if !ok {
		return nil, n.failed()
	}
	out := make([]secret.Secret, len(vals))
	for i, v := range vals {
		out[i] = secret.New(reqs[i].Name, normalize(v, valueInput))
		clear(v)
	}
	return out, nil
}

// ---- zenity: --forms ----

func (zenityTool) buildForm(path string, d dialog) command {
	args := []string{"--forms", "--no-markup", "--title=" + d.title, "--text=" + d.text, "--separator=" + formSep}
	for _, f := range d.fields {
		if f.visible {
			args = append(args, "--add-entry="+f.label)
		} else {
			args = append(args, "--add-password="+f.label)
		}
	}
	return command{Path: path, Args: args}
}

func (zenityTool) parseForm(out []byte, n int) ([][]byte, bool) {
	out = bytes.TrimRight(out, "\r\n")
	parts := bytes.Split(out, []byte(formSep))
	if len(parts) != n {
		return nil, false
	}
	vals := make([][]byte, n)
	for i, p := range parts {
		vals[i] = bytes.Clone(p)
	}
	return vals, true
}

// ---- PowerShell: one WinForms form ----

func (powershellTool) buildForm(path string, d dialog) command {
	c := powershellTool{}.build(path, dialog{kind: dialogSecret, title: d.title, text: d.text})
	c.Stdin = []byte(psFormScript(d))
	return c
}

func psFormScript(d dialog) string {
	var b strings.Builder
	b.WriteString(psPrelude(dialog{kind: dialogSecret, title: d.title, text: d.text}))
	labels := make([]string, len(d.fields))
	hides := make([]string, len(d.fields))
	for i, f := range d.fields {
		labels[i] = "(Dec " + psString(f.label) + ")"
		hides[i] = fmt.Sprintf("$%t", !f.visible)
	}
	fmt.Fprintf(&b, "$labels = @(%s)\n", strings.Join(labels, ", "))
	fmt.Fprintf(&b, "$hides = @(%s)\n", strings.Join(hides, ", "))
	b.WriteString(psBodyMarker + "\n")
	b.WriteString(psFormTop)
	b.WriteString(psFormInputs)
	b.WriteString(psButtons)
	b.WriteString("$f.AcceptButton = $ok\n")
	b.WriteString("$f.Add_Shown({ $this.Activate(); $boxes[0].Focus() | Out-Null })\n")
	b.WriteString(psShow)
	b.WriteString(psFormOutput)
	b.WriteString("exit 0\n")
	return b.String()
}

const psFormInputs = `$boxes = @()
for ($i = 0; $i -lt $labels.Count; $i++) { $fl = New-Object System.Windows.Forms.Label; $fl.UseMnemonic = $false; $fl.AutoSize = $true; $fl.MaximumSize = New-Object System.Drawing.Size(480, 0); $fl.Text = $labels[$i]; $p.Controls.Add($fl); $tb = New-Object System.Windows.Forms.TextBox; $tb.UseSystemPasswordChar = $hides[$i]; $tb.Width = 480; $tb.MaxLength = 70000; $p.Controls.Add($tb); $boxes += $tb }
`

// Each value leaves as one base64 line on the private stdout pipe, so no
// value can be mistaken for a separator.
const psFormOutput = `$out = [System.Console]::OpenStandardOutput()
foreach ($b in $boxes) { $bytes = [System.Text.Encoding]::ASCII.GetBytes([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($b.Text)) + "` + "`" + `n"); $out.Write($bytes, 0, $bytes.Length) }
$out.Flush()
`

func (powershellTool) parseForm(out []byte, n int) ([][]byte, bool) {
	// One line per value, each ended by "\n": only that last terminator is
	// dropped, so a blank last value stays a (blank) value.
	out = bytes.TrimSuffix(bytes.TrimSuffix(out, []byte("\n")), []byte("\r"))
	lines := bytes.Split(out, []byte("\n"))
	if len(lines) != n {
		return nil, false
	}
	vals := make([][]byte, n)
	for i, l := range lines {
		l = bytes.TrimRight(l, "\r")
		v := make([]byte, base64.StdEncoding.DecodedLen(len(l)))
		k, err := base64.StdEncoding.Decode(v, l)
		if err != nil {
			clear(v)
			for _, done := range vals[:i] {
				clear(done)
			}
			return nil, false
		}
		vals[i] = v[:k]
	}
	return vals, true
}
