package prompt

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// powershellTool shows a WinForms dialog (L4). The script goes to
// powershell.exe on stdin; the request text is in it only as base64 data
// that the script decodes, so no character of it can end a literal or start
// a command. Exit codes: 0 answered, 2 cancelled, anything else a failure.
type powershellTool struct{}

func (powershellTool) name() string    { return "powershell" }
func (powershellTool) program() string { return "powershell.exe" }

// psExitCancel is the exit code of a dialog the user closed or declined.
const psExitCancel = 2

func (powershellTool) classify(_ dialog, r result) status {
	switch r.Exit {
	case 0:
		return statusOK
	case psExitCancel:
		return statusCancel
	}
	return statusFail
}

func (powershellTool) build(path string, d dialog) command {
	return command{
		Path:  path,
		Args:  []string{"-NoProfile", "-NonInteractive", "-STA", "-Command", "-"},
		Stdin: []byte(psScript(d)),
	}
}

// Every statement of the script sits on one line: powershell.exe reads
// "-Command -" from stdin line by line and silently drops what follows a
// statement that spans lines (a for loop with a body on its own lines).

// psString is a PowerShell single-quoted literal for s: its base64, which has
// no quote, backslash, dollar, backtick, newline or non-ASCII character. The
// script turns it back into text with Dec.
func psString(s string) string {
	return "'" + base64.StdEncoding.EncodeToString([]byte(s)) + "'"
}

// psBodyMarker separates the data lines of a script from its fixed body.
const psBodyMarker = "# ---- body ----"

// psPrelude is the data half of the script: everything that comes from the
// request, as variables.
func psPrelude(d dialog) string {
	okLabel, cancelLabel := "OK", "Cancel"
	if d.kind == dialogConfirm {
		okLabel, cancelLabel = "Confirm", "Decline"
	}
	opts := make([]string, len(d.options))
	for i, o := range d.options {
		opts[i] = "(Dec " + psString(o) + ")"
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("function Dec($s) { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s)) }\n")
	fmt.Fprintf(&b, "$title = Dec %s\n", psString(d.title))
	fmt.Fprintf(&b, "$text = Dec %s\n", psString(d.text))
	fmt.Fprintf(&b, "$okLabel = Dec %s\n", psString(okLabel))
	fmt.Fprintf(&b, "$cancelLabel = Dec %s\n", psString(cancelLabel))
	fmt.Fprintf(&b, "$opts = @(%s)\n", strings.Join(opts, ", "))
	fmt.Fprintf(&b, "$def = %d\n", d.def)
	return b.String()
}

func psScript(d dialog) string {
	var b strings.Builder
	b.WriteString(psPrelude(d))
	b.WriteString(psBodyMarker + "\n")
	b.WriteString(psFormTop)
	accept := "$ok"
	switch d.kind {
	case dialogSecret:
		b.WriteString(psSecretInput)
	case dialogChoose:
		b.WriteString(psChooseInput)
	case dialogConfirm:
		accept = "$no" // Enter declines
	}
	b.WriteString(psButtons)
	fmt.Fprintf(&b, "$f.AcceptButton = %s\n", accept)
	if d.kind == dialogSecret {
		b.WriteString("$f.Add_Shown({ $this.Activate(); $tb.Focus() | Out-Null })\n")
	} else {
		b.WriteString("$f.Add_Shown({ $this.Activate() })\n")
	}
	b.WriteString(psShow)
	switch d.kind {
	case dialogSecret:
		b.WriteString(psSecretOutput)
	case dialogChoose:
		b.WriteString(psChooseOutput)
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// The dialog is TopMost so it cannot hide behind the agent's window; labels
// do not treat & as an accelerator, so a name with & is shown as written.
const psFormTop = `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$f = New-Object System.Windows.Forms.Form
$f.Text = $title
$f.TopMost = $true
$f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'
$f.MinimizeBox = $false
$f.MaximizeBox = $false
$f.AutoSize = $true
$f.AutoSizeMode = 'GrowAndShrink'
$f.Padding = New-Object System.Windows.Forms.Padding(12)
$p = New-Object System.Windows.Forms.FlowLayoutPanel
$p.FlowDirection = 'TopDown'
$p.WrapContents = $false
$p.AutoSize = $true
$l = New-Object System.Windows.Forms.Label
$l.UseMnemonic = $false
$l.AutoSize = $true
$l.MaximumSize = New-Object System.Drawing.Size(480, 0)
$l.Text = $text
$p.Controls.Add($l)
`

const psSecretInput = `$tb = New-Object System.Windows.Forms.TextBox
$tb.UseSystemPasswordChar = $true
$tb.Width = 480
$tb.MaxLength = 70000
$p.Controls.Add($tb)
`

const psChooseInput = `$radios = @()
for ($i = 0; $i -lt $opts.Count; $i++) { $r = New-Object System.Windows.Forms.RadioButton; $r.UseMnemonic = $false; $r.AutoSize = $true; $r.MaximumSize = New-Object System.Drawing.Size(480, 0); $r.Text = $opts[$i]; $r.Checked = ($i -eq $def); $p.Controls.Add($r); $radios += $r }
`

const psButtons = `$bp = New-Object System.Windows.Forms.FlowLayoutPanel
$bp.FlowDirection = 'LeftToRight'
$bp.AutoSize = $true
$ok = New-Object System.Windows.Forms.Button
$ok.Text = $okLabel
$ok.AutoSize = $true
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$no = New-Object System.Windows.Forms.Button
$no.Text = $cancelLabel
$no.AutoSize = $true
$no.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$bp.Controls.Add($ok)
$bp.Controls.Add($no)
$p.Controls.Add($bp)
$f.Controls.Add($p)
$f.CancelButton = $no
`

const psShow = `if ($f.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }
`

// The value leaves as UTF-8 bytes on the process's stdout, the private pipe
// to the broker; Console.Out would apply the console code page.
const psSecretOutput = `$bytes = [System.Text.Encoding]::UTF8.GetBytes($tb.Text)
$out = [System.Console]::OpenStandardOutput()
$out.Write($bytes, 0, $bytes.Length)
$out.Flush()
`

const psChooseOutput = `for ($i = 0; $i -lt $radios.Count; $i++) { if ($radios[$i].Checked) { [System.Console]::Out.Write([string]($i + 1)) } }
`
