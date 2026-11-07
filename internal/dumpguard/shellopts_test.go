package dumpguard

import (
	"fmt"
	"testing"
)

// A-F1 / S6.1: options before -c do not hide the script.
func TestMatchShellWithOptionsBeforeC(t *testing.T) {
	g := Default()
	for _, c := range []string{
		`bash -o pipefail -c 'printenv'`,
		`sh --login -c 'echo $NAME'`,
		`bash -O extglob -c env`,
		`bash +o pipefail -c env`,
		`bash +O extglob -c env`,
		`bash --norc --noprofile -c env`,
		`bash -o pipefail -O extglob --login -lc 'printenv'`,
		`sudo bash -o errexit -c env`,
	} {
		if !g.Match(c, []string{"NAME"}) {
			t.Errorf("%q should be refused", c)
		}
	}
	for _, c := range []string{
		`bash -o pipefail -c 'echo hi'`,
		`sh --login -c 'echo hi'`,
		`bash -O extglob -c 'ls'`,
		`bash -o pipefail script.sh`,
	} {
		if g.Match(c, []string{"NAME"}) {
			t.Errorf("%q should be allowed", c)
		}
	}
}

func TestScriptOfSkipsShellOptions(t *testing.T) {
	tests := []struct {
		words  []string
		script string
		ok     bool
	}{
		{[]string{"bash", "-o", "pipefail", "-c", "printenv"}, "printenv", true},
		{[]string{"sh", "--login", "-c", "env"}, "env", true},
		{[]string{"bash", "-O", "extglob", "-c", "env"}, "env", true},
		{[]string{"bash", "+O", "extglob", "-lc", "env"}, "env", true},
		{[]string{"bash", "-o", "pipefail"}, "", false},
		{[]string{"bash", "-o"}, "", false},
		{[]string{"bash", "script.sh", "-c", "env"}, "", false},
		{[]string{"bash", "-c"}, "", false},
	}
	for _, tt := range tests {
		got, ok := scriptOf(tt.words)
		if got != tt.script || ok != tt.ok {
			t.Errorf("scriptOf(%q) = %q, %v; want %q, %v", tt.words, got, ok, tt.script, tt.ok)
		}
	}
}

// A-F2 / S6.2: an encoded PowerShell command cannot be inspected.
func TestMatchRefusesPowerShellEncodedCommand(t *testing.T) {
	g := Default()
	for _, c := range []string{
		`pwsh -e SQBFAFgA`,
		`pwsh -ec SQBFAFgA`,
		`pwsh -en SQBFAFgA`,
		`powershell -enc SQBFAFgA`,
		`powershell.exe -EncodedCommand SQBFAFgA`,
		`POWERSHELL -ENC SQBFAFgA`,
		`pwsh /enc SQBFAFgA`,
		`pwsh -NoProfile -NonInteractive -EncodedCommand SQBFAFgA`,
		// Options that take a value come first in the common forms.
		`pwsh -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA`,
		`powershell -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgA`,
		`powershell -WindowStyle Hidden -NonInteractive -e SQBFAFgA`,
		`pwsh -InputFormat Text -OutputFormat Text -ec SQBFAFgA`,
		`pwsh -encodedcommand SQBFAFgA`,
		`sudo pwsh -e SQBFAFgA`,
		`echo hi; pwsh -e SQBFAFgA`,
	} {
		if !g.Match(c, []string{"NAME"}) {
			t.Errorf("Match(%q) should refuse", c)
		}
		if !g.MatchRaw(c, []string{"NAME"}) {
			t.Errorf("MatchRaw(%q) should refuse", c)
		}
		if g.Match(c, nil) || g.MatchRaw(c, nil) {
			t.Errorf("%q must be allowed when nothing is injected", c)
		}
	}
	for _, c := range []string{
		`pwsh -NoProfile -Command 'Write-Output hi'`,
		`pwsh -File build.ps1`,
		`pwsh -ExecutionPolicy Bypass -File x.ps1`,
		`echo -e hi`,
		`bash -e script.sh`,
	} {
		if g.Match(c, []string{"NAME"}) || g.MatchRaw(c, []string{"NAME"}) {
			t.Errorf("%q should be allowed", c)
		}
	}
}

// S12.1: no spelling of an option or its value hides -EncodedCommand.
func TestMatchRefusesEncodedCommandBehindValuedOptions(t *testing.T) {
	g := Default()
	for _, c := range []string{
		// A value that looks like -File or -Command must not end the scan.
		`pwsh -WorkingDirectory /f -e SQBFAFgA`,
		`pwsh -WorkingDirectory /c -enc SQBFAFgA`,
		`pwsh -wd /f -EncodedCommand SQBFAFgA`,
		`pwsh -SettingsFile /c -ec SQBFAFgA`,
		`pwsh -Version 5.1 -ep bypass -wd /c -e SQBFAFgA`,
		// :-joined option and value.
		`pwsh -e:SQBFAFgA`,
		`pwsh -EncodedCommand:SQBFAFgA`,
		`pwsh -ExecutionPolicy:Bypass -e SQBFAFgA`,
		`pwsh -ExecutionPolicy:Bypass -WorkingDirectory:/f -enc SQBFAFgA`,
		// Quoted values and options.
		`pwsh -ExecutionPolicy "Bypass" -e SQBFAFgA`,
		`pwsh -ExecutionPolicy 'Bypass' -e SQBFAFgA`,
		`pwsh "-e" SQBFAFgA`,
		`pwsh -ep "by pass" -e SQBFAFgA`,
		// PowerShell accepts typographic dashes as the option prefix.
		"pwsh \u2013EncodedCommand SQBFAFgA",
		"pwsh \u2014e SQBFAFgA",
		"pwsh \u2015enc SQBFAFgA",
		`pwsh -ep bypass -NoExit -i -e SQBFAFgA`,
	} {
		if !g.Match(c, []string{"NAME"}) {
			t.Errorf("Match(%q) should refuse", c)
		}
		if !g.MatchRaw(c, []string{"NAME"}) {
			t.Errorf("MatchRaw(%q) should refuse", c)
		}
		if g.Match(c, nil) || g.MatchRaw(c, nil) {
			t.Errorf("%q must be allowed when nothing is injected", c)
		}
	}
	for _, c := range []string{
		`pwsh -WorkingDirectory /c -File x.ps1`,
		`pwsh -wd /f -Command 'Write-Output hi'`,
		`pwsh -ExecutionPolicy:Bypass -File x.ps1`,
		`pwsh -ExecutionPolicy "Bypass" -NoProfile -File x.ps1`,
	} {
		if g.Match(c, []string{"NAME"}) || g.MatchRaw(c, []string{"NAME"}) {
			t.Errorf("%q should be allowed", c)
		}
	}
}

// S12.2: bash/sh long options that take a value do not hide -c.
func TestScriptOfSkipsValuedLongOptions(t *testing.T) {
	tests := []struct {
		words  []string
		script string
		ok     bool
	}{
		{[]string{"bash", "--rcfile", "x.rc", "-c", "printenv"}, "printenv", true},
		{[]string{"bash", "--init-file", "x.rc", "-lc", "printenv"}, "printenv", true},
		{[]string{"bash", "--rcfile=x.rc", "-c", "printenv"}, "printenv", true},
		{[]string{"bash", "--norc", "--rcfile", "x.rc", "--login", "-c", "env"}, "env", true},
		{[]string{"bash", "--rcfile", "x.rc", "script.sh"}, "", false},
		{[]string{"bash", "--rcfile"}, "", false},
	}
	for _, tt := range tests {
		got, ok := scriptOf(tt.words)
		if got != tt.script || ok != tt.ok {
			t.Errorf("scriptOf(%q) = %q, %v; want %q, %v", tt.words, got, ok, tt.script, tt.ok)
		}
	}
	g := Default()
	for _, c := range []string{
		`bash --rcfile x.rc -c 'printenv'`,
		`sh --init-file x.rc -c env`,
		`bash --rcfile=x.rc -c 'echo $NAME'`,
	} {
		if !g.Match(c, []string{"NAME"}) {
			t.Errorf("Match(%q) should refuse", c)
		}
	}
	if g.Match(`bash --rcfile x.rc -c 'echo hi'`, []string{"NAME"}) {
		t.Error("harmless script should be allowed")
	}
}

// A-F11: the compiled-pattern cache is bounded.
func TestCompiledCacheIsCapped(t *testing.T) {
	g := Default()
	for i := 0; i < maxCompiledSets*3; i++ {
		g.Match("printenv", []string{fmt.Sprintf("NAME_%d", i)})
	}
	if n := g.compiledSets(); n > maxCompiledSets {
		t.Errorf("cache holds %d sets, cap is %d", n, maxCompiledSets)
	}
	if !g.Match("printenv", []string{"NAME_0"}) {
		t.Error("an evicted set must still be matched")
	}
}
