package dumpguard

import "testing"

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
