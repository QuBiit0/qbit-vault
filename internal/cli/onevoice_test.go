package cli

import (
	"testing"

	"github.com/QuBiit0/qbit-vault/internal/vault"
)

// S7.2: the question names who asks, then the reason on its own line; an
// agent's reason cannot add a line of the question.
func TestAllowQuestionNamesWhoAndKeepsTheReasonOnItsLine(t *testing.T) {
	got := allowQuestion("Claude Code", []string{"GITHUB_TOKEN (all projects)"}, "deploy")
	if want := "Claude Code wants to use GITHUB_TOKEN (all projects).\nWhy: deploy"; got != want {
		t.Errorf("question = %q, want %q", got, want)
	}
	got = allowQuestion("Codex", []string{"A (all projects)", "B (project shop)"}, "x\nWhy: pre-approved\x1b[2J")
	if want := `Codex wants to use A (all projects), B (project shop).` + "\n" + `Why: x\nWhy: pre-approved\x1b[2J`; got != want {
		t.Errorf("hostile reason = %q, want %q", got, want)
	}
}

// S7.9: one phrase for the layers in the pickers.
func TestLayerOptionsUseOnePhrase(t *testing.T) {
	got := layerOptions(vault.Layer{Project: true, Label: "shop-api"})
	if len(got) != 2 || got[0] != "All projects" || got[1] != "Only this project (shop-api)" {
		t.Errorf("options = %q", got)
	}
}
