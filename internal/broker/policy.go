package broker

import "strings"

// PolicyCan and PolicyCannot are the normative strings of CONTRACT.md § list;
// a test compares them with the contract byte for byte.
var (
	PolicyCan = []string{
		"List secret names and metadata visible from this directory with secret_list.",
		"Ask the user for one or several secrets (up to 8 fields, each secret or plain text) with a concrete reason using secret_request; the user types them outside the chat.",
		"Run commands with granted secrets using secret_exec or the shell tool; output comes back redacted.",
		"Propose removing, editing, moving (global <-> this project) or replacing a secret using secret_manage; the user confirms or declines.",
	}
	PolicyCannot = []string{
		"Read, print, copy or receive any secret value.",
		"Create or widen a grant; only the user grants access.",
		"Apply any change without the user's confirmation.",
		"Reach the secrets of another project.",
		"Print the environment (env, printenv, set, /proc/*/environ, ...) while secrets are injected.",
		"Use a secret with a binary outside its allowlist.",
		"Re-ask for a name the user declined during its cooldown.",
		"Configure sync, pair or revoke devices, or link a project layer; only the user can.",
	}
)

// policy builds the block for a list result.
func policy(inProject bool, cooldowns []Cooldown) Policy {
	layers := []string{"global"}
	if inProject {
		layers = append(layers, "project")
	}
	if cooldowns == nil {
		cooldowns = []Cooldown{}
	}
	return Policy{
		Can:       append([]string(nil), PolicyCan...),
		Cannot:    append([]string(nil), PolicyCannot...),
		Layers:    layers,
		Scopes:    []string{"once", "session", "project"},
		Cooldowns: cooldowns,
	}
}

// Instructions is the MCP server's `instructions`: the same policy text.
func Instructions() string {
	var b strings.Builder
	b.WriteString("gentle-vault: use credentials without seeing them.\nYou can:\n")
	for _, s := range PolicyCan {
		b.WriteString("- " + s + "\n")
	}
	b.WriteString("You cannot:\n")
	for _, s := range PolicyCannot {
		b.WriteString("- " + s + "\n")
	}
	return b.String()
}
