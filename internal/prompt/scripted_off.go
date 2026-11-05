//go:build !e2eprompt

package prompt

// testBackend is the hook for a backend that only test builds contain. A
// release build (no e2eprompt tag) has none, so no QBIT_VAULT_PROMPT value
// reaches one: every unknown name is ErrUnknownBackend.
func testBackend(string, Env) (Backend, bool) { return nil, false }
