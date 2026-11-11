package pi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Pi extension refreshes its footer only after QBit Vault's own MCP tools,
// recognized by name (packages/qbit-vault-pi/src/index.ts, GRANT_TOOL). Pi names
// a tool mcp__<server>__<tool> with the server's "-" turned into "_", so the
// pattern must keep matching the server name this adapter registers.
func TestExtensionGrantToolMatchesTheRegisteredServer(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "qbit-vault-pi", "src", "index.ts"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const GRANT_TOOL = /(.+)/;`).FindSubmatch(src)
	if m == nil {
		t.Fatal("GRANT_TOOL not found in packages/qbit-vault-pi/src/index.ts")
	}
	grantTool := regexp.MustCompile(string(m[1]))
	server := strings.ReplaceAll(serverName, "-", "_")
	for _, tool := range []string{"secret_request", "secret_exec", "secret_manage"} {
		if name := "mcp__" + server + "__" + tool; !grantTool.MatchString(name) {
			t.Errorf("GRANT_TOOL %s does not match %s; update it to the server name %q", m[1], name, serverName)
		}
	}
}
