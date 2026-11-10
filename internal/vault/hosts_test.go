package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/qbitdevz/qbit-vault/internal/filemerge"
	"github.com/qbitdevz/qbit-vault/internal/secret"
)

func sampleHost(t *testing.T) HostState {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "cfg", "config.json")
	return HostState{
		RegisteredAt: "2026-11-04T00:00:00Z",
		Registered:   []string{"mcp"},
		Receipts: map[string]filemerge.Receipt{
			"mcp": {
				Path:     cfg,
				Snapshot: filemerge.Snapshot{Path: cfg, Existed: true, Backup: filepath.Join(filepath.Dir(cfg), "bk", "config.json")},
				SHA256:   "abc",
				Created:  false,
				Exact:    true,
			},
		},
	}
}

func TestHostsRoundTripKeepsTheRestOfState(t *testing.T) {
	v, home := newVault(t)
	if hs, err := ReadHosts(home); err != nil || len(hs) != 0 {
		t.Fatalf("fresh vault: %+v %v", hs, err)
	}
	remote := Remote{Server: "https://vault.example", AccountID: "a", Generation: 1}
	if err := WriteRemote(home, &remote); err != nil {
		t.Fatal(err)
	}
	want := sampleHost(t)
	if err := WriteHost(home, "fake", &want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadHosts(home)
	if err != nil || !reflect.DeepEqual(got["fake"], want) {
		t.Fatalf("got %+v %v", got, err)
	}
	if r, err := ReadRemote(home); err != nil || r == nil || *r != remote {
		t.Fatalf("remote lost: %+v %v", r, err)
	}
	// A later vault save keeps the hosts section.
	mustPut(t, v, Layer{}, "SOME_NAME", Record{Value: secret.New("v", []byte("TESTSECRET_x"))})
	if hs, err := ReadHosts(home); err != nil || !reflect.DeepEqual(hs["fake"], want) {
		t.Fatalf("vault save dropped hosts: %+v %v", hs, err)
	}
	if err := WriteHost(home, "fake", nil); err != nil {
		t.Fatal(err)
	}
	if hs, _ := ReadHosts(home); len(hs) != 0 {
		t.Fatalf("not removed: %+v", hs)
	}
	if r, _ := ReadRemote(home); r == nil {
		t.Fatal("removing a host dropped remote")
	}
}

func TestHostsStoredWithAbsolutePathsOnly(t *testing.T) {
	_, home := newVault(t)
	for name, mut := range map[string]func(*HostState){
		"receipt path":    func(h *HostState) { r := h.Receipts["mcp"]; r.Path = "~/.claude/settings.json"; h.Receipts["mcp"] = r },
		"snapshot path":   func(h *HostState) { r := h.Receipts["mcp"]; r.Snapshot.Path = "rel/x"; h.Receipts["mcp"] = r },
		"snapshot backup": func(h *HostState) { r := h.Receipts["mcp"]; r.Snapshot.Backup = "bk/x"; h.Receipts["mcp"] = r },
	} {
		h := sampleHost(t)
		mut(&h)
		before, _ := os.ReadFile(filepath.Join(home, "state.json"))
		if err := WriteHost(home, "fake", &h); err == nil {
			t.Fatalf("%s: relative path accepted", name)
		}
		after, _ := os.ReadFile(filepath.Join(home, "state.json"))
		if string(before) != string(after) {
			t.Fatalf("%s: state changed by a refused write", name)
		}
	}
	if err := WriteHost(home, "../evil", &HostState{}); err == nil {
		t.Fatal("bad host name accepted")
	}
}

func TestReadHostsRejectsMalformedSection(t *testing.T) {
	_, home := newVault(t)
	p := filepath.Join(home, "state.json")
	b, _ := os.ReadFile(p)
	bad := append(append([]byte(nil), b[:len(b)-2]...), []byte(`, "hosts": 5}`)...)
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHosts(home); err == nil {
		t.Fatal("malformed hosts accepted")
	}
}
