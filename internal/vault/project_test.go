package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mkRepo creates dir/name with a .git directory (or a worktree-style .git file).
func mkRepo(t *testing.T, dir, name string, gitFile bool) string {
	t.Helper()
	root := filepath.Join(dir, name)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	git := filepath.Join(root, ".git")
	if gitFile {
		if err := os.WriteFile(git, []byte("gitdir: ../elsewhere\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Mkdir(git, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func mkDir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// skipIfInsideRepo guards "outside a repository" cases against a temp dir
// that happens to live under a Git checkout.
func skipIfInsideRepo(t *testing.T, dir string) {
	t.Helper()
	if _, ok, err := ProjectRoot(dir); err != nil || ok {
		t.Skip("temp dir is inside a repository")
	}
}

func canonical(t *testing.T, p string) string {
	t.Helper()
	root, ok, err := ProjectRoot(p)
	if err != nil || !ok {
		t.Fatalf("ProjectRoot(%q): ok=%v err=%v", p, ok, err)
	}
	return root
}

func TestProjectRoot(t *testing.T) {
	tmp := t.TempDir()
	repo := mkRepo(t, tmp, "shop-api", false)
	sub := mkDir(t, repo, "pkg", "deep")
	nested := mkRepo(t, repo, "vendored", false)
	worktree := mkRepo(t, tmp, "shop-api-wt", true)

	tests := []struct {
		name string
		cwd  string
		want string // expected root, "" = none
	}{
		{"repo root itself", repo, repo},
		{"subdirectory", sub, repo},
		{"nested repo is nearest", mkDir(t, nested, "x"), nested},
		{"worktree .git file counts", worktree, worktree},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := ProjectRoot(tt.cwd)
			if err != nil || !ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if got != canonicalPath(t, tt.want) {
				t.Fatalf("root = %q, want %q", got, canonicalPath(t, tt.want))
			}
		})
	}

	t.Run("outside a repository", func(t *testing.T) {
		outside := mkDir(t, t.TempDir(), "plain")
		skipIfInsideRepo(t, outside)
		if _, ok, err := ProjectRoot(outside); ok || err != nil {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
	t.Run("missing cwd is an error", func(t *testing.T) {
		_, _, err := ProjectRoot(filepath.Join(tmp, "does-not-exist"))
		if err == nil || strings.Contains(err.Error(), "does-not-exist") {
			t.Fatalf("err = %v", err)
		}
	})
}

// canonicalPath mirrors the documented canonicalization for expectations.
func canonicalPath(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		real = strings.ToLower(real)
	}
	return real
}

func TestProjectRootCaseFolded(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("case folding applies to windows and darwin only")
	}
	repo := mkRepo(t, t.TempDir(), "MixedCase", false)
	a := canonical(t, repo)
	b := canonical(t, filepath.Join(filepath.Dir(repo), "MIXEDCASE"))
	if a != b || a != strings.ToLower(a) {
		t.Fatalf("roots differ or not folded: %q vs %q", a, b)
	}
}

func TestProjectRootResolvesSymlinks(t *testing.T) {
	tmp := t.TempDir()
	repo := mkRepo(t, tmp, "real", false)
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(repo, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if canonical(t, link) != canonical(t, repo) {
		t.Fatal("symlinked cwd resolved to a different root")
	}
}

func TestProjectLayer(t *testing.T) {
	tmp := t.TempDir()
	repo := mkRepo(t, tmp, "Shop-API", false)
	l, err := ProjectLayer(mkDir(t, repo, "sub"))
	if err != nil || !l.Project || l.Root != canonical(t, repo) || l.Label != "Shop-API" {
		t.Fatalf("layer = %+v err=%v", l, err)
	}
	outside := mkDir(t, t.TempDir(), "plain")
	skipIfInsideRepo(t, outside)
	if _, err := ProjectLayer(outside); !errors.Is(err, ErrNoProject) {
		t.Fatalf("err = %v, want ErrNoProject", err)
	}
}
