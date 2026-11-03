//go:build windows

package perm

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func currentSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// assertOwnerOnly reads the DACL back and checks for exactly one allowed ACE,
// for the current user.
func assertOwnerOnly(t *testing.T, path string, wantProtected bool) {
	t.Helper()
	info, err := inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.nullDACL {
		t.Fatal("DACL is null (everyone has access)")
	}
	if len(info.allowed) != 1 || !info.allowed[0].Equals(currentSID(t)) {
		t.Fatalf("want exactly one allowed ACE for the current user, got %d", len(info.allowed))
	}
	if info.otherACEs != 0 {
		t.Fatalf("%d ACEs of unsupported type", info.otherACEs)
	}
	if wantProtected && !info.protected {
		t.Fatal("DACL is not protected from inheritance")
	}
}

func TestWindowsEnsureFileSetsOwnerOnlyProtectedDACL(t *testing.T) {
	f := filepath.Join(t.TempDir(), "vault.enc")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFile(f); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, f, true)
	if ok, detail := Check(f); !ok {
		t.Fatalf("Check after EnsureFile: %s", detail)
	}
}

func TestWindowsCheckReportsOtherPrincipals(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Grant Everyone read access by hand, keeping the file otherwise private.
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{AccessPermissions: windows.GENERIC_READ, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(everyone)}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Check(f); ok || detail == "" {
		t.Fatalf("Check = %v, %q; want a report of another principal", ok, detail)
	}
	if err := EnsureFile(f); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, f, true)
}

func TestWindowsEnsureDirIsInheritedByNewFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, dir, true)
	f := filepath.Join(dir, "state.json")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, f, false)
	if ok, detail := Check(f); !ok {
		t.Fatalf("file created in a private dir is not private: %s", detail)
	}
}
