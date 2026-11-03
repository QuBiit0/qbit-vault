//go:build windows

package perm

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, which x/sys/windows does not export.
const fileAllAccess = 0x1F01FF

func userSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, errors.New("perm: cannot read the current user")
	}
	return tu.User.Sid, nil
}

// aclInfo is what check needs to know about a DACL.
type aclInfo struct {
	nullDACL  bool // no DACL, or an empty-permissive one: everyone has access
	protected bool
	allowed   []*windows.SID // SIDs of access-allowed ACEs (copies)
	otherACEs int            // ACEs of a type this package does not interpret
}

func inspect(path string) (aclInfo, error) {
	var info aclInfo
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return info, fmt.Errorf("perm: read ACL: %w", bareErr(err))
	}
	defer runtime.KeepAlive(sd)
	ctrl, _, err := sd.Control()
	if err != nil {
		return info, fmt.Errorf("perm: read ACL: %w", bareErr(err))
	}
	info.protected = ctrl&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		info.nullDACL = true
		return info, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return info, fmt.Errorf("perm: read ACL: %w", bareErr(err))
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid, err := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Copy()
			if err != nil {
				return info, fmt.Errorf("perm: read ACL: %w", bareErr(err))
			}
			info.allowed = append(info.allowed, sid)
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny entry grants nothing.
		default:
			info.otherACEs++
		}
	}
	return info, nil
}

func check(path string) (bool, string) {
	me, err := userSID()
	if err != nil {
		return false, "cannot read the current user"
	}
	info, err := inspect(path)
	switch {
	case err != nil:
		return false, "cannot read the ACL"
	case info.nullDACL:
		return false, "no restrictive ACL: everyone has access"
	case info.otherACEs > 0:
		return false, "ACL has entries of an unsupported type"
	}
	for _, sid := range info.allowed {
		if !sid.Equals(me) {
			return false, "ACL grants access to another account"
		}
	}
	return true, ""
}

func ensure(path string, isDir bool) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("perm: stat: %w", bareErr(err))
	}
	if ok, _ := check(path); ok {
		return nil
	}
	me, err := userSID()
	if err != nil {
		return err
	}
	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileAllAccess,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(me),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("perm: build ACL: %w", bareErr(err))
	}
	// PROTECTED_DACL_SECURITY_INFORMATION disables inheritance from the parent.
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("perm: set ACL: %w", bareErr(err))
	}
	return nil
}

func bareErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
