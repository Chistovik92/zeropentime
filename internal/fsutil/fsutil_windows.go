// SPDX-License-Identifier: MPL-2.0

package fsutil

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Protected DACL: no inherited entries from parent folders (ProgramData
// grants read access to all users), full control for SYSTEM (SY),
// Administrators (BA) and the current user.
const (
	dirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)"
	fileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)"
)

func currentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func applySDDL(path, sddlFormat string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(sddlFormat, sid))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func secureDir(dir string) error   { return applySDDL(dir, dirSDDL) }
func secureFile(path string) error { return applySDDL(path, fileSDDL) }
