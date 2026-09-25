// SPDX-License-Identifier: MPL-2.0

package fsutil

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func checkWindowsACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	sid, _ := currentUserSID()
	if !strings.Contains(sddl, "D:P") {
		t.Errorf("%s: DACL is not protected from inheritance: %s", path, sddl)
	}
	for _, who := range []string{"SY", "BA", sid} {
		if !strings.Contains(sddl, ";;;"+who+")") {
			t.Errorf("%s: no entry for %s: %s", path, who, sddl)
		}
	}
	// Exactly three entries: nobody else (Users, Everyone, Authenticated Users).
	if n := strings.Count(sddl, "(A;"); n != 3 {
		t.Errorf("%s: %d access entries, want 3: %s", path, n, sddl)
	}
	for _, other := range []string{";BU)", ";WD)", ";AU)"} {
		if strings.Contains(sddl, other) {
			t.Errorf("%s: grants access to %s: %s", path, other, sddl)
		}
	}
}
