// SPDX-License-Identifier: MPL-2.0

package fsutil

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// aces returns the access entries of an SDDL string, e.g. "(A;;FA;;;SY)...".
func aces(sddl string) string {
	if i := strings.Index(sddl, "("); i >= 0 {
		return sddl[i:]
	}
	return ""
}

func checkWindowsACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	got := sd.String()
	if !strings.HasPrefix(got, "D:P") {
		t.Errorf("%s: DACL is not protected from inheritance: %s", path, got)
	}
	// Build the expected descriptor the same way, so Windows renders SIDs
	// identically (e.g. the built-in Administrator account becomes "LA").
	format := fileSDDL
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		format = dirSDDL
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	want, err := windows.SecurityDescriptorFromString(fmt.Sprintf(format, sid))
	if err != nil {
		t.Fatal(err)
	}
	if aces(got) != aces(want.String()) {
		t.Errorf("%s: access entries\n got  %s\n want %s", path, aces(got), aces(want.String()))
	}
	for _, other := range []string{";BU)", ";WD)", ";AU)"} {
		if strings.Contains(got, other) {
			t.Errorf("%s: grants access to %s: %s", path, other, got)
		}
	}
}
