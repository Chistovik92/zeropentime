// SPDX-License-Identifier: MPL-2.0

package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFileIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zpt")
	path := filepath.Join(dir, "secret")
	if err := WriteFile(path, []byte("key")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "key" {
		t.Fatalf("content %q", got)
	}
	if runtime.GOOS == "windows" {
		checkWindowsACL(t, dir)
		checkWindowsACL(t, path)
		return
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", p, st.Mode().Perm(), want)
		}
	}
}
