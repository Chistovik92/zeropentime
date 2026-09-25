// SPDX-License-Identifier: MPL-2.0

// Package testutil has helpers shared by tests.
package testutil

import (
	"os"
	"testing"
	"time"
)

// TempDir is like t.TempDir, but retries the removal for a while: on
// Windows an antivirus may briefly hold freshly written database files,
// which makes t.TempDir's cleanup fail the test.
func TempDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "zpt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var err error
		for range 50 {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("could not remove %s: %v", dir, err)
	})
	return dir
}
