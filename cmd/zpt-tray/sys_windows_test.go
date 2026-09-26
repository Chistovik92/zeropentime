// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"testing"
)

// Only in CI: the test replaces the clipboard for a moment.
func TestClipboard(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("CI only")
	}
	old, _ := getClipboard()
	defer setClipboard(old)
	want := "10.7.0.3 комната ✓"
	if err := setClipboard(want); err != nil {
		t.Fatal(err)
	}
	if got, err := getClipboard(); err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
}
