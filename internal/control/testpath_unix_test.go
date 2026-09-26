// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package control

import (
	"os"
	"path/filepath"
	"testing"
)

func useTempChannel(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "zptctl") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	old := SocketPath
	SocketPath = filepath.Join(dir, "zpt.sock")
	t.Cleanup(func() { SocketPath = old })
}
