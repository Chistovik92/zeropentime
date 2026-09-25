// SPDX-License-Identifier: MPL-2.0

// Package fsutil stores secrets (node key, state) readable only by their
// owner, the administrators and the system.
package fsutil

import (
	"os"
	"path/filepath"
)

// SecureDir creates dir if needed and restricts access to it: 0700 on Unix;
// on Windows a protected ACL for SYSTEM, Administrators and the current user,
// inherited by files created inside.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return secureDir(dir)
}

// SecureFile restricts access to an existing file the same way (0600 on Unix).
func SecureFile(path string) error { return secureFile(path) }

// WriteFile atomically writes a secret file inside a secured directory.
func WriteFile(path string, data []byte) error {
	if err := SecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := secureFile(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
