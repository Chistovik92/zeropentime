// SPDX-License-Identifier: MPL-2.0

// Package fsutil stores secrets (node key, state) readable only by their
// owner, the administrators and the system.
package fsutil

import (
	"os"
	"path/filepath"
	"time"
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
	// A temporary file of its own: the CLI and the service may write at
	// the same time.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = secureFile(tmp)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	// On Windows the file cannot be replaced while another process is
	// reading it: try again for a moment.
	for i := 0; ; i++ {
		err = os.Rename(tmp, path)
		if err == nil || i == 20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// ReadFile reads a file written by WriteFile, retrying for a moment if it
// is being replaced right now (Windows).
func ReadFile(path string) ([]byte, error) {
	for i := 0; ; i++ {
		b, err := os.ReadFile(path)
		if err == nil || os.IsNotExist(err) || i == 20 {
			return b, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
