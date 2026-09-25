// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package fsutil

import "os"

func secureDir(dir string) error   { return os.Chmod(dir, 0o700) }
func secureFile(path string) error { return os.Chmod(path, 0o600) }
