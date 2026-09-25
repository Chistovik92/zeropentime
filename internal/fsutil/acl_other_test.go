// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package fsutil

import "testing"

func checkWindowsACL(*testing.T, string) {}
