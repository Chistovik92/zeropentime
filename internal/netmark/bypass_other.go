// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package netmark

import "syscall"

// Track is needed only on Windows: marks stay on a socket for its lifetime.
func Track(syscall.Conn) (untrack func()) { return func() {} }

// SetBypass is needed only on Windows (see mark_windows.go).
func SetBypass(bool) {}
