// SPDX-License-Identifier: MPL-2.0

//go:build !linux && !windows

package netmark

func mark(uintptr) {}
