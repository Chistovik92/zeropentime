// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package main

// requireAdmin is a no-op: on Unix the TUN device itself reports missing
// root or CAP_NET_ADMIN, which is also allowed without full root.
func requireAdmin() error { return nil }
