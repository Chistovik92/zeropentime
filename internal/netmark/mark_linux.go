// SPDX-License-Identifier: MPL-2.0

package netmark

import "syscall"

func mark(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Mark) }
