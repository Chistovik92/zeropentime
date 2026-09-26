// SPDX-License-Identifier: MPL-2.0

package update

import "unsafe"

func unsafePtr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }
