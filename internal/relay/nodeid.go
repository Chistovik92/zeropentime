// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"encoding/base32"
	"strings"
)

// Must match identity.NodeIDFromPublic: lowercase unpadded base32 of 10 bytes.
var nodeIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func upper(s string) string { return strings.ToUpper(s) }
func lower(s string) string { return strings.ToLower(s) }
