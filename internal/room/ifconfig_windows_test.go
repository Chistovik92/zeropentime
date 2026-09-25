// SPDX-License-Identifier: MPL-2.0

package room

import "testing"

func TestSafeIfname(t *testing.T) {
	for _, ok := range []string{"zpt-game", "zpt-igry", "zpt-r1a2b3c"} {
		if !safeIfname(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", `zpt-x'; Remove-Item C:/ -Recurse #`, "zpt game", "ZPT-GAME", "zpt-игры"} {
		if safeIfname(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
