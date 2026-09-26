// SPDX-License-Identifier: MPL-2.0

package room

import (
	"net/netip"

	"github.com/Chistovik92/zeropentime/internal/wgfirewall"
)

// SetKillSwitch blocks all traffic of this machine except through the
// given rooms, of the node itself, loopback, DHCP, IPv6 neighbour
// discovery and to the allowed networks (the LAN), with the WFP firewall
// of wireguard-windows. Windows removes the rules when the node exits.
func SetKillSwitch(on bool, rooms []*Room, allowed []netip.Prefix) error {
	if !on {
		DisableKillSwitch()
		return nil
	}
	var luids []uint64
	for _, r := range rooms {
		if r.tdev == nil {
			continue
		}
		if luid, err := luidOf(r.tdev); err == nil {
			luids = append(luids, uint64(luid))
		}
	}
	return wgfirewall.EnableFirewall(luids, allowed, false, nil)
}

// DisableKillSwitch removes the kill switch.
func DisableKillSwitch() { wgfirewall.DisableFirewall() }
