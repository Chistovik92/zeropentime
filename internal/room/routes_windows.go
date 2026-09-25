// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func setRoute(dev tun.Device, _ string, p netip.Prefix, add bool) error {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("unexpected TUN type %T", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	if add {
		return luid.AddRoute(p, netip.IPv4Unspecified(), 0)
	}
	return luid.DeleteRoute(p, netip.IPv4Unspecified())
}
