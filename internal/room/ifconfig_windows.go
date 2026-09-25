// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func configureInterface(dev tun.Device, _ string, addr netip.Prefix, mtu int) error {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("unexpected TUN type %T", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	// Windows adds the on-link route for the subnet together with the address.
	if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if addr.Addr().Is6() {
		family = windows.AF_INET6
	}
	iface, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	iface.NLMTU = uint32(mtu)
	iface.ForwardingEnabled = false
	if err := iface.Set(); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}
	return nil
}
