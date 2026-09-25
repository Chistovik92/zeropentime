// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func configureInterface(_ tun.Device, name string, addr netip.Prefix, mtu int, _ *slog.Logger) error {
	cmds := [][]string{
		// "brd +": the subnet broadcast address must be a broadcast for the
		// kernel on this point-to-point device, or LAN discovery breaks.
		{"ip", "address", "add", addr.String(), "brd", "+", "dev", name},
		// Multicast must be on for mDNS / SSDP / game discovery.
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "multicast", "on", "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, out)
		}
	}
	return nil
}
