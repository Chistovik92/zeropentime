// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func configureInterface(_ tun.Device, name string, addr netip.Prefix, mtu int) error {
	cmds := [][]string{
		{"ip", "address", "add", addr.String(), "dev", name},
		{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, out)
		}
	}
	return nil
}
