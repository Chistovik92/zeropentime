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
	var cmds [][]string
	if addr.Addr().Is4() {
		cmds = [][]string{
			{"ifconfig", name, "inet", addr.String(), addr.Addr().String(), "mtu", strconv.Itoa(mtu), "up"},
			{"route", "-q", "-n", "add", "-inet", addr.Masked().String(), "-interface", name},
		}
	} else {
		cmds = [][]string{
			{"ifconfig", name, "inet6", addr.String(), "mtu", strconv.Itoa(mtu), "up"},
		}
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, out)
		}
	}
	return nil
}
