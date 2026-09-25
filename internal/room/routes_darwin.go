// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func setRoute(_ tun.Device, name string, p netip.Prefix, add bool) error {
	verb := "add"
	if !add {
		verb = "delete"
	}
	if out, err := exec.Command("route", "-q", "-n", verb, "-net", p.String(), "-interface", name).CombinedOutput(); err != nil {
		return fmt.Errorf("route %s %s: %w: %s", verb, p, err, out)
	}
	return nil
}

var errNoRouter = errors.New("subnet router mode is supported on Linux only for now")

func enableRouter(string, netip.Prefix, []netip.Prefix) error { return errNoRouter }
func disableRouter(string)                                    {}
