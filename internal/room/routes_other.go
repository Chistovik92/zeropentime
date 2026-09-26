// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !linux && !darwin

package room

import (
	"errors"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func setRoute(tun.Device, string, netip.Prefix, bool) error {
	return errors.New("routes are not supported on this OS yet")
}

func enableRouter(string, netip.Prefix, []netip.Prefix, bool, int, int) error {
	return errors.New("subnet router and exit node modes are supported on Linux only for now")
}
func disableRouter(string) {}
func enableExit(tun.Device, string) error {
	return errors.New("going through an exit node is not supported on this OS yet")
}
func disableExit(tun.Device, string) {}
func setDNS(tun.Device, string, []netip.Addr) error {
	return errors.New("DNS settings are not supported on this OS yet")
}
