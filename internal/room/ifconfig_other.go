// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !linux && !darwin

package room

import (
	"errors"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func configureInterface(tun.Device, string, netip.Prefix, int) error {
	return errors.New("system interfaces are not supported on this OS yet; use userspace: true")
}
