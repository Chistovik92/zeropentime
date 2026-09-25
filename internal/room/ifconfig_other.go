// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !linux && !darwin

package room

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func configureInterface(tun.Device, string, netip.Prefix, int, *slog.Logger) error {
	return errors.New("system interfaces are not supported on this OS yet; use userspace: true")
}
