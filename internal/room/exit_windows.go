// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/Chistovik92/zeropentime/internal/netmark"
)

// Exit client on Windows: two halves of the IPv4 space through the room
// win over the ordinary default route without touching it; the node's
// own sockets are bound to the physical interface (netmark.SetBypass).
// The exit carries IPv4 only: the IPv6 internet gets the same routes into
// the room, where nothing answers, so apps fall back to IPv4 instead of
// leaking.
var exitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
}

func luidOf(dev tun.Device) (winipcfg.LUID, error) {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return 0, fmt.Errorf("unexpected TUN type %T", dev)
	}
	return winipcfg.LUID(nt.LUID()), nil
}

func enableExit(dev tun.Device, _ string) error {
	luid, err := luidOf(dev)
	if err != nil {
		return err
	}
	netmark.SetBypass(true)
	for _, p := range exitRoutes {
		hop := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			hop = netip.IPv6Unspecified()
		}
		err := luid.AddRoute(p, hop, 0)
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) && p.Addr().Is4() {
			disableExit(dev, "")
			return fmt.Errorf("add route %s: %w", p, err)
		}
	}
	return nil
}

func disableExit(dev tun.Device, _ string) {
	if luid, err := luidOf(dev); err == nil {
		for _, p := range exitRoutes {
			hop := netip.IPv4Unspecified()
			if p.Addr().Is6() {
				hop = netip.IPv6Unspecified()
			}
			luid.DeleteRoute(p, hop)
		}
	}
	netmark.SetBypass(false)
}

// nrptBase is where the Name Resolution Policy Table rules live; each
// room has its own rule sending its zone (and, when it carries this
// machine's DNS, every name ".") to the room's DNS server.
const nrptBase = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\`

// oldNRPTKey is the single rule of 0.3.2 – 0.3.6.
const oldNRPTKey = nrptBase + `{7a707a70-e417-4d05-9a3a-5f2d1e0c7a70}`

func setDNS(dev tun.Device, ifname string, own netip.Addr, zone string, carrier bool) error {
	luid, err := luidOf(dev)
	if err != nil {
		return err
	}
	defer exec.Command("ipconfig", "/flushdns").Run()
	registry.DeleteKey(registry.LOCAL_MACHINE, oldNRPTKey)
	key := nrptBase + "zeropentime-" + ifname
	if !own.IsValid() || zone == "" && !carrier {
		registry.DeleteKey(registry.LOCAL_MACHINE, key)
		return luid.FlushDNS(windows.AF_INET)
	}
	if carrier {
		if err := luid.SetDNS(windows.AF_INET, []netip.Addr{own}, nil); err != nil {
			return fmt.Errorf("set DNS server: %w", err)
		}
	} else {
		luid.FlushDNS(windows.AF_INET)
	}
	var names []string
	if zone != "" {
		names = append(names, "."+zone)
	}
	if carrier {
		names = append(names, ".")
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("NRPT rule: %w", err)
	}
	defer k.Close()
	return errors.Join(
		k.SetDWordValue("Version", 2),
		k.SetStringsValue("Name", names),
		k.SetStringValue("GenericDNSServers", own.String()),
		k.SetDWordValue("ConfigOptions", 8), // generic DNS servers
		k.SetStringValue("IPSECCARestriction", ""),
	)
}
