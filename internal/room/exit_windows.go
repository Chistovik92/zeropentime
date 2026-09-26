// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

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

// nrptKey is the Name Resolution Policy Table rule that sends every name
// (".") to the exit's DNS server whatever interface Windows prefers.
const nrptKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{7a707a70-e417-4d05-9a3a-5f2d1e0c7a70}`

func setDNS(dev tun.Device, _ string, servers []netip.Addr) error {
	luid, err := luidOf(dev)
	if err != nil {
		return err
	}
	defer exec.Command("ipconfig", "/flushdns").Run()
	if len(servers) == 0 {
		registry.DeleteKey(registry.LOCAL_MACHINE, nrptKey)
		return errors.Join(luid.FlushDNS(windows.AF_INET), luid.FlushDNS(windows.AF_INET6))
	}
	var v4, v6 []netip.Addr
	var list []string
	for _, a := range servers {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
		list = append(list, a.String())
	}
	if err := luid.SetDNS(windows.AF_INET, v4, nil); err != nil {
		return fmt.Errorf("set DNS servers: %w", err)
	}
	if len(v6) > 0 {
		luid.SetDNS(windows.AF_INET6, v6, nil)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("NRPT rule: %w (DNS queries may go to other servers too)", err)
	}
	defer k.Close()
	return errors.Join(
		k.SetDWordValue("Version", 2),
		k.SetStringsValue("Name", []string{"."}),
		k.SetStringValue("GenericDNSServers", strings.Join(list, ";")),
		k.SetDWordValue("ConfigOptions", 8), // generic DNS servers
		k.SetStringValue("IPSECCARestriction", ""),
	)
}
