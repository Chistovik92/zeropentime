// SPDX-License-Identifier: MPL-2.0

package dnsfwd

import (
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// SystemResolvers are the DNS servers of this machine's working network
// adapters, except the rooms' own interfaces (zpt-*).
func SystemResolvers() []netip.AddrPort {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, a := range adapters {
		if a.OperStatus != winipcfg.IfOperStatusUp || strings.HasPrefix(a.FriendlyName(), "zpt-") {
			continue
		}
		for dns := a.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			if ip, ok := netip.AddrFromSlice(dns.Address.IP()); ok {
				ap := netip.AddrPortFrom(ip.Unmap().WithZone(""), 53)
				if !ip.IsLinkLocalUnicast() && !containsAP(out, ap) {
					out = append(out, ap)
				}
			}
		}
	}
	return out
}

func containsAP(list []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}
