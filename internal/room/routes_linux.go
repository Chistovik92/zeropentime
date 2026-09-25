// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func setRoute(_ tun.Device, name string, p netip.Prefix, add bool) error {
	verb := "replace"
	if !add {
		verb = "del"
	}
	if out, err := exec.Command("ip", "route", verb, p.String(), "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip route %s %s: %w: %s", verb, p, err, out)
	}
	return nil
}

// nftTable is the per-room nftables table of a subnet router.
func nftTable(ifname string) string { return "zpt_" + strings.ReplaceAll(ifname, "-", "_") }

// enableRouter lets members of the room reach the given networks through
// this node: IP forwarding plus masquerade of room traffic into them.
func enableRouter(ifname string, room netip.Prefix, routes []netip.Prefix) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip forwarding: %w", err)
	}
	var dst []string
	for _, r := range routes {
		dst = append(dst, r.String())
	}
	t := nftTable(ifname)
	rules := fmt.Sprintf(`table ip %[1]s
delete table ip %[1]s
table ip %[1]s {
  chain postrouting {
    type nat hook postrouting priority 100;
    iifname "%[2]s" ip saddr %[3]s ip daddr { %[4]s } masquerade
  }
  chain forward {
    type filter hook forward priority 0;
    iifname "%[2]s" ip saddr %[3]s ip daddr { %[4]s } accept
    oifname "%[2]s" ct state established,related accept
  }
}
`, t, ifname, room.Masked(), strings.Join(dst, ", "))
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, out)
	}
	return nil
}

func disableRouter(ifname string) {
	exec.Command("nft", "delete", "table", "ip", nftTable(ifname)).Run()
}
