// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/netmark"
)

const killSwitchTable = "zpt_killswitch"

// SetKillSwitch blocks every outgoing packet of this machine except those
// into the given rooms, the node's own (marked) packets, loopback, DHCP,
// IPv6 neighbour discovery and packets to the allowed networks (the LAN).
// The rules stay if the node crashes: "zpt exit off" removes them.
func SetKillSwitch(on bool, rooms []*Room, allowed []netip.Prefix) error {
	if !on {
		DisableKillSwitch()
		return nil
	}
	var ifaces, v4, v6 []string
	for _, r := range rooms {
		if r.tdev != nil {
			ifaces = append(ifaces, `"`+r.ifname+`"`)
		}
	}
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	rules := []string{
		`oifname "lo" accept`,
		fmt.Sprintf("meta mark %d accept", netmark.Mark),
		"udp dport { 67, 547 } accept",
		"icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
	}
	if len(ifaces) > 0 {
		rules = append(rules, "oifname { "+strings.Join(ifaces, ", ")+" } accept")
	}
	if len(v4) > 0 {
		rules = append(rules, "ip daddr { "+strings.Join(v4, ", ")+" } accept")
	}
	if len(v6) > 0 {
		rules = append(rules, "ip6 daddr { "+strings.Join(v6, ", ")+" } accept")
	}
	rules = append(rules, "reject with icmpx type admin-prohibited")
	script := fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
  chain output {
    type filter hook output priority 0;
    %[2]s
  }
}
`, killSwitchTable, strings.Join(rules, "\n    "))
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, out)
	}
	return nil
}

// DisableKillSwitch removes the kill switch, also one left by a crashed node.
func DisableKillSwitch() {
	exec.Command("nft", "delete", "table", "inet", killSwitchTable).Run()
}
