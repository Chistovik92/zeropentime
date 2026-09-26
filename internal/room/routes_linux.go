// SPDX-License-Identifier: MPL-2.0

package room

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/tun"

	"github.com/Chistovik92/zeropentime/internal/netmark"
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

// nftTable is the per-room nftables table of a subnet router / exit node.
func nftTable(ifname string) string { return "zpt_" + strings.ReplaceAll(ifname, "-", "_") }

// enableRouter lets members of the room reach the given networks through
// this node, and with exit the internet: IP forwarding plus masquerade of
// room traffic.
// limit and total are an exit's speed limits in bytes per second, per
// client and in total, in each direction (0: none).
func enableRouter(ifname string, room netip.Prefix, routes []netip.Prefix, exit bool, limit, total int) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip forwarding: %w", err)
	}
	var dst []string
	for _, r := range routes {
		dst = append(dst, r.String())
	}
	var nat, fwd []string
	from := fmt.Sprintf(`iifname "%s" ip saddr %s`, ifname, room.Masked())
	if len(dst) > 0 {
		set := "{ " + strings.Join(dst, ", ") + " }"
		nat = append(nat, from+" ip daddr "+set+" masquerade")
		fwd = append(fwd, from+" ip daddr "+set+" accept")
	}
	var sets []string
	if exit {
		out := fmt.Sprintf(`oifname != "%s"`, ifname)
		back := fmt.Sprintf(`oifname "%s" ip daddr %s iifname != "%s"`, ifname, room.Masked(), ifname)
		var private []string
		for _, p := range privateNets {
			private = append(private, p.String())
		}
		rate := func(bps int) string {
			return fmt.Sprintf("limit rate over %d kbytes/second burst %d kbytes", max(bps/1024, 1), max(bps/1024/10, 64))
		}
		if limit > 0 {
			sets = append(sets,
				"set rl_up { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }",
				"set rl_down { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m; }")
			fwd = append(fwd, from+" "+out+" update @rl_up { ip saddr "+rate(limit)+" } drop",
				back+" update @rl_down { ip daddr "+rate(limit)+" } drop")
		}
		if total > 0 {
			fwd = append(fwd, from+" "+out+" "+rate(total)+" drop", back+" "+rate(total)+" drop")
		}
		fwd = append(fwd, from+" ip daddr { "+strings.Join(private, ", ")+" } drop", from+" "+out+" accept")
		nat = append(nat, from+" "+out+" masquerade")
	}
	t := nftTable(ifname)
	rules := fmt.Sprintf(`table ip %[1]s
delete table ip %[1]s
table ip %[1]s {
  %[5]s
  chain postrouting {
    type nat hook postrouting priority 100;
    %[3]s
  }
  chain forward {
    type filter hook forward priority 0;
    %[4]s
    oifname "%[2]s" ct state established,related accept
  }
}
`, t, ifname, strings.Join(nat, "\n    "), strings.Join(fwd, "\n    "), strings.Join(sets, "\n  "))
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

// Exit client: like wg-quick, the default route lives in its own table,
// used by every packet without the node's mark; the main table still wins
// for everything more specific than a default route (the LAN, rooms,
// approved networks). The exit carries IPv4 only, so the IPv6 internet is
// made unreachable meanwhile: apps fall back to IPv4 instead of leaking.
const (
	exitTable    = netmark.Mark // routing table and rule priority
	exitMainPref = exitTable - 1
	exitNftTable = "zpt_exit"
)

var (
	exitMu    sync.Mutex
	exitRooms = map[string]bool{}
)

func ipCmd(args ...string) error {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func enableExit(_ tun.Device, ifname string) error {
	exitMu.Lock()
	defer exitMu.Unlock()
	table := strconv.Itoa(exitTable)
	if err := ipCmd("-4", "route", "replace", "default", "dev", ifname, "table", table); err != nil {
		return err
	}
	if len(exitRooms) == 0 {
		// Replies to the node's marked packets get the mark back from
		// conntrack, so reverse path filtering accepts them.
		os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0o644)
		delExitRules()
		nft := exec.Command("nft", "-f", "-")
		nft.Stdin = strings.NewReader(fmt.Sprintf(`table inet %[1]s {
  chain premangle {
    type filter hook prerouting priority -150;
    meta mark set ct mark
  }
  chain postmangle {
    type filter hook postrouting priority -150;
    meta mark %[2]d ct mark set meta mark
  }
}
`, exitNftTable, netmark.Mark))
		if out, err := nft.CombinedOutput(); err != nil {
			ipCmd("-4", "route", "del", "default", "dev", ifname, "table", table)
			return fmt.Errorf("nft: %w: %s", err, out)
		}
		err := errors.Join(
			ipCmd("-4", "rule", "add", "pref", strconv.Itoa(exitMainPref), "table", "main", "suppress_prefixlength", "0"),
			ipCmd("-4", "rule", "add", "pref", table, "not", "fwmark", strconv.Itoa(netmark.Mark), "table", table),
		)
		if err != nil {
			delExitRules()
			ipCmd("-4", "route", "del", "default", "dev", ifname, "table", table)
			return err
		}
		// Best effort: fails where IPv6 is switched off, and then there
		// is nothing to leak.
		ipCmd("-6", "route", "replace", "unreachable", "default", "table", table)
		ipCmd("-6", "rule", "add", "pref", strconv.Itoa(exitMainPref), "table", "main", "suppress_prefixlength", "0")
		ipCmd("-6", "rule", "add", "pref", table, "not", "fwmark", strconv.Itoa(netmark.Mark), "table", table)
	}
	exitRooms[ifname] = true
	return nil
}

func disableExit(_ tun.Device, ifname string) {
	exitMu.Lock()
	defer exitMu.Unlock()
	ipCmd("-4", "route", "del", "default", "dev", ifname, "table", strconv.Itoa(exitTable))
	delete(exitRooms, ifname)
	if len(exitRooms) == 0 {
		delExitRules()
	}
}

// delExitRules removes the rules, also ones left by a crashed node.
func delExitRules() {
	exec.Command("nft", "delete", "table", "inet", exitNftTable).Run()
	exec.Command("nft", "delete", "table", "ip", exitNftTable).Run() // 0.3.1
	ipCmd("-6", "route", "flush", "table", strconv.Itoa(exitTable))
	for _, family := range []string{"-4", "-6"} {
		for _, pref := range []int{exitMainPref, exitTable} {
			for ipCmd(family, "rule", "del", "pref", strconv.Itoa(pref)) == nil {
			}
		}
	}
}

// setDNS sends all DNS queries of the machine to the servers through
// systemd-resolved (routing domain "~." on the room interface); no servers
// revert the interface's DNS settings.
func setDNS(_ tun.Device, ifname string, servers []netip.Addr) error {
	if len(servers) == 0 {
		exec.Command("resolvectl", "revert", ifname).Run()
		return nil
	}
	dns := []string{"dns", ifname}
	for _, a := range servers {
		dns = append(dns, a.String())
	}
	for _, args := range [][]string{dns, {"domain", ifname, "~."}, {"default-route", ifname, "yes"}} {
		if out, err := exec.Command("resolvectl", args...).CombinedOutput(); err != nil {
			exec.Command("resolvectl", "revert", ifname).Run()
			return fmt.Errorf("resolvectl %s: %w: %s (is systemd-resolved running?)", strings.Join(args, " "), err, out)
		}
	}
	return nil
}
