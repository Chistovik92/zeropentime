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

// privateNets are never reachable through an exit node unless they are
// routes the admin approved: the exit's own LAN stays closed.
const privateNets = "10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4"

// enableRouter lets members of the room reach the given networks through
// this node, and with exit the internet: IP forwarding plus masquerade of
// room traffic.
func enableRouter(ifname string, room netip.Prefix, routes []netip.Prefix, exit bool) error {
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
	if exit {
		out := fmt.Sprintf(`oifname != "%s"`, ifname)
		fwd = append(fwd, from+" ip daddr { "+privateNets+" } drop", from+" "+out+" accept")
		nat = append(nat, from+" "+out+" masquerade")
	}
	t := nftTable(ifname)
	rules := fmt.Sprintf(`table ip %[1]s
delete table ip %[1]s
table ip %[1]s {
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
`, t, ifname, strings.Join(nat, "\n    "), strings.Join(fwd, "\n    "))
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
// approved networks).
const (
	exitTable    = netmark.Mark // routing table and rule priority
	exitMainPref = exitTable - 1
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

func enableExit(ifname string) error {
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
		nft.Stdin = strings.NewReader(fmt.Sprintf(`table ip %[1]s {
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
	}
	exitRooms[ifname] = true
	return nil
}

func disableExit(ifname string) {
	exitMu.Lock()
	defer exitMu.Unlock()
	ipCmd("-4", "route", "del", "default", "dev", ifname, "table", strconv.Itoa(exitTable))
	delete(exitRooms, ifname)
	if len(exitRooms) == 0 {
		delExitRules()
	}
}

const exitNftTable = "zpt_exit"

// delExitRules removes the rules, also ones left by a crashed node.
func delExitRules() {
	exec.Command("nft", "delete", "table", "ip", exitNftTable).Run()
	for _, pref := range []int{exitMainPref, exitTable} {
		for ipCmd("-4", "rule", "del", "pref", strconv.Itoa(pref)) == nil {
		}
	}
}
