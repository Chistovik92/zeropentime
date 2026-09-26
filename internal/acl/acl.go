// SPDX-License-Identifier: MPL-2.0

// Package acl is a room's access rules. Without rules everything inside
// the room is allowed. With rules, a packet is allowed only if some rule
// allows it; replies to allowed connections always pass.
//
// One rule per line:
//
//	allow ОТКУДА -> КУДА [ПОРТЫ...]
//
// ОТКУДА and КУДА are comma-separated selectors: "*" (anyone / anything),
// "tag:NAME", a member name, a network ("192.168.1.0/24"); КУДА may also be
// "internet" (through an exit node). ПОРТЫ are "tcp:22", "udp:27015-27030",
// "tcp:*", "icmp" or omitted (all). Lines starting with # are comments.
package acl

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Protocol numbers.
const (
	ICMP = 1
	TCP  = 6
	UDP  = 17
)

// Rule allows traffic From -> To on Ports.
type Rule struct {
	From  []string    `json:"from"`
	To    []string    `json:"to"`
	Ports []PortRange `json:"ports,omitempty"` // empty: all
}

// PortRange is a protocol with an inclusive port range (0-65535: any).
type PortRange struct {
	Proto int    `json:"proto"`
	First uint16 `json:"first,omitempty"`
	Last  uint16 `json:"last,omitempty"`
}

// Member is what rules know about a room member.
type Member struct {
	Name string
	IP   netip.Addr
	Tags []string
}

// Parse reads rules in the text form.
func Parse(text string) ([]Rule, error) {
	var rules []Rule
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", i+1, err)
		}
		rules = append(rules, r)
	}
	if len(rules) > 500 {
		return nil, fmt.Errorf("слишком много правил (%d, не больше 500)", len(rules))
	}
	return rules, nil
}

func parseRule(line string) (Rule, error) {
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != "allow" || f[2] != "->" {
		return Rule{}, fmt.Errorf("ожидалось «allow ОТКУДА -> КУДА [ПОРТЫ]»: %q", line)
	}
	r := Rule{From: splitSel(f[1]), To: splitSel(f[3])}
	for _, s := range r.From {
		if err := checkSel(s, false); err != nil {
			return Rule{}, err
		}
	}
	for _, s := range r.To {
		if err := checkSel(s, true); err != nil {
			return Rule{}, err
		}
	}
	for _, p := range f[4:] {
		for _, one := range strings.Split(p, ",") {
			pr, err := parsePorts(one)
			if err != nil {
				return Rule{}, err
			}
			r.Ports = append(r.Ports, pr)
		}
	}
	return r, nil
}

func splitSel(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func checkSel(s string, to bool) error {
	switch {
	case s == "*":
		return nil
	case s == "internet":
		if !to {
			return fmt.Errorf("«internet» может быть только адресатом")
		}
		return nil
	case strings.HasPrefix(s, "tag:"):
		if len(s) == 4 {
			return fmt.Errorf("пустой тег")
		}
		return nil
	case strings.Contains(s, "/"):
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("сеть %q: %w", s, err)
		}
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if len(s) > 40 {
		return fmt.Errorf("слишком длинное имя %q", s)
	}
	return nil // a member name
}

func parsePorts(s string) (PortRange, error) {
	proto, rng, _ := strings.Cut(strings.ToLower(s), ":")
	var p PortRange
	switch proto {
	case "tcp":
		p.Proto = TCP
	case "udp":
		p.Proto = UDP
	case "icmp":
		if rng != "" {
			return p, fmt.Errorf("у icmp нет портов: %q", s)
		}
		return PortRange{Proto: ICMP}, nil
	default:
		return p, fmt.Errorf("протокол %q: tcp, udp или icmp", proto)
	}
	if rng == "" || rng == "*" {
		p.First, p.Last = 0, 65535
		return p, nil
	}
	a, b, isRange := strings.Cut(rng, "-")
	first, err := strconv.ParseUint(a, 10, 16)
	if err != nil {
		return p, fmt.Errorf("порт %q", a)
	}
	last := first
	if isRange {
		if last, err = strconv.ParseUint(b, 10, 16); err != nil || last < first {
			return p, fmt.Errorf("диапазон портов %q", rng)
		}
	}
	p.First, p.Last = uint16(first), uint16(last)
	return p, nil
}

// String renders rules back in the text form.
func String(rules []Rule) string {
	var sb strings.Builder
	for _, r := range rules {
		sb.WriteString("allow " + strings.Join(r.From, ",") + " -> " + strings.Join(r.To, ","))
		for _, p := range r.Ports {
			sb.WriteString(" " + p.String())
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (p PortRange) String() string {
	name := map[int]string{TCP: "tcp", UDP: "udp", ICMP: "icmp"}[p.Proto]
	switch {
	case p.Proto == ICMP:
		return name
	case p.First == 0 && p.Last == 65535:
		return name + ":*"
	case p.First == p.Last:
		return fmt.Sprintf("%s:%d", name, p.First)
	}
	return fmt.Sprintf("%s:%d-%d", name, p.First, p.Last)
}

// Policy decides for one room.
type Policy struct {
	Rules   []Rule
	Members []Member
	Subnet  netip.Prefix // the room
}

func (pol *Policy) member(ip netip.Addr) *Member {
	for i := range pol.Members {
		if pol.Members[i].IP == ip {
			return &pol.Members[i]
		}
	}
	return nil
}

// matches reports whether addr fits a selector.
func (pol *Policy) matches(sel string, addr netip.Addr, to bool) bool {
	m := pol.member(addr)
	switch {
	case sel == "*":
		return true
	case sel == "internet":
		return to && !pol.Subnet.Contains(addr)
	case strings.HasPrefix(sel, "tag:"):
		return m != nil && slices.Contains(m.Tags, sel[4:])
	case strings.Contains(sel, "/"):
		p, err := netip.ParsePrefix(sel)
		return err == nil && p.Contains(addr)
	}
	if a, err := netip.ParseAddr(sel); err == nil {
		return a == addr
	}
	return m != nil && strings.EqualFold(m.Name, sel)
}

// Allowed reports whether a packet from src to dst (proto, destination
// port) may pass, and which rule allowed it (-1: none; no rules: all).
func (pol *Policy) Allowed(src, dst netip.Addr, proto int, port uint16) (bool, int) {
	if len(pol.Rules) == 0 {
		return true, -1
	}
	for i, r := range pol.Rules {
		if !pol.any(r.From, src, false) || !pol.any(r.To, dst, true) {
			continue
		}
		if len(r.Ports) == 0 {
			return true, i
		}
		for _, p := range r.Ports {
			if p.Proto == proto && (proto == ICMP || port >= p.First && port <= p.Last) {
				return true, i
			}
		}
	}
	return false, -1
}

func (pol *Policy) any(sels []string, a netip.Addr, to bool) bool {
	for _, s := range sels {
		if pol.matches(s, a, to) {
			return true
		}
	}
	return false
}
