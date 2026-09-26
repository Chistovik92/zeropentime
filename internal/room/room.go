// SPDX-License-Identifier: MPL-2.0

// Package room runs one virtual LAN: an AmneziaWG device on top of a TUN
// interface (or an in-process network stack in userspace mode).
package room

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/Chistovik92/zeropentime/internal/acl"
	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/dnsfwd"
	"github.com/Chistovik92/zeropentime/internal/exitnat"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/tunwrap"
)

// Room is a running virtual LAN.
type Room struct {
	Name    string
	Address netip.Prefix
	// Net is the in-process network stack; set only in userspace mode.
	Net *netstack.Net

	ifname            string
	dev               *device.Device
	bcast             *tunwrap.Device
	tdev              tun.Device // the OS interface (nil in userspace mode)
	routes            []netip.Prefix
	routing           []netip.Prefix // networks this node routes for the room
	exitSrv           bool           // this node is an exit for the room
	exit              bool           // this node's internet traffic goes into the room
	exitErr           string         // last error turning exit on (logged once)
	dns               []netip.Addr   // DNS servers this room carries
	dnsUp             atomic.Pointer[[]netip.Addr]
	exitSrvOn         atomic.Bool
	zone              *dnsfwd.Zone
	dnsErr            string
	ups               []netip.Addr // upstreams of the exit's DNS forwarder (nil: resolv.conf)
	dnsSrv            *dnsfwd.Forwarder
	nat               *exitnat.NAT // userspace exit
	mtu               int
	userExit          bool
	limit, limitTotal int
	log               *slog.Logger
	psk               string

	self identity.Key // this node's public key in the room

	mu     sync.Mutex
	peers  map[identity.Key]config.Peer // as last configured
	closed bool
}

// keepaliveDelay postpones persistent keepalive on the side of a new peer
// pair with the larger public key. If both sides start a handshake in the
// same instant (typical when the controller introduces two nodes to each
// other), one direction stays unusable until the handshake is retried
// REKEY_TIMEOUT (5 s) later. Letting the smaller key go first avoids that;
// afterwards only the initiator rekeys, so the race does not come back.
var keepaliveDelay = 3 * time.Second

// Options configure Up.
type Options struct {
	Config    config.Room
	Key       identity.Key // this node's private key in the room
	Bind      conn.Bind
	Userspace bool
	Log       *slog.Logger
	// DNSUpstreams replace resolv.conf as the resolvers the exit's DNS
	// forwarder asks (exit_dns_upstreams in the node config).
	DNSUpstreams []netip.Addr
	// UserspaceExit: as an exit node, forward the room's internet traffic
	// with our own NAT (package exitnat) instead of the OS.
	UserspaceExit bool
	// ExitLimit and ExitLimitTotal limit an exit's speed in bytes per
	// second, per client and in total, in each direction (0: no limit).
	ExitLimit, ExitLimitTotal int
}

// Up creates the interface, configures AmneziaWG and brings the room up.
func Up(o Options) (_ *Room, err error) {
	c := o.Config
	log := o.Log.With("room", c.Name)
	prof := c.Secret.Derive()
	r := &Room{Name: c.Name, Address: c.Address, log: log, psk: hex.EncodeToString(prof.PresharedKey[:]), self: o.Key.Public(), peers: map[identity.Key]config.Peer{}, ups: o.DNSUpstreams,
		mtu: c.MTU, userExit: o.UserspaceExit, limit: o.ExitLimit, limitTotal: o.ExitLimitTotal}

	var tdev tun.Device
	if o.Userspace {
		tdev, r.Net, err = netstack.CreateNetTUN([]netip.Addr{c.Address.Addr()}, nil, c.MTU)
		if err != nil {
			return nil, fmt.Errorf("room %s: userspace stack: %w", c.Name, err)
		}
		r.ifname = "netstack"
	} else {
		tdev, err = tun.CreateTUN("zpt-"+c.Name, c.MTU)
		if err != nil {
			hint := "admin/root rights required"
			if runtime.GOOS == "windows" && strings.Contains(err.Error(), "wintun.dll") {
				hint = "put wintun.dll (amd64/arm64 build from https://www.wintun.net) next to zpt.exe"
			}
			return nil, fmt.Errorf("room %s: create interface (%s): %w", c.Name, hint, err)
		}
		if r.ifname, err = tdev.Name(); err != nil {
			tdev.Close()
			return nil, err
		}
		if err := configureInterface(tdev, r.ifname, c.Address, c.MTU, log); err != nil {
			tdev.Close()
			return nil, fmt.Errorf("room %s: configure %s: %w", c.Name, r.ifname, err)
		}
		r.tdev = tdev
	}

	r.bcast = tunwrap.New(tdev, c.Address, c.Broadcast)
	if o.UserspaceExit {
		r.bcast.EnablePump()
	}
	r.dev = device.NewDevice(r.bcast, o.Bind, wgLogger(log))
	defer func() {
		if err != nil {
			r.dev.Close() // also closes tdev
		}
	}()
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(o.Key[:]))
	b.WriteString(prof.DeviceUAPI(c.ClientParams()))
	if err := r.dev.IpcSet(b.String()); err != nil {
		return nil, fmt.Errorf("room %s: configure AmneziaWG: %w", c.Name, err)
	}
	if err := r.SetPeers(c.Peers); err != nil {
		return nil, err
	}
	if err := r.dev.Up(); err != nil {
		return nil, fmt.Errorf("room %s: up: %w", c.Name, err)
	}
	if r.tdev != nil {
		r.mu.Lock()
		r.startDNSServerLocked()
		r.mu.Unlock()
	}
	log.Info("room up", "interface", r.ifname, "address", c.Address, "peers", len(c.Peers))
	return r, nil
}

// deviceConfig is the device part of the AmneziaWG config: key and obfuscation.
func deviceConfig(c config.Room, key identity.Key) string {
	return fmt.Sprintf("private_key=%s\n", hex.EncodeToString(key[:])) + c.Secret.Derive().DeviceUAPI(c.ClientParams())
}

// SetPeers changes the peer list in place. Unchanged peers keep their
// sessions; only the difference is sent to AmneziaWG.
func (r *Room) SetPeers(peers []config.Peer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	uapi, next, deferred := peersDiff(r.peers, peers, r.psk, r.self)
	if uapi == "" {
		return nil
	}
	if err := r.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("room %s: update peers: %w", r.Name, err)
	}
	r.peers = next
	var ips []netip.Addr
	for _, p := range next {
		for _, a := range p.AllowedIPs {
			if a.IsSingleIP() {
				ips = append(ips, a.Addr())
			}
		}
	}
	r.bcast.SetPeers(ips)
	for _, k := range deferred {
		time.AfterFunc(keepaliveDelay, func() { r.enableKeepalive(k) })
	}
	return nil
}

func (r *Room) enableKeepalive(k identity.Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[k]
	if r.closed || !ok || p.Keepalive == 0 {
		return
	}
	uapi := fmt.Sprintf("public_key=%s\nupdate_only=true\npersistent_keepalive_interval=%d\n", hex.EncodeToString(k[:]), p.Keepalive)
	if err := r.dev.IpcSet(uapi); err != nil {
		r.log.Error("enable keepalive", "err", err)
	}
}

// peersDiff renders the AmneziaWG config change from old to peers. For new
// peers whose key is smaller than ours, keepalive is left off for now and
// returned in deferred (see keepaliveDelay).
func peersDiff(old map[identity.Key]config.Peer, peers []config.Peer, psk string, self identity.Key) (uapi string, next map[identity.Key]config.Peer, deferred []identity.Key) {
	next = make(map[identity.Key]config.Peer, len(peers))
	var b strings.Builder
	for _, p := range peers {
		next[p.PublicKey] = p
		prev, existed := old[p.PublicKey]
		if existed && prev.Endpoint == p.Endpoint && prev.Keepalive == p.Keepalive && slices.Equal(prev.AllowedIPs, p.AllowedIPs) {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if !existed {
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		// Only push the endpoint when the controller's view changed, so a
		// roamed (learned) endpoint is not reset on every update.
		if p.Endpoint != "" && (!existed || prev.Endpoint != p.Endpoint) {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		switch {
		case !existed && p.Keepalive > 0 && bytes.Compare(self[:], p.PublicKey[:]) > 0:
			b.WriteString("persistent_keepalive_interval=0\n")
			deferred = append(deferred, p.PublicKey)
		case !existed || prev.Keepalive != p.Keepalive:
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.Masked())
		}
	}
	for k := range old {
		if _, ok := next[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(k[:]))
		}
	}
	return b.String(), next, deferred
}

// SetBroadcast changes how broadcast and multicast are shared ("on", "off", "mdns").
func (r *Room) SetBroadcast(mode string) { r.bcast.SetMode(mode) }

// SetRoutes sends traffic for these networks (other members' LANs) into
// the room. Routes that disappear are removed.
func (r *Room) SetRoutes(routes []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tdev != nil {
		for _, p := range r.routes {
			if !slices.Contains(routes, p) {
				if err := setRoute(r.tdev, r.ifname, p, false); err != nil {
					r.log.Warn("remove route", "route", p, "err", err)
				}
			}
		}
		for _, p := range routes {
			if !slices.Contains(r.routes, p) {
				if err := setRoute(r.tdev, r.ifname, p, true); err != nil {
					r.log.Warn("add route", "route", p, "err", err)
					continue
				}
				r.log.Info("route through the room", "route", p)
			}
		}
	}
	r.routes = slices.Clone(routes)
}

// SetRouter makes this node route the room's traffic into the given
// networks (subnet router) and, with exit, into the internet (exit node);
// nil and false turn it off. An exit also answers DNS queries on its room
// address for the members that go through it.
func (r *Room) SetRouter(routes []netip.Prefix, exit bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Equal(routes, r.routing) && exit == r.exitSrv || r.tdev == nil {
		r.routing, r.exitSrv = slices.Clone(routes), exit
		return
	}
	kernelExit := exit && !r.userExit
	if len(routes) == 0 && !kernelExit {
		if len(r.routing) > 0 || r.exitSrv && !r.userExit {
			disableRouter(r.ifname)
		}
	} else if err := enableRouter(r.ifname, r.Address, routes, kernelExit, r.limit, r.limitTotal); err != nil {
		r.log.Warn("cannot route for the room", "routes", routes, "exit", exit, "err", err)
		return
	}
	if exit && r.userExit {
		if err := r.startNATLocked(routes); err != nil {
			r.log.Warn("cannot be an exit node", "err", err)
			exit = false
		}
	} else {
		r.stopNATLocked()
	}
	if len(routes) > 0 || exit {
		mode := "kernel"
		if r.userExit {
			mode = "userspace"
		}
		r.log.Info("routing for the room on", "routes", routes, "exit", exit, "exit_nat", mode)
	} else {
		r.log.Info("routing for the room off")
	}
	r.routing, r.exitSrv = slices.Clone(routes), exit
	r.exitSrvOn.Store(exit)
}

// privateNets are never reachable through an exit node unless they are
// routes a room admin approved: the exit's own LAN stays closed.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/4"),
}

func isPrivate(a netip.Addr) bool {
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// startNATLocked makes this node a userspace exit: the room's packets to
// the internet go to our NAT instead of the OS; approved routes (kernel
// subnet router) and the room itself are left alone.
func (r *Room) startNATLocked(routes []netip.Prefix) error {
	if r.nat == nil {
		nat, err := exitnat.New(r.bcast.Inject, exitnat.Options{
			MTU: r.mtu, Allow: func(a netip.Addr) bool { return !isPrivate(a) },
			PerClient: r.limit, Total: r.limitTotal, Log: r.log,
		})
		if err != nil {
			return err
		}
		r.nat = nat
	}
	nat, subnet, self, keep := r.nat, r.Address.Masked(), r.Address.Addr(), slices.Clone(routes)
	r.bcast.SetDivert(func(pkt []byte) bool {
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			return false
		}
		src := netip.AddrFrom4([4]byte(pkt[12:16]))
		dst := netip.AddrFrom4([4]byte(pkt[16:20]))
		if !subnet.Contains(src) || subnet.Contains(dst) || dst == self || dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return false
		}
		for _, p := range keep {
			if p.Contains(dst) {
				return false
			}
		}
		nat.Inbound(pkt)
		return true
	})
	return nil
}

func (r *Room) stopNATLocked() {
	if r.nat != nil {
		r.bcast.SetDivert(nil)
		r.nat.Close()
		r.nat = nil
	}
}

// upstreams are the resolvers for a query that reached the room's DNS
// server from src: this machine's own queries go to the servers it chose
// (SetDNS); members going through this exit get the exit's resolvers;
// anybody else gets only the room's names.
func (r *Room) upstreams(src netip.Addr) []netip.AddrPort {
	self := r.Address.Addr()
	if src == self || src.IsLoopback() {
		var out []netip.AddrPort
		if p := r.dnsUp.Load(); p != nil {
			for _, a := range *p {
				if a != self {
					out = append(out, netip.AddrPortFrom(a, 53))
				}
			}
		}
		return out
	}
	if !r.exitSrvOn.Load() {
		return nil
	}
	if len(r.ups) == 0 {
		return dnsfwd.SystemResolvers()
	}
	var out []netip.AddrPort
	for _, a := range r.ups {
		out = append(out, netip.AddrPortFrom(a, 53))
	}
	return out
}

// startDNSServerLocked answers DNS on the room address: the room's names
// and, as configured, forwarding (see upstreams).
func (r *Room) startDNSServerLocked() {
	f, err := dnsfwd.Listen(netip.AddrPortFrom(r.Address.Addr(), 53), r.upstreams, r.log)
	if err != nil {
		r.log.Warn("cannot answer DNS on the room address: room names and DNS through the room will not work", "err", err)
		return
	}
	r.dnsSrv = f
	if r.zone != nil {
		f.SetZone(r.zone)
	}
}

// SetZone sets the room's names (name.room.zpt) and makes this machine
// resolve them through the room's DNS server.
func (r *Room) SetZone(z *dnsfwd.Zone) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := ""
	if r.zone != nil {
		old = r.zone.Name
	}
	r.zone = z
	if r.dnsSrv != nil {
		r.dnsSrv.SetZone(z)
	}
	if z != nil && z.Name != old {
		r.applyOSDNSLocked()
	}
}

// Zone is the room's DNS zone ("" if none).
func (r *Room) Zone() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zone == nil {
		return ""
	}
	return r.zone.Name
}

// applyOSDNSLocked points this machine's resolver at the room's DNS
// server: for the room's zone, and for all names when the room carries
// this machine's DNS (SetDNS with servers).
func (r *Room) applyOSDNSLocked() {
	if r.tdev == nil || r.dnsSrv == nil {
		return
	}
	zone := ""
	if r.zone != nil {
		zone = r.zone.Name
	}
	carrier := len(r.dns) > 0
	if err := setDNS(r.tdev, r.ifname, r.Address.Addr(), zone, carrier); err != nil {
		if err.Error() != r.dnsErr {
			r.log.Warn("cannot configure the system resolver for the room", "err", err)
		}
		r.dnsErr = err.Error()
		return
	}
	r.dnsErr = ""
}

// SetExit sends this machine's internet traffic into the room, to the
// peer that has 0.0.0.0/0 in its AllowedIPs (the exit node). The node's
// own sockets keep the usual routes (package netmark).
func (r *Room) SetExit(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if on == r.exit {
		return
	}
	if r.tdev == nil {
		r.exit = on
		return
	}
	if !on {
		disableExit(r.tdev, r.ifname)
		r.exit, r.exitErr = false, ""
		r.log.Info("internet traffic no longer goes through the room")
		return
	}
	if err := enableExit(r.tdev, r.ifname); err != nil {
		if err.Error() != r.exitErr {
			r.log.Warn("cannot send internet traffic through the room", "err", err)
		}
		r.exitErr = err.Error()
		return
	}
	r.exit, r.exitErr = true, ""
	r.log.Info("internet traffic goes through the room's exit node")
}

// SetDNS sends all DNS queries of this machine to the given servers,
// attached to this room's interface (nil: the room does not touch DNS).
// Only one room of a node carries the DNS settings at a time.
func (r *Room) SetDNS(servers []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Equal(servers, r.dns) {
		return
	}
	was := len(r.dns) > 0
	r.dns = slices.Clone(servers)
	cp := slices.Clone(servers)
	r.dnsUp.Store(&cp)
	if was != (len(servers) > 0) {
		r.applyOSDNSLocked()
	}
	if len(servers) > 0 {
		r.log.Info("DNS queries go through the room to", "servers", servers)
	} else if was {
		r.log.Info("DNS queries no longer go through the room")
	}
}

// Exit reports whether internet traffic is meant to go through this room
// and the DNS servers this room carries.
func (r *Room) Exit() (bool, []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exit, slices.Clone(r.dns)
}

// SetPolicy applies the room's access rules to incoming packets (nil or
// no rules: everything allowed).
func (r *Room) SetPolicy(pol *acl.Policy) {
	if pol == nil || len(pol.Rules) == 0 {
		r.bcast.SetFilter(nil)
		return
	}
	r.bcast.SetFilter(acl.NewFilter(pol, r.Address.Addr()))
}

// ListenUDP listens on the room address (in the tunnel), in the OS or in
// the in-process network stack.
func (r *Room) ListenUDP(port uint16) (net.PacketConn, error) {
	ap := netip.AddrPortFrom(r.Address.Addr(), port)
	if r.Net != nil {
		return r.Net.ListenUDPAddrPort(ap)
	}
	return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ap))
}

// ListenTCP listens on the room address.
func (r *Room) ListenTCP(port uint16) (net.Listener, error) {
	ap := netip.AddrPortFrom(r.Address.Addr(), port)
	if r.Net != nil {
		return r.Net.ListenTCPAddrPort(ap)
	}
	return net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(ap))
}

// DialTCP connects to a member through the room.
func (r *Room) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if r.Net != nil {
		return r.Net.DialContextTCPAddrPort(ctx, dst)
	}
	d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(r.Address.Addr(), 0))}
	return d.DialContext(ctx, "tcp4", dst.String())
}

// Ifname is the OS interface of the room ("netstack" in userspace mode).
func (r *Room) Ifname() string { return r.ifname }

// Close tears the room down.
func (r *Room) Close() {
	r.mu.Lock()
	r.closed = true
	if (len(r.routing) > 0 || r.exitSrv) && r.tdev != nil {
		disableRouter(r.ifname)
	}
	r.stopNATLocked()
	if r.dnsSrv != nil {
		r.dnsSrv.Close()
		if r.tdev != nil {
			setDNS(r.tdev, r.ifname, netip.Addr{}, "", false)
		}
	}
	if r.exit && r.tdev != nil {
		disableExit(r.tdev, r.ifname)
	}
	r.mu.Unlock()
	r.dev.Close()
	r.log.Info("room down")
}

// Stats returns the raw AmneziaWG status (UAPI "get" output).
func (r *Room) Stats() (string, error) { return r.dev.IpcGet() }

func wgLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { log.Error(fmt.Sprintf(format, args...)) },
	}
}
