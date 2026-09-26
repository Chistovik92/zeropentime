// SPDX-License-Identifier: MPL-2.0

// Package room runs one virtual LAN: an AmneziaWG device on top of a TUN
// interface (or an in-process network stack in userspace mode).
package room

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/dnsfwd"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/tunwrap"
)

// Room is a running virtual LAN.
type Room struct {
	Name    string
	Address netip.Prefix
	// Net is the in-process network stack; set only in userspace mode.
	Net *netstack.Net

	ifname  string
	dev     *device.Device
	bcast   *tunwrap.Device
	tdev    tun.Device // the OS interface (nil in userspace mode)
	routes  []netip.Prefix
	routing []netip.Prefix // networks this node routes for the room
	exitSrv bool           // this node is an exit for the room
	exit    bool           // this node's internet traffic goes into the room
	exitErr string         // last error turning exit on (logged once)
	exitDNS netip.Addr     // DNS server behind the exit in use
	dnsSrv  *dnsfwd.Forwarder
	log     *slog.Logger
	psk     string

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
}

// Up creates the interface, configures AmneziaWG and brings the room up.
func Up(o Options) (_ *Room, err error) {
	c := o.Config
	log := o.Log.With("room", c.Name)
	prof := c.Secret.Derive()
	r := &Room{Name: c.Name, Address: c.Address, log: log, psk: hex.EncodeToString(prof.PresharedKey[:]), self: o.Key.Public(), peers: map[identity.Key]config.Peer{}}

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
	if len(routes) == 0 && !exit {
		disableRouter(r.ifname)
		r.log.Info("routing for the room off")
	} else if err := enableRouter(r.ifname, r.Address, routes, exit); err != nil {
		r.log.Warn("cannot route for the room", "routes", routes, "exit", exit, "err", err)
		return
	} else {
		r.log.Info("routing for the room on", "routes", routes, "exit", exit)
	}
	r.routing, r.exitSrv = slices.Clone(routes), exit
	r.setDNSServerLocked(exit)
}

func (r *Room) setDNSServerLocked(on bool) {
	if !on {
		if r.dnsSrv != nil {
			r.dnsSrv.Close()
			r.dnsSrv = nil
		}
		return
	}
	if r.dnsSrv != nil {
		return
	}
	f, err := dnsfwd.Listen(netip.AddrPortFrom(r.Address.Addr(), 53),
		func() []netip.AddrPort { return dnsfwd.SystemUpstreams("/etc/resolv.conf") }, r.log)
	if err != nil {
		r.log.Warn("cannot answer DNS for the room's exit users: their DNS will fail", "err", err)
		return
	}
	r.dnsSrv = f
	r.log.Info("answering DNS for the room's exit users", "addr", f.Addr())
}

// SetExit sends this machine's internet traffic into the room, to the
// peer that has 0.0.0.0/0 in its AllowedIPs (the exit node), and with a
// valid dns all DNS queries to that address (the exit's forwarder). The
// node's own sockets keep the usual routes (package netmark).
func (r *Room) SetExit(on bool, dns netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !on {
		dns = netip.Addr{}
	}
	if on == r.exit && dns == r.exitDNS {
		return
	}
	if r.tdev == nil {
		r.exit, r.exitDNS = on, dns
		return
	}
	if !on {
		setExitDNS(r.tdev, r.ifname, netip.Addr{})
		disableExit(r.tdev, r.ifname)
		r.exit, r.exitDNS, r.exitErr = false, netip.Addr{}, ""
		r.log.Info("internet traffic no longer goes through the room")
		return
	}
	if !r.exit {
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
	if err := setExitDNS(r.tdev, r.ifname, dns); err != nil {
		r.log.Warn("DNS through the exit", "err", err)
	} else if dns.IsValid() {
		r.log.Info("DNS queries go through the exit node", "dns", dns)
	} else {
		r.log.Warn("the exit node does not answer DNS (older version): DNS queries go directly")
	}
	r.exitDNS = dns
}

// Exit reports whether internet traffic is meant to go through this room
// and the exit's DNS server (invalid if it has none).
func (r *Room) Exit() (bool, netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exit, r.exitDNS
}

// Close tears the room down.
func (r *Room) Close() {
	r.mu.Lock()
	r.closed = true
	if (len(r.routing) > 0 || r.exitSrv) && r.tdev != nil {
		disableRouter(r.ifname)
	}
	r.setDNSServerLocked(false)
	if r.exit && r.tdev != nil {
		setExitDNS(r.tdev, r.ifname, netip.Addr{})
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
