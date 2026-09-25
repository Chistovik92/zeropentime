// SPDX-License-Identifier: MPL-2.0

// Package room runs one virtual LAN: an AmneziaWG device on top of a TUN
// interface (or an in-process network stack in userspace mode).
package room

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/identity"
)

// Room is a running virtual LAN.
type Room struct {
	Name    string
	Address netip.Prefix
	// Net is the in-process network stack; set only in userspace mode.
	Net *netstack.Net

	ifname string
	dev    *device.Device
	log    *slog.Logger
	psk    string

	mu    sync.Mutex
	peers map[identity.Key]config.Peer // as last configured
}

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
	r := &Room{Name: c.Name, Address: c.Address, log: log, psk: hex.EncodeToString(prof.PresharedKey[:]), peers: map[identity.Key]config.Peer{}}

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
		if err := configureInterface(tdev, r.ifname, c.Address, c.MTU); err != nil {
			tdev.Close()
			return nil, fmt.Errorf("room %s: configure %s: %w", c.Name, r.ifname, err)
		}
	}

	r.dev = device.NewDevice(tdev, o.Bind, wgLogger(log))
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
	uapi, next := peersDiff(r.peers, peers, r.psk)
	if uapi == "" {
		return nil
	}
	if err := r.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("room %s: update peers: %w", r.Name, err)
	}
	r.peers = next
	return nil
}

func peersDiff(old map[identity.Key]config.Peer, peers []config.Peer, psk string) (string, map[identity.Key]config.Peer) {
	next := make(map[identity.Key]config.Peer, len(peers))
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
		if !existed || prev.Keepalive != p.Keepalive {
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
	return b.String(), next
}

// Close tears the room down.
func (r *Room) Close() {
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
