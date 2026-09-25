// Package room runs one virtual LAN: an AmneziaWG device on top of a TUN
// interface (or an in-process network stack in userspace mode).
package room

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"

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
	r := &Room{Name: c.Name, Address: c.Address}

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
	if err := r.dev.IpcSet(uapiConfig(c, o.Key)); err != nil {
		return nil, fmt.Errorf("room %s: configure AmneziaWG: %w", c.Name, err)
	}
	if err := r.dev.Up(); err != nil {
		return nil, fmt.Errorf("room %s: up: %w", c.Name, err)
	}
	log.Info("room up", "interface", r.ifname, "address", c.Address, "peers", len(c.Peers))
	return r, nil
}

// Close tears the room down.
func (r *Room) Close() {
	r.dev.Close()
}

// Stats returns the raw AmneziaWG status (UAPI "get" output).
func (r *Room) Stats() (string, error) { return r.dev.IpcGet() }

func uapiConfig(c config.Room, key identity.Key) string {
	prof := c.Secret.Derive()
	psk := hex.EncodeToString(prof.PresharedKey[:])

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(key[:]))
	b.WriteString(prof.DeviceUAPI(c.ClientParams()))
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.Masked())
		}
	}
	return b.String()
}

func wgLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { log.Error(fmt.Sprintf(format, args...)) },
	}
}
