// SPDX-License-Identifier: MPL-2.0

// Package portmap asks the home router to forward the node's UDP port
// (NAT-PMP or UPnP IGD), so peers can reach the node directly even behind
// NAT. PCP is not supported yet.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

const (
	// Lifetime requested from the router; mappings are renewed at half of it.
	Lifetime    = time.Hour
	description = "zeropentime"
)

// mapper is one port mapping protocol.
type mapper interface {
	name() string
	// add creates or renews the mapping and returns the external address
	// and granted lifetime.
	add(ctx context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error)
	remove(ctx context.Context, port uint16, external uint16) error
}

// discover returns the protocols the local router speaks, fastest first.
var discover = func(ctx context.Context) []mapper {
	var out []mapper
	if gw, err := gateway.DiscoverGateway(); err == nil {
		out = append(out, &pmp{client: natpmp.NewClientWithTimeout(gw, 2*time.Second)})
	}
	if igd := discoverIGD(ctx); igd != nil {
		out = append(out, igd)
	}
	return out
}

// Run keeps a mapping for the UDP port alive until ctx ends, then removes
// it. onChange gets the external address, or a zero value when the mapping
// is lost or unavailable.
func Run(ctx context.Context, port uint16, log *slog.Logger, onChange func(netip.AddrPort)) {
	var current netip.AddrPort
	set := func(a netip.AddrPort) {
		if a != current {
			current = a
			onChange(a)
		}
	}
	retry := time.Minute
	for ctx.Err() == nil {
		m, ext, life := establish(ctx, port, log)
		if m == nil {
			set(netip.AddrPort{})
			if !sleep(ctx, retry) {
				return
			}
			retry = min(retry*2, 30*time.Minute)
			continue
		}
		retry = time.Minute
		log.Info("router forwards the node port", "method", m.name(), "external", ext)
		set(ext)
		for {
			if !sleep(ctx, life/2) {
				rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				m.remove(rctx, port, ext.Port())
				cancel()
				return
			}
			var err error
			ext, life, err = m.add(ctx, port, Lifetime)
			if err != nil {
				log.Warn("port mapping renewal failed", "method", m.name(), "err", err)
				break
			}
			set(ext)
		}
	}
}

func establish(ctx context.Context, port uint16, log *slog.Logger) (mapper, netip.AddrPort, time.Duration) {
	for _, m := range discover(ctx) {
		ext, life, err := m.add(ctx, port, Lifetime)
		if err != nil {
			log.Debug("port mapping failed", "method", m.name(), "err", err)
			continue
		}
		if !usable(ext.Addr()) {
			// Double NAT or carrier-grade NAT: the "external" address is
			// still private, the mapping helps nobody outside.
			m.remove(ctx, port, ext.Port())
			log.Info("router is behind another NAT, port mapping not used", "method", m.name(), "external", ext)
			continue
		}
		if life <= 0 {
			life = Lifetime
		}
		return m, ext, life
	}
	return nil, netip.AddrPort{}, 0
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func usable(a netip.Addr) bool {
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- NAT-PMP ----

type pmp struct{ client *natpmp.Client }

func (p *pmp) name() string { return "nat-pmp" }

func (p *pmp) add(_ context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	ext, err := p.client.GetExternalAddress()
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	res, err := p.client.AddPortMapping("udp", int(port), int(port), int(lifetime.Seconds()))
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	ip := netip.AddrFrom4(ext.ExternalIPAddress)
	return netip.AddrPortFrom(ip, res.MappedExternalPort), time.Duration(res.PortMappingLifetimeInSeconds) * time.Second, nil
}

func (p *pmp) remove(_ context.Context, port uint16, _ uint16) error {
	_, err := p.client.AddPortMapping("udp", int(port), 0, 0) // lifetime 0 deletes
	return err
}

// ---- UPnP IGD ----

// igdClient is what the WANIPConnection1/2 and WANPPPConnection1 clients share.
type igdClient interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16,
		internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	LocalAddr() net.IP
}

type upnp struct{ client igdClient }

func (u *upnp) name() string { return "upnp" }

func discoverIGD(ctx context.Context) *upnp {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil && len(cs) > 0 {
		return &upnp{client: cs[0]}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil && len(cs) > 0 {
		return &upnp{client: cs[0]}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil && len(cs) > 0 {
		return &upnp{client: cs[0]}
	}
	return nil
}

func (u *upnp) add(ctx context.Context, port uint16, lifetime time.Duration) (netip.AddrPort, time.Duration, error) {
	local := u.client.LocalAddr()
	if local == nil {
		return netip.AddrPort{}, 0, errors.New("upnp: unknown local address")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	extIP, err := u.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	ip, err := netip.ParseAddr(extIP)
	if err != nil {
		return netip.AddrPort{}, 0, fmt.Errorf("upnp: bad external address %q", extIP)
	}
	err = u.client.AddPortMappingCtx(ctx, "", port, "UDP", port, local.String(), true, description, uint32(lifetime.Seconds()))
	if err != nil {
		// Some routers only accept permanent mappings.
		if err2 := u.client.AddPortMappingCtx(ctx, "", port, "UDP", port, local.String(), true, description, 0); err2 != nil {
			return netip.AddrPort{}, 0, err
		}
	}
	return netip.AddrPortFrom(ip.Unmap(), port), lifetime, nil
}

func (u *upnp) remove(ctx context.Context, _ uint16, external uint16) error {
	return u.client.DeletePortMappingCtx(ctx, "", external, "UDP")
}
