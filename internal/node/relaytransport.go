// SPDX-License-Identifier: MPL-2.0

package node

import (
	"context"
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/relay"
	"github.com/Chistovik92/zeropentime/internal/vless"
)

const (
	// udpRelayGrace: how long UDP to the relay may stay silent before a
	// node in "auto" mode falls back to VLESS.
	udpRelayGrace = 8 * time.Second
	vlessDialTime = 10 * time.Second
)

// relayWrite sends a frame to the relay: through the VLESS stream when one
// is up, else as a UDP datagram.
func (n *Node) relayWrite(pkt []byte, to netip.AddrPort) error {
	if pc := n.vlessConn.Load(); pc != nil {
		return pc.WritePacket(pkt)
	}
	return n.sock.WriteDirect(pkt, to)
}

// relayTransport decides how to reach the relay. UDP is tried first (unless
// the config says "vless"); VLESS + REALITY over TCP takes over when UDP
// stays silent for udpRelayGrace. While no VLESS stream is up, relay
// frames go out over UDP, so a recovered UDP path is noticed by itself.
func (n *Node) relayTransport(ctx context.Context, c *relay.Client, want api.Relay, udpAddr netip.AddrPort) {
	mode := n.opts.Config.RelayTransport
	if mode == "udp" || want.VLESS == nil {
		return
	}
	cfg, err := vlessConfig(want.VLESS)
	if err != nil {
		n.log.Warn("bad VLESS settings from controller", "err", err)
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if mode != "vless" && !n.waitUDPSilent(ctx, c) {
			return
		}
		if err := n.vlessSession(ctx, c, cfg, udpAddr); err != nil {
			n.log.Warn("VLESS connection failed", "addr", cfg.Addr, "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
	}
}

// waitUDPSilent returns once the relay has not answered over UDP for
// udpRelayGrace (false if ctx ends first).
func (n *Node) waitUDPSilent(ctx context.Context, c *relay.Client) bool {
	lastOK := time.Now()
	for {
		if c.Ready() {
			lastOK = time.Now()
		}
		if time.Since(lastOK) >= udpRelayGrace {
			n.log.Info("relay unreachable over UDP, trying VLESS + REALITY")
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

// vlessSession runs one VLESS stream to the relay until it breaks.
func (n *Node) vlessSession(ctx context.Context, c *relay.Client, cfg vless.ClientConfig, udpAddr netip.AddrPort) error {
	dctx, cancel := context.WithTimeout(ctx, vlessDialTime)
	pc, err := vless.Dial(dctx, cfg, udpAddr)
	cancel()
	if err != nil {
		return err
	}
	n.vlessConn.Store(pc)
	n.log.Info("relay reached through VLESS + REALITY", "addr", cfg.Addr)
	c.Hello() // new transport: register at once
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	buf := make([]byte, vless.MaxPacket)
	for {
		m, err := pc.ReadPacket(buf)
		if err != nil {
			break
		}
		c.Handle(append([]byte(nil), buf[:m]...))
	}
	n.vlessConn.CompareAndSwap(pc, nil)
	pc.Close()
	if ctx.Err() == nil {
		n.log.Warn("VLESS connection lost")
	}
	return nil
}

func vlessConfig(v *api.VLESS) (vless.ClientConfig, error) {
	c := vless.ClientConfig{Addr: v.Addr, ServerName: v.ServerName, PublicKey: v.PublicKey}
	sid, err := hex.DecodeString(v.ShortID)
	if err != nil || len(sid) > 8 {
		return c, err
	}
	copy(c.ShortID[:], sid)
	c.User, err = vless.ParseUUID(v.User)
	return c, err
}
