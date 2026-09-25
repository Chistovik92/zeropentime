// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/Chistovik92/zeropentime/internal/identity"
)

const (
	helloEvery     = 2 * time.Second
	keepaliveEvery = 20 * time.Second
	// Without any frame from the relay for this long we register again
	// (the relay restarted, or our NAT mapping changed).
	silenceLimit = 60 * time.Second
)

// Client is a node's session with one relay over the node's UDP socket.
type Client struct {
	Addr      netip.AddrPort
	relayPub  identity.Key
	priv, pub identity.Key
	write     func(pkt []byte, to netip.AddrPort) error
	deliver   func(src [NodeIDLen]byte, payload []byte)
	log       *slog.Logger

	mu    sync.Mutex
	sess  *Session
	heard time.Time
}

// NewClient prepares a session with the relay at addr. write sends a
// datagram from the node socket; deliver receives relayed payloads.
func NewClient(addr netip.AddrPort, relayPub, priv, pub identity.Key,
	write func([]byte, netip.AddrPort) error, deliver func([NodeIDLen]byte, []byte), log *slog.Logger) *Client {
	return &Client{Addr: addr, relayPub: relayPub, priv: priv, pub: pub, write: write, deliver: deliver, log: log}
}

// Ready reports whether a session is established.
func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess != nil && time.Since(c.heard) < silenceLimit
}

// Run keeps the session alive until ctx ends.
func (c *Client) Run(ctx context.Context) {
	t := time.NewTicker(helloEvery)
	defer t.Stop()
	var lastPing time.Time
	for {
		c.mu.Lock()
		sess, heard := c.sess, c.heard
		c.mu.Unlock()
		switch {
		case sess == nil || time.Since(heard) > silenceLimit:
			if h, err := Hello(c.priv, c.pub, c.relayPub); err == nil {
				c.write(h, c.Addr)
			}
		case time.Since(lastPing) > keepaliveEvery:
			if f, err := Seal(sess, c.relayPub, TypePing, [NodeIDLen]byte{}, nil); err == nil {
				c.write(f, c.Addr)
				lastPing = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Handle processes a datagram that came from the relay address.
func (c *Client) Handle(pkt []byte) {
	if IsWelcome(pkt, c.pub) {
		s, err := OpenWelcome(pkt, c.priv, c.relayPub)
		if err != nil {
			return
		}
		c.mu.Lock()
		first := c.sess == nil
		c.sess, c.heard = s, time.Now()
		c.mu.Unlock()
		if first {
			c.log.Info("relay session established", "relay", c.Addr)
		}
		return
	}
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return
	}
	typ, node, payload, err := Open(sess, pkt)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.heard = time.Now()
	c.mu.Unlock()
	if typ == TypeRecv {
		c.deliver(node, payload)
	}
}

// Send forwards payload to the node through the relay.
func (c *Client) Send(dst [NodeIDLen]byte, payload []byte) error {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return errors.New("relay: no session")
	}
	f, err := Seal(sess, c.relayPub, TypeSend, dst, payload)
	if err != nil {
		return err
	}
	return c.write(f, c.Addr)
}
