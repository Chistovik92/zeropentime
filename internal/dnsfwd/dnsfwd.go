// SPDX-License-Identifier: MPL-2.0

// Package dnsfwd is the DNS forwarder of an exit node: members that send
// their internet traffic through the exit also resolve names there, so
// their queries neither leak to the local network nor reveal it.
//
// It relays raw DNS messages over UDP and TCP to the exit's own resolvers
// and understands nothing but the message length and ID.
package dnsfwd

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	queryTimeout = 5 * time.Second
	maxInflight  = 256
)

// Forwarder answers DNS queries on one address.
type Forwarder struct {
	upstreams func() []netip.AddrPort
	log       *slog.Logger
	udp       *net.UDPConn
	tcp       *net.TCPListener
	sem       chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
}

// Listen starts a forwarder on addr (port 53 in production; 0 picks one).
func Listen(addr netip.AddrPort, upstreams func() []netip.AddrPort, log *slog.Logger) (*Forwarder, error) {
	u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, err
	}
	port := u.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	t, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr.Addr(), port)))
	if err != nil {
		u.Close()
		return nil, err
	}
	f := &Forwarder{upstreams: upstreams, log: log, udp: u, tcp: t, sem: make(chan struct{}, maxInflight)}
	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()
	return f, nil
}

// Addr is where the forwarder listens (UDP and TCP).
func (f *Forwarder) Addr() netip.AddrPort { return f.udp.LocalAddr().(*net.UDPAddr).AddrPort() }

// Close stops the forwarder.
func (f *Forwarder) Close() {
	f.once.Do(func() {
		f.udp.Close()
		f.tcp.Close()
		f.wg.Wait()
	})
}

func (f *Forwarder) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := f.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < 12 {
			continue
		}
		select {
		case f.sem <- struct{}{}:
		default:
			continue // overloaded: the client retries
		}
		q := append([]byte(nil), buf[:n]...)
		f.wg.Add(1)
		go func() {
			defer func() { <-f.sem; f.wg.Done() }()
			if resp, err := f.exchange(q, "udp"); err == nil {
				f.udp.WriteToUDPAddrPort(resp, src)
			}
		}()
	}
}

func (f *Forwarder) serveTCP() {
	defer f.wg.Done()
	for {
		c, err := f.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		select {
		case f.sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		f.wg.Add(1)
		go func() {
			defer func() { <-f.sem; f.wg.Done(); c.Close() }()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readMsg(c)
				if err != nil {
					return
				}
				resp, err := f.exchange(q, "tcp")
				if err != nil || writeMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

// exchange asks the upstreams in turn. A truncated UDP answer is passed
// on as is: the client repeats the query over TCP.
func (f *Forwarder) exchange(q []byte, network string) ([]byte, error) {
	last := errors.New("dnsfwd: no upstream resolvers")
	for _, up := range f.upstreams() {
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		resp, err := exchangeOne(ctx, network, up, q)
		cancel()
		if err == nil {
			return resp, nil
		}
		last = err
	}
	f.log.Debug("dns query failed", "err", last)
	return nil, last
}

func exchangeOne(ctx context.Context, network string, up netip.AddrPort, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, up.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	if network == "udp" {
		if _, err := c.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return nil, err
			}
			if n >= 12 && buf[0] == q[0] && buf[1] == q[1] { // same ID
				return buf[:n], nil
			}
		}
	}
	if err := writeMsg(c, q); err != nil {
		return nil, err
	}
	return readMsg(c)
}

func readMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(l[:])
	if n < 12 {
		return nil, errors.New("dnsfwd: short message")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeMsg(w io.Writer, m []byte) error {
	b := make([]byte, 2+len(m))
	binary.BigEndian.PutUint16(b, uint16(len(m)))
	copy(b[2:], m)
	_, err := w.Write(b)
	return err
}

// SystemUpstreams reads the name servers of a resolv.conf. Loopback
// resolvers such as systemd-resolved (127.0.0.53) work too: the forwarder
// runs on the exit itself.
func SystemUpstreams(path string) []netip.AddrPort {
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	var out []netip.AddrPort
	s := bufio.NewScanner(fh)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, netip.AddrPortFrom(a.WithZone(""), 53))
			}
		}
	}
	return out
}
