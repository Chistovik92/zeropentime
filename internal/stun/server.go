// SPDX-License-Identifier: MPL-2.0

package stun

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
)

// Serve answers Binding requests on each of the UDP addresses until ctx is
// done. Two ports on one host are enough for nodes to tell whether their
// NAT keeps the same external port for different destinations.
func Serve(ctx context.Context, addrs []string, log *slog.Logger) error {
	var conns []*net.UDPConn
	for _, a := range addrs {
		ua, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			return err
		}
		c, err := net.ListenUDP("udp", ua)
		if err != nil {
			for _, c := range conns {
				c.Close()
			}
			return err
		}
		conns = append(conns, c)
		log.Info("stun listening", "addr", c.LocalAddr().String())
	}
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(c, log)
		}()
	}
	<-ctx.Done()
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	return nil
}

func serveConn(c *net.UDPConn, log *slog.Logger) {
	buf := make([]byte, MaxMessage)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debug("stun read", "err", err)
			continue
		}
		id, err := ParseRequest(buf[:n])
		if err != nil {
			continue // not for us; never answer garbage (no amplification)
		}
		c.WriteToUDPAddrPort(Response(id, from), from)
	}
}
