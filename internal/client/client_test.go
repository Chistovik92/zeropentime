// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestCachedDialKeepsLastAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	dnsUp := true
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		if !dnsUp {
			return nil, errors.New("no DNS")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	dial := cachedDial(&net.Dialer{}, lookup)
	for i, up := range []bool{true, false} {
		dnsUp = up
		c, err := dial(context.Background(), "tcp", net.JoinHostPort("controller.example", port))
		if err != nil {
			t.Fatalf("dial %d (dns up=%v): %v", i, up, err)
		}
		c.Close()
	}
	if _, err := dial(context.Background(), "tcp", net.JoinHostPort("other.example", port)); err == nil {
		t.Fatal("dialed a name never resolved")
	}
}
