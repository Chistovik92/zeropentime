/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 zeropentime authors.
 */

package netstack

import (
	"net/netip"
	"sync"
	"testing"
)

// Closing while the stack is still sending must not panic ("send on
// closed channel" in upstream).
func TestCloseWhileSending(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev, tnet, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.9.0.2:9"))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // the device reading packets, like wireguard does
			defer wg.Done()
			buf, sizes := [][]byte{make([]byte, 2000)}, []int{0}
			for {
				if _, err := dev.Read(buf, sizes, 0); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, err := c.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
		if i%2 == 0 {
			dev.Close()
		} else {
			go dev.Close()
		}
		wg.Wait()
		dev.Close() // twice is fine
	}
}
