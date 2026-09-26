// SPDX-License-Identifier: MPL-2.0

package netmark

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows has no firewall marks. While traffic goes through an exit, the
// node's sockets are bound to the interface of the ordinary default route
// (IP_UNICAST_IF), like wireguard-windows does, so they bypass the room's
// 0.0.0.0/1 and 128.0.0.0/1 routes.

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

var (
	bypass  atomic.Bool
	ifIndex atomic.Uint64 // IPv4 index << 32 | IPv6 index

	mu      sync.Mutex
	tracked = map[*trackedConn]bool{}
	stop    chan struct{}
)

type trackedConn struct{ c syscall.Conn }

func mark(fd uintptr) {
	if !bypass.Load() {
		return
	}
	idx := ifIndex.Load()
	bind(windows.Handle(fd), uint32(idx>>32), uint32(idx))
}

func bind(h windows.Handle, v4, v6 uint32) {
	// IP_UNICAST_IF takes the index in network byte order, IPV6_UNICAST_IF in host order.
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], v4)
	windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(*(*uint32)(unsafe.Pointer(&be[0]))))
	windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(v6))
}

// Track keeps a long-lived socket (the node's UDP socket) bound to the
// current default interface while traffic goes through an exit.
func Track(c syscall.Conn) (untrack func()) {
	t := &trackedConn{c}
	mu.Lock()
	tracked[t] = true
	mu.Unlock()
	apply(t)
	return func() {
		mu.Lock()
		delete(tracked, t)
		mu.Unlock()
	}
}

func apply(t *trackedConn) {
	rc, err := t.c.SyscallConn()
	if err != nil {
		return
	}
	var v4, v6 uint32
	if bypass.Load() {
		idx := ifIndex.Load()
		v4, v6 = uint32(idx>>32), uint32(idx)
	}
	rc.Control(func(fd uintptr) { bind(windows.Handle(fd), v4, v6) }) // 0 unbinds
}

func applyAll() {
	mu.Lock()
	defer mu.Unlock()
	for t := range tracked {
		apply(t)
	}
}

// SetBypass turns the binding of the node's sockets on or off.
func SetBypass(on bool) {
	mu.Lock()
	if on == bypass.Load() {
		mu.Unlock()
		return
	}
	if on {
		updateIndex()
		stop = make(chan struct{})
		go watch(stop)
	} else {
		close(stop)
	}
	bypass.Store(on)
	mu.Unlock()
	applyAll()
}

// watch follows the default interface (Wi-Fi to Ethernet and back).
func watch(stop chan struct{}) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if updateIndex() {
				applyAll()
			}
		}
	}
}

func updateIndex() (changed bool) {
	v := uint64(defaultIndex(windows.AF_INET))<<32 | uint64(defaultIndex(windows.AF_INET6))
	return ifIndex.Swap(v) != v
}

// defaultIndex is the interface of the best default route (0 if none).
func defaultIndex(family winipcfg.AddressFamily) uint32 {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0
	}
	best, bestMetric := uint32(0), ^uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		iface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil || !iface.Connected {
			continue
		}
		if m := r.Metric + iface.Metric; m < bestMetric {
			best, bestMetric = r.InterfaceIndex, m
		}
	}
	return best
}
