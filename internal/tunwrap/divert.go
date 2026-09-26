// SPDX-License-Identifier: MPL-2.0

package tunwrap

import "time"

// A userspace exit node (package exitnat) takes the room's internet
// packets away from the OS and puts its answers back into the room. For
// that the wrapper can:
//
//   - divert: hand incoming packets (from AmneziaWG) to a function that may
//     keep them instead of the OS;
//   - inject: add packets to the outgoing stream (to AmneziaWG). Reading
//     then goes through a pump goroutine, so injected packets need not wait
//     for the OS to produce one. The pump is chosen when the room comes up
//     (EnablePump), never while a Read may be blocked in the device.

type divertFunc func(pkt []byte) bool

type pumped struct {
	pkt []byte
	err error
}

// EnablePump makes reads go through a goroutine, so Inject works. Call it
// right after New, before AmneziaWG starts reading.
func (d *Device) EnablePump() {
	d.pumpCh = make(chan pumped, 1024)
	d.pumping.Store(true)
	go d.pump()
}

func (d *Device) pump() {
	batch := max(d.Device.BatchSize(), 1)
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := d.Device.Read(bufs, sizes, 0)
		for i := range n {
			d.pumpCh <- pumped{pkt: append([]byte(nil), bufs[i][:sizes[i]]...)}
		}
		if err != nil {
			d.pumpCh <- pumped{err: err}
			close(d.pumpCh)
			return
		}
	}
}

// Inject queues a packet for AmneziaWG (dropped if the queue is full or
// the pump is off).
func (d *Device) Inject(pkt []byte) {
	if !d.pumping.Load() || d.injectClosed.Load() {
		return
	}
	defer func() { recover() }() // the pump closed the channel meanwhile
	select {
	case d.pumpCh <- pumped{pkt: append([]byte(nil), pkt...)}:
	default:
	}
}

// SetDivert sets (nil: removes) the function that may keep incoming packets.
func (d *Device) SetDivert(f func(pkt []byte) bool) {
	if f == nil {
		d.divert.Store(nil)
		return
	}
	df := divertFunc(f)
	d.divert.Store(&df)
}

// readPumped is Read when the pump is on.
func (d *Device) readPumped(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	now := time.Now()
	add := func(p pumped) error {
		if p.err != nil {
			d.injectClosed.Store(true)
			return p.err
		}
		pkt := p.pkt
		if d.shouldForward(pkt) {
			if d.allow(now) {
				for _, peer := range *d.peers.Load() {
					d.pending = append(d.pending, d.wrap(pkt, peer))
				}
			}
			return nil
		}
		if n < len(bufs) && offset+len(pkt) <= len(bufs[n]) {
			sizes[n] = copy(bufs[n][offset:], pkt)
			n++
		}
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pending) == 0 {
		d.mu.Unlock()
		p, ok := <-d.pumpCh
		d.mu.Lock()
		if !ok {
			return 0, errPumpClosed
		}
		if err := add(p); err != nil {
			return n, err
		}
	}
	for n+len(d.pending) < len(bufs) {
		select {
		case p, ok := <-d.pumpCh:
			if !ok {
				return d.drainLocked(bufs, sizes, offset, n), nil
			}
			if err := add(p); err != nil {
				return d.drainLocked(bufs, sizes, offset, n), err
			}
			continue
		default:
		}
		break
	}
	return d.drainLocked(bufs, sizes, offset, n), nil
}

type pumpClosedErr struct{}

func (pumpClosedErr) Error() string { return "tunwrap: device closed" }

var errPumpClosed error = pumpClosedErr{}
