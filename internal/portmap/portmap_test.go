// SPDX-License-Identifier: MPL-2.0

package portmap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeMapper struct {
	mu      sync.Mutex
	ext     netip.AddrPort
	life    time.Duration
	fail    bool
	adds    int
	removed bool
}

func (f *fakeMapper) name() string { return "fake" }
func (f *fakeMapper) add(context.Context, uint16, time.Duration) (netip.AddrPort, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds++
	if f.fail {
		return netip.AddrPort{}, 0, errors.New("router said no")
	}
	return f.ext, f.life, nil
}
func (f *fakeMapper) remove(context.Context, uint16, uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = true
	return nil
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func withMappers(t *testing.T, ms ...mapper) {
	old := discover
	discover = func(context.Context) []mapper { return ms }
	t.Cleanup(func() { discover = old })
}

func TestRunRenewsAndRemoves(t *testing.T) {
	f := &fakeMapper{ext: netip.MustParseAddrPort("203.0.113.5:4790"), life: 100 * time.Millisecond}
	withMappers(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan netip.AddrPort, 10)
	done := make(chan struct{})
	go func() { Run(ctx, 4790, quiet, func(a netip.AddrPort) { got <- a }); close(done) }()

	if a := <-got; a != f.ext {
		t.Fatalf("reported %v, want %v", a, f.ext)
	}
	time.Sleep(350 * time.Millisecond) // ~6 renewals at life/2
	cancel()
	<-done
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.adds < 4 {
		t.Errorf("mapping renewed %d times, want several", f.adds-1)
	}
	if !f.removed {
		t.Error("mapping not removed on shutdown")
	}
}

func TestPrivateExternalAddressIgnored(t *testing.T) {
	double := &fakeMapper{ext: netip.MustParseAddrPort("192.168.0.2:4790"), life: time.Hour}
	cgn := &fakeMapper{ext: netip.MustParseAddrPort("100.72.1.1:4790"), life: time.Hour}
	good := &fakeMapper{ext: netip.MustParseAddrPort("198.51.100.7:4790"), life: time.Hour}
	withMappers(t, double, cgn, good)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan netip.AddrPort, 1)
	go Run(ctx, 4790, quiet, func(a netip.AddrPort) { got <- a })
	if a := <-got; a != good.ext {
		t.Fatalf("reported %v, want the public mapping %v", a, good.ext)
	}
	if !double.removed || !cgn.removed {
		t.Error("useless mappings behind another NAT were not removed")
	}
}

func TestNoRouter(t *testing.T) {
	withMappers(t, &fakeMapper{fail: true})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	called := false
	Run(ctx, 4790, quiet, func(a netip.AddrPort) { called = true })
	if called {
		t.Error("onChange called although no mapping ever existed")
	}
}
