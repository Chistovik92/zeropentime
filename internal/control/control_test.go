// SPDX-License-Identifier: MPL-2.0

package control

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeNode struct{ reloads chan struct{} }

func (f *fakeNode) Status() Status { return Status{NodeID: "node1", Rooms: []Room{{Name: "game"}}} }
func (f *fakeNode) Reload()        { f.reloads <- struct{}{} }

func TestServeAndClient(t *testing.T) {
	useTempChannel(t)
	c := NewClient()
	if _, err := c.Status(); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("no node: got %v, want ErrNotRunning", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &fakeNode{reloads: make(chan struct{}, 1)}
	go func() {
		if err := Serve(ctx, n); err != nil {
			t.Error(err)
		}
	}()
	var s *Status
	var err error
	for range 50 {
		if s, err = c.Status(); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || s.NodeID != "node1" || len(s.Rooms) != 1 {
		t.Fatalf("status %+v, %v", s, err)
	}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-n.reloads:
	case <-time.After(5 * time.Second):
		t.Fatal("reload not delivered")
	}
}
