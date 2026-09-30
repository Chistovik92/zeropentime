// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/store"
)

func joinNode(t *testing.T, svc *Service, room string, token string, name string) (*api.JoinResponse, error) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := &api.JoinRequest{RoomID: room, Token: token, Name: name}
	rand.Read(req.WGKey[:])
	rand.Read(req.BoxKey[:])
	return svc.Join(context.Background(), pub, req, netip.MustParseAddr("203.0.113.5"))
}

func TestQuotas(t *testing.T) {
	_, svc := newTestServer(t)
	ctx := context.Background()
	svc.SetQuotas(1, 2)
	if err := svc.CreateUser(ctx, nil, "bob", "bobs long password", false); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Login(ctx, "bob", "bobs long password", "")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, _ := svc.Session(ctx, tok)
	if _, err := svc.CreateRoom(ctx, bob, "first", "", "auto"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateRoom(ctx, bob, "second", "", "auto"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second room: %v, want the quota error", err)
	}
	atok, _ := svc.Login(ctx, "admin", "correct horse battery", "")
	admin, _, _ := svc.Session(ctx, atok)
	for _, n := range []string{"a", "b"} { // admins are not limited
		if _, err := svc.CreateRoom(ctx, admin, n, "", "auto"); err != nil {
			t.Fatal(err)
		}
	}

	rooms, _ := svc.Rooms(ctx, bob)
	inv, err := svc.CreateInvite(ctx, bob, "http://x", rooms[0].ID, 10, time.Hour, true, "")
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"n1", "n2", "n3"} {
		_, err := joinNode(t, svc, rooms[0].ID, inv.Token, name)
		if i < 2 && err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if i == 2 && !errors.Is(err, ErrForbidden) {
			t.Fatalf("third member: %v, want ErrForbidden (room full)", err)
		}
	}
}

func TestDashboardAndTopology(t *testing.T) {
	_, svc := newTestServer(t)
	ctx := context.Background()
	atok, _ := svc.Login(ctx, "admin", "correct horse battery", "")
	admin, _, _ := svc.Session(ctx, atok)
	r, err := svc.CreateRoom(ctx, admin, "games", "", "auto")
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := svc.CreateInvite(ctx, admin, "http://x", r.ID, 10, time.Hour, true, "")
	for _, n := range []string{"one", "two"} {
		if _, err := joinNode(t, svc, r.ID, inv.Token, n); err != nil {
			t.Fatal(err)
		}
	}
	d, err := svc.Dashboard(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if d.Rooms != 1 || d.Members != 2 || d.Nodes != 2 || d.DirectPercent() != -1 {
		t.Fatalf("dashboard: %+v", d)
	}
	rv, _ := svc.Room(ctx, admin, r.ID)
	rv.Members[0].Name = `<script>x</script>`
	svg := string(Topology(rv.Members, func(store.Member) bool { return true }))
	if !strings.Contains(svg, "<svg") || strings.Contains(svg, "<script>") || strings.Count(svg, "<circle") != 2 {
		t.Fatalf("topology: %s", svg)
	}
	if Topology(rv.Members[:1], func(store.Member) bool { return true }) != "" {
		t.Fatal("one member needs no graph")
	}
}

func TestDashboardPage(t *testing.T) {
	hs, _ := newTestServer(t)
	b := newBrowser(t, hs.URL)
	b.post("/login", map[string][]string{"login": {"admin"}, "password": {"correct horse battery"}})
	if code, body := b.get("/dashboard"); code != 200 || !strings.Contains(body, "устройств в сети") {
		t.Fatalf("dashboard page: %d", code)
	}
}
