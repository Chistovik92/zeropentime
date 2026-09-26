// SPDX-License-Identifier: AGPL-3.0-only

// Package e2e runs a controller and several nodes in one process (userspace
// network stacks, real UDP on loopback) and checks the phase 1 scenarios.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/client"
	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/controller"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/node"
	"github.com/Chistovik92/zeropentime/internal/store"
	"github.com/Chistovik92/zeropentime/internal/stun"

	"github.com/Chistovik92/zeropentime/internal/testutil"
)

var quiet = slog.New(slog.DiscardHandler)

// logBuf collects debug logs in memory and prints them only if the test fails.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func testLogger(t *testing.T) *slog.Logger {
	lb := &logBuf{}
	t.Cleanup(func() {
		if t.Failed() {
			lb.mu.Lock()
			defer lb.mu.Unlock()
			os.WriteFile(filepath.Join(os.TempDir(), "zpt-e2e-"+t.Name()+".log"), lb.buf.Bytes(), 0o600)
			t.Logf("debug log: %s", filepath.Join(os.TempDir(), "zpt-e2e-"+t.Name()+".log"))
		}
	})
	return slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type env struct {
	t     *testing.T
	svc   *controller.Service
	log   *slog.Logger
	url   string
	admin *store.User
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(testutil.TempDir(t), "ctl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc, err := controller.NewService(st, quiet)
	if err != nil {
		t.Fatal(err)
	}
	// A real STUN server on two loopback ports, like zpt-controller runs.
	var stunAddrs []string
	for range 2 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		stunAddrs = append(stunAddrs, c.LocalAddr().String())
		c.Close()
	}
	sctx, stopSTUN := context.WithCancel(context.Background())
	t.Cleanup(stopSTUN)
	go stun.Serve(sctx, stunAddrs, quiet)

	rc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := rc.LocalAddr().String()
	rc.Close()

	// The website REALITY imitates: a local TLS 1.3 server for example.com.
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("real site")) }))
	site.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	site.StartTLS()
	t.Cleanup(site.Close)
	vl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	vlessAddr := vl.Addr().String()
	vl.Close()

	srv, err := controller.NewServer(controller.Config{
		STUNListen: stunAddrs, RelayListen: relayAddr,
		VLESSListen: vlessAddr, VLESSPublic: vlessAddr, VLESSDest: site.Listener.Addr().String(), VLESSServerNames: []string{"example.com"},
	}, svc, quiet)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	go srv.RunRelay(sctx)
	go srv.RunVLESS(sctx)

	ctx := context.Background()
	if err := svc.CreateUser(ctx, nil, "admin", "correct horse battery", true); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Login(ctx, "admin", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := svc.Session(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, svc: svc, log: testLogger(t), url: hs.URL, admin: admin}
}

func (e *env) room(name, policy string) *store.Room {
	r, err := e.svc.CreateRoom(context.Background(), e.admin, name, "", policy)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) invite(roomID string, uses int, auto bool) api.Invite {
	inv, err := e.svc.CreateInvite(context.Background(), e.admin, e.url, roomID, uses, time.Hour, auto, "")
	if err != nil {
		e.t.Fatal(err)
	}
	return inv
}

type testNode struct {
	id    *identity.Identity
	state string
	node  *node.Node
}

func (e *env) node(name string) *testNode {
	e.t.Helper()
	return e.nodeWith(name, func(uint16, []netip.Prefix) []netip.AddrPort { return nil })
}

func (e *env) nodeWith(name string, locals func(uint16, []netip.Prefix) []netip.AddrPort) *testNode {
	e.t.Helper()
	return e.nodeOpts(name, locals, false)
}

func (e *env) nodeOpts(name string, locals func(uint16, []netip.Prefix) []netip.AddrPort, blockDirect bool) *testNode {
	e.t.Helper()
	return e.nodeFull(name, locals, blockDirect, false)
}

func (e *env) nodeFull(name string, locals func(uint16, []netip.Prefix) []netip.AddrPort, blockDirect, blockUDPRelay bool) *testNode {
	e.t.Helper()
	return e.nodeCfg(name, locals, blockDirect, blockUDPRelay, nil)
}

func (e *env) nodeCfg(name string, locals func(uint16, []netip.Prefix) []netip.AddrPort, blockDirect, blockUDPRelay bool, tweak func(*config.Config)) *testNode {
	e.t.Helper()
	id, _ := identity.Generate()
	dir := testutil.TempDir(e.t)
	port := 0
	cfg := &config.Config{ListenPort: &port, Userspace: true}
	if tweak != nil {
		tweak(cfg)
	}
	if err := cfg.Validate(); err != nil {
		e.t.Fatal(err)
	}
	tn := &testNode{id: id, state: filepath.Join(dir, "state.json")}
	n, err := node.Start(node.Options{
		Config: cfg, Identity: id, Log: e.log.With("node", name), StatePath: tn.state, Version: "test",
		LocalEndpoints: locals, BlockDirectForTests: blockDirect, BlockUDPRelayForTests: blockUDPRelay,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { n.Close() })
	tn.node = n
	return tn
}

// join does what "zpt join" does.
func (e *env) join(tn *testNode, inv api.Invite, name string) (*api.JoinResponse, error) {
	resp, err := client.New(inv.Controller, tn.id, "test").Join(context.Background(), inv, name, api.Endpoints{UDPPort: tn.node.Port()})
	if err != nil {
		return nil, err
	}
	st, err := node.LoadState(tn.state)
	if err != nil {
		return nil, err
	}
	st.Pin(inv.Controller, inv.RoomID, inv.RoomKey)
	return resp, st.Save(tn.state)
}

func (e *env) mustJoin(tn *testNode, inv api.Invite, name, wantStatus string) {
	e.t.Helper()
	resp, err := e.join(tn, inv, name)
	if err != nil {
		e.t.Fatal(err)
	}
	if resp.Status != wantStatus {
		e.t.Fatalf("%s: status %q, want %q", name, resp.Status, wantStatus)
	}
}

func (e *env) act(roomID string, tn *testNode, a controller.MemberAction) {
	e.t.Helper()
	if err := e.svc.MemberAction(context.Background(), e.admin, roomID, tn.id.NodeID(), a); err != nil {
		e.t.Fatal(err)
	}
}

func eventually(t *testing.T, timeout time.Duration, what string, fn func() error) time.Duration {
	t.Helper()
	start := time.Now()
	var err error
	for time.Since(start) < timeout {
		if err = fn(); err == nil {
			return time.Since(start)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: not reached in %s: %v", what, timeout, err)
	return 0
}

func hasRoom(tn *testNode, name string, peers int) func() error {
	return func() error {
		r, err := tn.node.Room(name)
		if err != nil {
			return err
		}
		stats, _ := r.Stats()
		if got := bytes.Count([]byte(stats), []byte("public_key=")); got != peers {
			return fmt.Errorf("room %s has %d peers, want %d", name, got, peers)
		}
		return nil
	}
}

func noRoom(tn *testNode, name string) func() error {
	return func() error {
		if _, err := tn.node.Room(name); err == nil {
			return errors.New("room still running")
		}
		return nil
	}
}

func serveEcho(t *testing.T, tn *testNode, roomName string) netip.AddrPort {
	t.Helper()
	r, err := tn.node.Room(roomName)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := r.Net.ListenTCP(&net.TCPAddr{IP: r.Address.Addr().AsSlice(), Port: 7000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return netip.AddrPortFrom(r.Address.Addr(), 7000)
}

func talk(tn *testNode, roomName string, dst netip.AddrPort, timeout time.Duration) error {
	r, err := tn.node.Room(roomName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := r.Net.DialContextTCPAddrPort(ctx, dst)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	msg := []byte("hello through the room")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return errors.New("echo mismatch")
	}
	return nil
}

// Phase 1 demo: create a room, invite three nodes, approve them, talk,
// kick one and see it disappear everywhere within 5 seconds.
func TestInviteApproveTalkKick(t *testing.T) {
	e := newEnv(t)
	game := e.room("Игры", "manual")
	inv := e.invite(game.ID, 3, false)

	a, b, c := e.node("a"), e.node("b"), e.node("c")
	e.mustJoin(a, inv, "alice", "pending")
	e.mustJoin(b, inv, "bob", "pending")
	e.mustJoin(c, inv, "carol", "pending")

	// Pending members get nothing.
	time.Sleep(time.Second)
	if _, err := a.node.Room("igry"); err == nil {
		t.Fatal("room started before approval")
	}

	for _, n := range []*testNode{a, b, c} {
		e.act(game.ID, n, controller.ActApprove)
	}
	for _, n := range []*testNode{a, b, c} {
		eventually(t, 10*time.Second, "room with 2 peers", hasRoom(n, "igry", 2))
	}

	srv := serveEcho(t, a, "igry")
	eventually(t, 10*time.Second, "b talks to a", func() error { return talk(b, "igry", srv, 3*time.Second) })
	eventually(t, 10*time.Second, "c talks to a", func() error { return talk(c, "igry", srv, 3*time.Second) })

	// The invite had 3 uses: a fourth node is refused.
	if _, err := e.join(e.node("d"), inv, "dave"); !client.IsForbidden(err) {
		t.Fatalf("used-up invite accepted: %v", err)
	}

	e.act(game.ID, c, controller.ActKick)
	took := eventually(t, 5*time.Second, "kicked node loses the room", noRoom(c, "igry"))
	eventually(t, 5*time.Second, "others drop the kicked peer", func() error {
		if err := hasRoom(a, "igry", 1)(); err != nil {
			return err
		}
		return hasRoom(b, "igry", 1)()
	})
	t.Logf("kick propagated in %s", took)
	if err := talk(b, "igry", srv, 3*time.Second); err != nil {
		t.Fatalf("remaining members lost connectivity after kick: %v", err)
	}
}

// One node in two rooms from the same controller; a banned node cannot
// come back with a fresh invite.
func TestTwoRoomsAndBan(t *testing.T) {
	e := newEnv(t)
	game := e.room("game", "auto")
	work := e.room("work", "manual")

	a, b := e.node("a"), e.node("b")
	e.mustJoin(a, e.invite(game.ID, 0, false), "alice", "active") // auto room
	e.mustJoin(b, e.invite(game.ID, 0, false), "bob", "active")
	e.mustJoin(a, e.invite(work.ID, 1, true), "alice", "active") // auto-approve invite
	e.mustJoin(b, e.invite(work.ID, 1, true), "bob", "active")

	for _, n := range []*testNode{a, b} {
		eventually(t, 10*time.Second, "game", hasRoom(n, "game", 1))
		eventually(t, 10*time.Second, "work", hasRoom(n, "work", 1))
	}
	gameSrv := serveEcho(t, a, "game")
	workSrv := serveEcho(t, a, "work")
	eventually(t, 10*time.Second, "game traffic", func() error { return talk(b, "game", gameSrv, 3*time.Second) })
	eventually(t, 10*time.Second, "work traffic", func() error { return talk(b, "work", workSrv, 3*time.Second) })

	e.act(work.ID, b, controller.ActBan)
	eventually(t, 5*time.Second, "banned node loses work", noRoom(b, "work"))
	if err := talk(b, "game", gameSrv, 3*time.Second); err != nil {
		t.Fatalf("ban in one room broke another room: %v", err)
	}
	if _, err := e.join(b, e.invite(work.ID, 1, true), "bob"); !client.IsForbidden(err) {
		t.Fatalf("banned node rejoined: %v", err)
	}
}

// If the room key pinned from the invite does not match the key the
// configs are signed with (e.g. a forged or swapped controller), the node
// must refuse to start the room.
func TestWrongPinnedKeyRejected(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	other := e.room("other", "auto")

	a := e.node("a")
	inv := e.invite(room.ID, 1, false)
	inv.RoomKey = e.invite(other.ID, 1, false).RoomKey // pin the wrong key
	e.mustJoin(a, inv, "alice", "active")

	time.Sleep(2 * time.Second)
	if len(a.node.Rooms()) != 0 {
		t.Fatal("node started a room whose config is signed by an unpinned key")
	}
}

// Regression: "zpt join" pins the room key after the controller already
// pushed the netmap that contains the room. The daemon must still start it.
func TestPinAfterNetmapArrived(t *testing.T) {
	e := newEnv(t)
	room := e.room("late", "auto")
	a := e.node("a")
	// Follow the controller through another room so a syncer is running.
	e.mustJoin(a, e.invite(e.room("first", "auto").ID, 1, false), "alice", "active")
	eventually(t, 10*time.Second, "first room", hasRoom(a, "first", 0))

	inv := e.invite(room.ID, 1, false)
	if _, err := client.New(inv.Controller, a.id, "test").Join(context.Background(), inv, "alice", api.Endpoints{UDPPort: a.node.Port()}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // the netmap with "late" arrives and is skipped: not pinned yet
	if _, err := a.node.Room("late"); err == nil {
		t.Fatal("room started without a pinned key")
	}
	st, _ := node.LoadState(a.state)
	st.Pin(inv.Controller, inv.RoomID, inv.RoomKey)
	if err := st.Save(a.state); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "room starts after pinning", hasRoom(a, "late", 0))
}

// 0.2.0: nodes learn their external address through the controller's STUN
// server, report it, and peers dial exactly that address.
func TestExternalAddressReported(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	a, b := e.node("a"), e.node("b")
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")

	eventually(t, 15*time.Second, "both nodes report NAT and address", func() error {
		v, err := e.svc.Room(context.Background(), e.admin, room.ID)
		if err != nil {
			return err
		}
		for _, m := range v.Members {
			if m.NAT != "none" || len(m.Reflexive) != 1 || m.Reflexive[0].Addr() != netip.MustParseAddr("127.0.0.1") {
				return fmt.Errorf("%s: nat=%q reflexive=%v", m.Name, m.NAT, m.Reflexive)
			}
		}
		return nil
	})
	eventually(t, 10*time.Second, "peer endpoint is the STUN-reported address", func() error {
		r, err := a.node.Room("game")
		if err != nil {
			return err
		}
		stats, _ := r.Stats()
		want := fmt.Sprintf("endpoint=127.0.0.1:%d", b.node.Port())
		if !bytes.Contains([]byte(stats), []byte(want)) {
			return fmt.Errorf("no %s in\n%s", want, stats)
		}
		return nil
	})
	srv := serveEcho(t, b, "game")
	eventually(t, 10*time.Second, "traffic", func() error { return talk(a, "game", srv, 3*time.Second) })
}

// 0.2.1: each node advertises a "LAN" address that leads nowhere, so the
// controller's first guess for both peers is wrong. Path discovery must
// find the working address on its own and hand it to AmneziaWG.
func TestDiscoFindsWorkingPath(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	dead := func(uint16, []netip.Prefix) []netip.AddrPort {
		return []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")} // discard port
	}
	a, b := e.nodeWith("a", dead), e.nodeWith("b", dead)
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")

	endpointIs := func(n *testNode, port uint16) func() error {
		return func() error {
			r, err := n.node.Room("game")
			if err != nil {
				return err
			}
			stats, _ := r.Stats()
			want := fmt.Sprintf("endpoint=127.0.0.1:%d", port)
			if !bytes.Contains([]byte(stats), []byte(want)) {
				return fmt.Errorf("no %s in\n%s", want, stats)
			}
			return nil
		}
	}
	took := eventually(t, 20*time.Second, "a uses the discovered path to b", endpointIs(a, b.node.Port()))
	eventually(t, 10*time.Second, "b uses the discovered path to a", endpointIs(b, a.node.Port()))
	t.Logf("path discovered in %s", took)

	srv := serveEcho(t, b, "game")
	eventually(t, 10*time.Second, "traffic over the discovered path", func() error { return talk(a, "game", srv, 3*time.Second) })
}

// 0.2.2: no direct path can work (both nodes drop everything that does not
// come through the relay), so traffic must flow through the controller's
// relay — and the relay only ever sees encrypted AmneziaWG packets.
func TestRelayWhenNoDirectPath(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	none := func(uint16, []netip.Prefix) []netip.AddrPort { return nil }
	a, b := e.nodeOpts("a", none, true), e.nodeOpts("b", none, true)
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")

	viaRelay := func(n *testNode) func() error {
		return func() error {
			r, err := n.node.Room("game")
			if err != nil {
				return err
			}
			stats, _ := r.Stats()
			if !bytes.Contains([]byte(stats), []byte("endpoint=[fd7a:7a70:72ff:")) {
				return fmt.Errorf("peer endpoint is not the relay:\n%s", stats)
			}
			return nil
		}
	}
	took := eventually(t, 30*time.Second, "a reaches b through the relay", viaRelay(a))
	eventually(t, 15*time.Second, "b reaches a through the relay", viaRelay(b))
	t.Logf("relay path in %s", took)

	srv := serveEcho(t, b, "game")
	eventually(t, 15*time.Second, "traffic through the relay", func() error { return talk(a, "game", srv, 3*time.Second) })
	eventually(t, 15*time.Second, "panel knows the peers are relayed", func() error {
		if p := e.svc.Paths(a.id.NodeID()); p.Relay != 1 || p.Direct != 0 {
			return fmt.Errorf("paths %+v", p)
		}
		return nil
	})
	page := e.panelPage("/rooms/" + room.ID)
	for _, want := range []string{"через relay: 1", "alice", "bob"} {
		if !strings.Contains(page, want) {
			t.Errorf("room page misses %q", want)
		}
	}
}

// panelPage logs into the admin panel and returns the page body.
func (e *env) panelPage(path string) string {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	res, err := c.PostForm(e.url+"/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}})
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	res, err = c.Get(e.url + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s: %d\n%s", path, res.StatusCode, body)
	}
	return string(body)
}

// Regression (0.2.1): the relay answers before NAT holes are punched, so a
// peer is first reached through it. Once a direct path works, the nodes
// must switch to it within seconds, not at the next slow re-check.
func TestSwitchFromRelayToDirect(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	none := func(uint16, []netip.Prefix) []netip.AddrPort { return nil }
	a, b := e.nodeOpts("a", none, true), e.nodeOpts("b", none, true)
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")
	eventually(t, 30*time.Second, "relayed first", func() error {
		if p := e.svc.Paths(a.id.NodeID()); p.Relay != 1 {
			return fmt.Errorf("paths %+v", p)
		}
		return nil
	})

	a.node.DropDirectForTests(false)
	b.node.DropDirectForTests(false)
	took := eventually(t, 10*time.Second, "switched to the direct path", func() error {
		if p := e.svc.Paths(a.id.NodeID()); p.Direct != 1 || p.Relay != 0 {
			return fmt.Errorf("paths %+v", p)
		}
		return nil
	})
	t.Logf("switched to direct in %s", took)
}

// 0.2.2: no direct path and no UDP to the relay (UDP blocked by the
// network): nodes reach the relay through VLESS + REALITY over TCP.
func TestRelayOverVLESS(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	none := func(uint16, []netip.Prefix) []netip.AddrPort { return nil }
	a := e.nodeFull("a", none, true, true)
	b := e.nodeFull("b", none, true, true)
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")

	took := eventually(t, 40*time.Second, "peers reach each other through the relay over VLESS", func() error {
		if p := e.svc.Paths(a.id.NodeID()); p.Relay != 1 {
			return fmt.Errorf("a paths %+v", p)
		}
		if p := e.svc.Paths(b.id.NodeID()); p.Relay != 1 {
			return fmt.Errorf("b paths %+v", p)
		}
		return nil
	})
	t.Logf("relay over VLESS in %s", took)
	srv := serveEcho(t, b, "game")
	eventually(t, 15*time.Second, "traffic over VLESS", func() error { return talk(a, "game", srv, 3*time.Second) })
}

// 0.3.0: a member offers the network behind it; only after a room admin
// approves does it reach the other members (signed in the room config),
// and revoking takes it away again.
func TestSubnetRouteApproval(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	none := func(uint16, []netip.Prefix) []netip.AddrPort { return nil }
	lan := netip.MustParsePrefix("192.168.77.0/24")
	a := e.node("a")
	b := e.nodeCfg("b", none, false, false, func(c *config.Config) { c.AdvertiseRoutes = []netip.Prefix{lan} })
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")

	peerHas := func(want bool) func() error {
		return func() error {
			r, err := a.node.Room("game")
			if err != nil {
				return err
			}
			stats, _ := r.Stats()
			if got := strings.Contains(stats, "allowed_ip=192.168.77.0/24"); got != want {
				return fmt.Errorf("route present=%v, want %v", got, want)
			}
			return nil
		}
	}
	eventually(t, 15*time.Second, "b offers its network", func() error {
		v, _ := e.svc.Room(context.Background(), e.admin, room.ID)
		for _, m := range v.Members {
			if m.Name == "bob" && len(m.Offered) == 1 {
				return nil
			}
		}
		return errors.New("not offered yet")
	})
	eventually(t, 5*time.Second, "not routed before approval", peerHas(false))

	e.act(room.ID, b, controller.ActRoutes)
	eventually(t, 10*time.Second, "routed after approval", peerHas(true))
	e.act(room.ID, b, controller.ActNoRoutes)
	eventually(t, 10*time.Second, "not routed after revoke", peerHas(false))
}

// 0.3.1: a member offers to be an exit node; after a room admin approves
// it, a member sends its internet traffic there when the admin picks that
// exit for it in the panel or the member picks it itself ("zpt exit"),
// and the member's own choice wins.
func TestExitNode(t *testing.T) {
	e := newEnv(t)
	room := e.room("game", "auto")
	none := func(uint16, []netip.Prefix) []netip.AddrPort { return nil }
	a := e.node("a")
	b := e.nodeCfg("b", none, false, false, func(c *config.Config) { c.AdvertiseExit = true })
	e.mustJoin(a, e.invite(room.ID, 0, false), "alice", "active")
	e.mustJoin(b, e.invite(room.ID, 0, false), "bob", "active")
	ctx := context.Background()

	exitVia := func(want bool) func() error {
		return func() error {
			r, err := a.node.Room("game")
			if err != nil {
				return err
			}
			stats, _ := r.Stats()
			if got := strings.Contains(stats, "allowed_ip=0.0.0.0/0"); got != want {
				return fmt.Errorf("default route to bob=%v, want %v", got, want)
			}
			return nil
		}
	}
	setChoice := func(c *node.ExitChoice) {
		st, err := node.LoadState(a.state)
		if err != nil {
			t.Fatal(err)
		}
		st.Exit = c
		if err := st.Save(a.state); err != nil {
			t.Fatal(err)
		}
	}

	eventually(t, 15*time.Second, "b offers to be an exit", func() error {
		v, _ := e.svc.Room(ctx, e.admin, room.ID)
		for _, m := range v.Members {
			if m.Name == "bob" && m.ExitOffered {
				return nil
			}
		}
		return errors.New("not offered yet")
	})
	if err := e.svc.SetMemberExit(ctx, e.admin, room.ID, a.id.NodeID(), b.id.NodeID()); err == nil {
		t.Fatal("picked an exit that is not approved")
	}
	if err := e.svc.MemberAction(ctx, e.admin, room.ID, a.id.NodeID(), controller.ActExit); err == nil {
		t.Fatal("approved an exit that does not offer itself")
	}
	e.act(room.ID, b, controller.ActExit)
	if !strings.Contains(e.panelPage("/rooms/"+room.ID), "через bob") {
		t.Fatal("panel does not offer bob as an exit")
	}
	eventually(t, 5*time.Second, "approved but not chosen", exitVia(false))

	if err := e.svc.SetMemberExit(ctx, e.admin, room.ID, a.id.NodeID(), b.id.NodeID()); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "exit picked in the panel", exitVia(true))
	eventually(t, 5*time.Second, "DNS through the exit", func() error {
		r, err := a.node.Room("game")
		if err != nil {
			return err
		}
		v, _ := e.svc.Room(ctx, e.admin, room.ID)
		for _, m := range v.Members {
			if on, dns := r.Exit(); m.Name == "bob" && (!on || dns != m.IP) {
				return fmt.Errorf("exit %v, dns %v, want %v", on, dns, m.IP)
			}
		}
		return nil
	})
	setChoice(&node.ExitChoice{Off: true})
	eventually(t, 10*time.Second, "zpt exit off wins over the panel", exitVia(false))
	setChoice(&node.ExitChoice{Room: "game", Member: "bob"})
	eventually(t, 10*time.Second, "zpt exit game bob", exitVia(true))
	e.act(room.ID, b, controller.ActNoExit)
	eventually(t, 10*time.Second, "exit revoked", exitVia(false))
}
