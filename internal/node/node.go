// SPDX-License-Identifier: MPL-2.0

// Package node is the zeropentime daemon: one shared socket, many rooms.
//
// Rooms come from two sources: static rooms in the config file, and rooms
// joined through controllers ("zpt join"), which the node follows by long
// polling and verifies against the room key pinned from the invite.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/client"
	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/disco"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/magicsock"
	"github.com/Chistovik92/zeropentime/internal/netcheck"
	"github.com/Chistovik92/zeropentime/internal/pki"
	"github.com/Chistovik92/zeropentime/internal/portmap"
	"github.com/Chistovik92/zeropentime/internal/relay"
	"github.com/Chistovik92/zeropentime/internal/room"
	"github.com/Chistovik92/zeropentime/internal/vless"
)

const (
	// PeerKeepalive keeps NAT mappings between peers open.
	PeerKeepalive = 25
	// stateCheckEvery is how often the daemon notices new "zpt join"s.
	stateCheckEvery = time.Second
	// netcheckEvery is how often the node re-checks its external address.
	netcheckEvery = time.Minute
)

// Options configure Start.
type Options struct {
	Config   *config.Config
	Identity *identity.Identity
	Log      *slog.Logger
	// StatePath is the "zpt join" state file. Empty: static rooms only.
	StatePath string
	Version   string
	// LocalEndpoints overrides discovery of local addresses (tests).
	LocalEndpoints func(port uint16, exclude []netip.Prefix) []netip.AddrPort
	// LocalAddrs overrides the list of this machine's IPs used by netcheck (tests).
	LocalAddrs func() []netip.Addr
	// BlockDirectForTests accepts only relayed traffic (tests only).
	BlockDirectForTests bool
	// BlockUDPRelayForTests ignores the relay over UDP, forcing VLESS (tests only).
	BlockUDPRelayForTests bool
}

// Node is a running daemon.
type Node struct {
	ID   *identity.Identity
	opts Options
	log  *slog.Logger
	sock *magicsock.Conn

	mu       sync.Mutex
	rooms    map[string]*running    // by room ID, or "static:<name>"
	versions map[string]int64       // highest accepted config version per room
	pending  map[string]string      // last reported non-active status per room
	last     map[string]*api.NetMap // last netmap per controller
	reports  map[string]netcheck.Report
	portMap  netip.AddrPort
	changed  chan struct{} // closed and replaced when our reachability changes
	disco    *discoMgr
	exitNote string // last explanation why the chosen exit is not used
	ksKey    string // the kill switch rules in force ("" = off)
	dnsNote  string // last DNS warning (logged once)
	syncs    map[string]syncInfo
	started  time.Time
	wake     chan struct{} // Reload

	relayMu     sync.Mutex
	vlessConn   atomic.Pointer[vless.PacketConn]
	relay       *relay.Client
	relayAddr   string
	relayCancel context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type running struct {
	room       *room.Room
	tagKey     [16]byte
	controller string // "" for static rooms
	cfg        config.Room
}

// Start opens the shared socket, starts static rooms and follows controllers.
func Start(o Options) (_ *Node, err error) {
	if o.LocalEndpoints == nil {
		o.LocalEndpoints = discoverLocal
	}
	if o.LocalAddrs == nil {
		o.LocalAddrs = netcheck.LocalAddrs
	}
	sock, err := magicsock.Listen(o.Config.Port(), o.Log)
	if err != nil {
		return nil, err
	}
	sock.DropDirectForTests(o.BlockDirectForTests)
	sock.DropRelayUDPForTests(o.BlockUDPRelayForTests)
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		ID: o.Identity, opts: o, log: o.Log, sock: sock, ctx: ctx, cancel: cancel,
		rooms: map[string]*running{}, versions: map[string]int64{}, pending: map[string]string{}, last: map[string]*api.NetMap{},
		reports: map[string]netcheck.Report{}, changed: make(chan struct{}),
		syncs: map[string]syncInfo{}, started: time.Now(), wake: make(chan struct{}, 1),
	}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	n.log.Info("node starting", "node_id", n.ID.NodeID(), "udp_port", sock.Port(), "static_rooms", len(o.Config.Rooms))

	for _, rc := range o.Config.Rooms {
		n.mu.Lock()
		err := n.startLocked("static:"+rc.Name, "", rc)
		n.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	if o.StatePath != "" {
		n.disco = newDiscoMgr(n)
		sock.SetDisco(disco.TagKey(n.disco.pub), n.disco.handle)
		n.wg.Add(2)
		go func() { defer n.wg.Done(); n.disco.run(ctx) }()
		go n.supervise(ctx)
	}
	if !o.Config.Userspace && o.Config.PortMapEnabled() {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			portmap.Run(ctx, sock.Port(), n.log, func(ext netip.AddrPort) {
				n.mu.Lock()
				n.portMap = ext
				n.mu.Unlock()
				n.notifyChanged()
			})
		}()
	}
	return n, nil
}

// notifyChanged wakes the syncers so the controller learns our new
// reachability at once instead of at the end of the current long poll.
func (n *Node) notifyChanged() {
	n.mu.Lock()
	close(n.changed)
	n.changed = make(chan struct{})
	n.mu.Unlock()
}

func (n *Node) changedCh() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.changed
}

// DropDirectForTests switches off (or on) direct traffic at runtime (tests only).
func (n *Node) DropDirectForTests(v bool) { n.sock.DropDirectForTests(v) }

// Port is the UDP port all rooms share.
func (n *Node) Port() uint16 { return n.sock.Port() }

// Rooms returns the running rooms sorted by name.
func (n *Node) Rooms() []*room.Room {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*room.Room, 0, len(n.rooms))
	for _, r := range n.rooms {
		out = append(out, r.room)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Room returns a running room by name.
func (n *Node) Room(name string) (*room.Room, error) {
	for _, r := range n.Rooms() {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no room %q", name)
}

// Close stops everything.
func (n *Node) Close() error {
	n.cancel()
	n.wg.Wait()
	n.mu.Lock()
	for k := range n.rooms {
		n.stopLocked(k)
	}
	if n.ksKey != "" {
		room.DisableKillSwitch()
		n.log.Info("kill switch off: the node stops")
	}
	n.mu.Unlock()
	return n.sock.Close()
}

func (n *Node) startLocked(key, controller string, rc config.Room) error {
	for _, other := range n.rooms {
		if other.cfg.Address.Masked().Overlaps(rc.Address.Masked()) {
			return fmt.Errorf("room %s: subnet %s overlaps room %s (%s)", rc.Name, rc.Address.Masked(), other.cfg.Name, other.cfg.Address.Masked())
		}
	}
	prof := rc.Secret.Derive()
	bind, err := n.sock.Bind(prof.TagKey)
	if err != nil {
		return fmt.Errorf("room %s: %w", rc.Name, err)
	}
	key32, err := n.ID.RoomKey(rc.Secret.RoomID())
	if err != nil {
		n.sock.Unbind(prof.TagKey)
		return err
	}
	r, err := room.Up(room.Options{Config: rc, Key: key32, Bind: bind, Userspace: n.opts.Config.Userspace, Log: n.log,
		DNSUpstreams: n.opts.Config.ExitDNSUpstreams})
	if err != nil {
		n.sock.Unbind(prof.TagKey)
		return err
	}
	r.SetRoutes(rc.Routes)
	r.SetRouter(rc.Routing, rc.ExitNode)
	r.SetExit(rc.Exit)
	n.rooms[key] = &running{room: r, tagKey: prof.TagKey, controller: controller, cfg: rc}
	return nil
}

func (n *Node) stopLocked(key string) {
	r, ok := n.rooms[key]
	if !ok {
		return
	}
	r.room.Close()
	n.sock.Unbind(r.tagKey)
	delete(n.rooms, key)
}

// ---- controllers ----

// reapplyAll applies the last netmap of every controller again (after new
// pins, or when a better path to a peer is found).
func (n *Node) reapplyAll() {
	n.mu.Lock()
	last := make(map[string]*api.NetMap, len(n.last))
	for url, nm := range n.last {
		last[url] = nm
	}
	n.mu.Unlock()
	for url, nm := range last {
		n.apply(url, nm)
	}
}

// supervise starts and stops one syncer per controller in the state file.
func (n *Node) supervise(ctx context.Context) {
	defer n.wg.Done()
	syncers := map[string]context.CancelFunc{}
	var swg sync.WaitGroup
	defer func() {
		for _, c := range syncers {
			c()
		}
		swg.Wait()
	}()
	var prevPins string
	for {
		st, err := LoadState(n.opts.StatePath)
		if err != nil {
			n.log.Error("read state", "path", n.opts.StatePath, "err", err)
		} else {
			// A "zpt join" may pin a room after its netmap already arrived:
			// re-apply the last netmaps whenever the pins change.
			pins := fmt.Sprint(st.Controllers)
			if st.Exit != nil {
				pins += fmt.Sprintf("%+v", *st.Exit)
			}
			if st.DNS != nil {
				pins += fmt.Sprintf("%+v", *st.DNS)
			}
			if pins != prevPins {
				prevPins = pins
				n.reapplyAll()
				n.mu.Lock()
				n.updateKillSwitchLocked(st)
				n.updateDNSLocked(st)
				n.mu.Unlock()
			}
			want := map[string]bool{}
			for _, c := range st.Controllers {
				want[c.URL] = true
				if _, ok := syncers[c.URL]; !ok {
					sctx, cancel := context.WithCancel(ctx)
					syncers[c.URL] = cancel
					swg.Add(1)
					go func(url string) {
						defer swg.Done()
						n.sync(sctx, url)
					}(c.URL)
				}
			}
			for url, cancel := range syncers {
				if !want[url] {
					cancel()
					delete(syncers, url)
					n.apply(url, &api.NetMap{}) // tear its rooms down
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(stateCheckEvery):
		case <-n.wake:
		}
	}
}

// sync long-polls one controller and applies every netmap.
func (n *Node) sync(ctx context.Context, url string) {
	log := n.log.With("controller", url)
	if strings.HasPrefix(url, "http://") {
		log.Warn("controller uses plain HTTP: responses are still encrypted and signed, but use HTTPS in production")
	}
	cl := client.New(url, n.ID, n.opts.Version)
	var since int64
	backoff := time.Second
	stunServers := make(chan []string, 1)
	go n.netcheckLoop(ctx, url, stunServers)
	for ctx.Err() == nil {
		pctx, cancel := context.WithCancel(ctx)
		var woken atomic.Bool
		changed := n.changedCh()
		go func() {
			select {
			case <-changed:
				woken.Store(true)
				cancel()
			case <-pctx.Done():
			}
		}()
		nm, err := cl.Poll(pctx, since, n.endpoints(url))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if woken.Load() {
				continue // our address changed: report it right away
			}
			n.noteSync(url, err)
			log.Warn("controller unreachable, rooms keep running", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		n.noteSync(url, nil)
		since = nm.Version
		select {
		case <-stunServers:
		default:
		}
		stunServers <- nm.STUN
		n.ensureRelay(nm.Relays)
		n.apply(url, nm)
	}
}

// netcheckLoop re-checks the external address with the controller's STUN
// servers every netcheckEvery and whenever the server list changes.
func (n *Node) netcheckLoop(ctx context.Context, url string, servers <-chan []string) {
	var current []string
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-servers:
			if slices.Equal(s, current) {
				continue
			}
			current = s
		case <-timer.C:
		}
		if len(current) == 0 {
			continue
		}
		addrs := netcheck.Resolve(ctx, current)
		r := netcheck.Check(ctx, n.sock, addrs, n.sock.Port(), n.opts.LocalAddrs())
		n.mu.Lock()
		old := n.reports[url]
		n.reports[url] = r
		n.mu.Unlock()
		if old.NAT != r.NAT || !slices.Equal(old.Mapped, r.Mapped) {
			n.log.Info("external address checked", "controller", url, "nat", r.NAT, "mapped", r.Mapped)
			n.notifyChanged()
		}
		timer.Reset(netcheckEvery)
	}
}

func (n *Node) endpoints(url string) api.Endpoints {
	n.mu.Lock()
	var exclude []netip.Prefix
	for _, r := range n.rooms {
		exclude = append(exclude, r.cfg.Address.Masked())
	}
	rep := n.reports[url]
	pm := n.portMap
	n.mu.Unlock()
	return api.Endpoints{
		UDPPort:   n.sock.Port(),
		Locals:    n.opts.LocalEndpoints(n.sock.Port(), exclude),
		Reflexive: rep.Mapped,
		NAT:       rep.NAT,
		PortMap:   pm,
		DiscoKey:  n.discoPub(),
		Relay:     n.relayReadyAddr(),
		Paths:     n.pathStats(),
		Routes:    n.opts.Config.AdvertiseRoutes,
		Exit:      n.opts.Config.AdvertiseExit,
		ExitDNS:   n.opts.Config.AdvertiseExit,
	}
}

// apply brings the rooms of one controller in line with its netmap.
func (n *Node) apply(url string, nm *api.NetMap) {
	st, err := LoadState(n.opts.StatePath)
	if err != nil {
		n.log.Error("read state", "err", err)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.last[url] = nm

	desired := map[string]config.Room{}
	active := map[string]bool{} // peers in rooms we are an active member of
	for _, rs := range nm.Rooms {
		keyStr, pinned := st.RoomKey(url, rs.RoomID)
		if !pinned {
			continue // not joined from this machine (or left)
		}
		if rs.Status != "active" || rs.Config == nil {
			if n.pending[rs.RoomID] != rs.Status {
				n.log.Info("room not active", "room_id", rs.RoomID, "status", rs.Status)
				n.pending[rs.RoomID] = rs.Status
			}
			continue
		}
		delete(n.pending, rs.RoomID)
		rc, err := n.roomFromConfig(url, keyStr, rs, nm, active, st.Exit)
		if err != nil {
			n.log.Error("rejecting room config", "room_id", rs.RoomID, "err", err)
			if cur, ok := n.rooms[rs.RoomID]; ok {
				desired[rs.RoomID] = cur.cfg // keep what we have
			}
			continue
		}
		if rc != nil {
			desired[rs.RoomID] = *rc
		}
	}

	if n.disco != nil {
		n.disco.setPeers(url, nm.Peers, active)
	}

	for key, r := range n.rooms {
		if r.controller == url {
			if _, ok := desired[key]; !ok {
				n.log.Info("leaving room", "room", r.cfg.Name)
				n.stopLocked(key)
			}
		}
	}
	for id, rc := range desired {
		if cur, ok := n.rooms[id]; ok {
			if cur.cfg.Secret == rc.Secret && cur.cfg.Address == rc.Address {
				rc.Name = cur.cfg.Name
				if err := cur.room.SetPeers(rc.Peers); err != nil {
					n.log.Error("update peers", "room", rc.Name, "err", err)
					continue
				}
				cur.room.SetBroadcast(rc.Broadcast)
				cur.room.SetRoutes(rc.Routes)
				cur.room.SetRouter(rc.Routing, rc.ExitNode)
				cur.room.SetExit(rc.Exit)
				cur.cfg = rc
				continue
			}
			n.stopLocked(id)
		}
		rc.Name = n.ifnameLocked(id, rc.Name)
		if err := rc.ValidateRoom(); err != nil {
			n.log.Error("room config invalid", "room", rc.Name, "err", err)
			continue
		}
		if err := n.startLocked(id, url, rc); err != nil {
			n.log.Error("cannot start room", "room", rc.Name, "err", err)
		}
	}
	n.updateKillSwitchLocked(st)
	n.updateDNSLocked(st)
}

// roomFromConfig verifies a signed room config and turns it into a local
// room description. It returns nil if this node is not an active member.
func (n *Node) roomFromConfig(url, keyStr string, rs api.RoomState, nm *api.NetMap, active map[string]bool, exit *ExitChoice) (*config.Room, error) {
	pub, err := pki.ParseRoomKey(keyStr)
	if err != nil {
		return nil, err
	}
	cfg, err := pki.VerifyRoomConfig(pub, rs.Config)
	if err != nil {
		return nil, err
	}
	if cfg.RoomID != rs.RoomID {
		return nil, errors.New("config is for another room")
	}
	if cfg.Version < n.versions[rs.RoomID] {
		return nil, fmt.Errorf("config version %d is older than %d (rollback)", cfg.Version, n.versions[rs.RoomID])
	}
	n.versions[rs.RoomID] = cfg.Version

	me := n.ID.NodeID()
	rc := &config.Room{Name: cfg.Name, Secret: cfg.Secret, MTU: config.DefaultMTU, Broadcast: cfg.Broadcast, RoomDNS: cfg.DNS}
	exitID := n.exitPeerLocked(exit, rs, cfg)
	found := false
	for _, m := range cfg.Members {
		if m.NodeID == me {
			rc.Address = netip.PrefixFrom(m.IP, cfg.Subnet.Bits())
			rc.Routing = m.Routes
			rc.ExitNode = m.Exit && n.opts.Config.AdvertiseExit
			found = true
			continue
		}
		active[m.NodeID] = true
		allowed := []netip.Prefix{netip.PrefixFrom(m.IP, 32)}
		for _, r := range m.Routes {
			if why := n.routeConflictLocked(r, rs.RoomID, cfg.Subnet); why != "" {
				n.log.Warn("not using a member's network", "room", cfg.Name, "member", m.Name, "route", r, "reason", why)
				continue
			}
			allowed = append(allowed, r)
			rc.Routes = append(rc.Routes, r)
		}
		if rc.PeerNodes == nil {
			rc.PeerNodes = map[identity.Key]string{}
		}
		rc.PeerNodes[m.WGKey] = m.NodeID
		if m.NodeID == exitID {
			allowed = append(allowed, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
			rc.Exit, rc.ExitPeer = true, m.NodeID
			if m.ExitDNS {
				rc.ExitDNS = m.IP
			}
		}
		rc.Peers = append(rc.Peers, config.Peer{
			Name:       m.Name,
			PublicKey:  m.WGKey,
			Endpoint:   n.peerEndpoint(m.NodeID, chooseEndpoint(nm.Peers[m.NodeID], nm.ObservedIP, n.localPrefixes())),
			AllowedIPs: allowed,
			Keepalive:  PeerKeepalive,
		})
	}
	if !found {
		return nil, nil
	}
	return rc, nil
}

// exitPeerLocked picks the member of a room this node sends its internet
// traffic through ("" = none): the one chosen with "zpt exit", else the one
// a room admin picked. It must be an approved exit in the signed config,
// and only one room at a time carries the internet traffic.
func (n *Node) exitPeerLocked(choice *ExitChoice, rs api.RoomState, cfg *pki.RoomConfig) string {
	var byName, byID string
	switch {
	case choice != nil && choice.Off:
		return ""
	case choice != nil:
		if choice.Room != rs.RoomID && choice.Room != cfg.Name {
			return ""
		}
		byName = choice.Member
	case rs.UseExit != "":
		byID = rs.UseExit
	default:
		return ""
	}
	note, id := "", ""
	for _, m := range cfg.Members {
		if m.Name == byName || m.NodeID == byID {
			switch {
			case m.NodeID == n.ID.NodeID():
				note = "this node itself"
			case !m.Exit:
				note = m.Name + " is not an approved exit node of the room"
			default:
				id = m.NodeID
			}
		}
	}
	if id == "" && note == "" {
		note = "no member " + byName + byID + " in the room"
	}
	for key, o := range n.rooms {
		if id != "" && key != rs.RoomID && o.cfg.Exit {
			note, id = "room "+o.cfg.Name+" already carries the internet traffic", ""
		}
	}
	if note != "" && note != n.exitNote {
		n.log.Warn("not using the chosen exit node", "room", cfg.Name, "reason", note)
	}
	n.exitNote = note
	return id
}

// updateKillSwitchLocked keeps the kill switch on while an exit is wanted
// with it: chosen with "zpt exit -kill-switch", or picked by a room admin
// with kill_switch in the config. It stays on when that exit is gone or
// revoked — that is its point — until the choice is withdrawn.
func (n *Node) updateKillSwitchLocked(st *State) {
	on, lan := false, false
	switch c := st.Exit; {
	case c != nil && !c.Off:
		on, lan = c.KillSwitch, c.AllowLAN
	case c == nil && n.opts.Config.KillSwitch:
		for url, nm := range n.last {
			for _, rs := range nm.Rooms {
				if _, pinned := st.RoomKey(url, rs.RoomID); pinned && rs.Status == "active" && rs.UseExit != "" {
					on = true
				}
			}
		}
		lan = n.opts.Config.KillSwitchAllowLAN
	}
	if n.opts.Config.Userspace {
		on = false
	}
	var rooms []*room.Room
	var names []string
	var allowed []netip.Prefix
	if on {
		for _, r := range n.rooms {
			rooms = append(rooms, r.room)
			names = append(names, r.cfg.Name)
		}
		sort.Strings(names)
		if lan {
			allowed = n.lanPrefixesLocked()
		}
	}
	key := ""
	if on {
		key = fmt.Sprint(names, allowed)
	}
	if key == n.ksKey {
		return
	}
	if err := room.SetKillSwitch(on, rooms, allowed); err != nil {
		n.log.Error("kill switch", "err", err)
		return
	}
	if on && n.ksKey == "" {
		n.log.Info("kill switch on: the internet goes only through the exit", "allow_lan", lan)
	} else if !on {
		n.log.Info("kill switch off")
	}
	n.ksKey = key
}

// updateDNSLocked decides which DNS servers this machine uses and which
// room carries them. Servers picked on this device ("zpt dns", then dns in
// the config) come first. While the internet goes through an exit, that
// room carries DNS: the device's own servers, else the room's, else the
// exit's forwarder — so queries do not leak even with "zpt dns off".
// Otherwise the first room (by name) with its own servers carries them.
func (n *Node) updateDNSLocked(st *State) {
	own, off := n.opts.Config.DNS, false
	if c := st.DNS; c != nil {
		own, off = c.Servers, c.Off
	}
	keys := make([]string, 0, len(n.rooms))
	for k := range n.rooms {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return n.rooms[keys[i]].cfg.Name < n.rooms[keys[j]].cfg.Name })
	carrier := ""
	var servers []netip.Addr
	for _, k := range keys {
		if c := n.rooms[k].cfg; c.Exit {
			carrier = k
			switch {
			case len(own) > 0:
				servers = own
			case !off && len(c.RoomDNS) > 0:
				servers = c.RoomDNS
			case c.ExitDNS.IsValid():
				servers = []netip.Addr{c.ExitDNS}
			}
			if len(servers) == 0 && n.dnsNote != "old-exit" {
				n.log.Warn("the exit node does not answer DNS (older version): DNS queries go directly")
				n.dnsNote = "old-exit"
			}
		}
	}
	if carrier == "" {
		for _, k := range keys {
			if c := n.rooms[k].cfg; len(own) > 0 || !off && len(c.RoomDNS) > 0 {
				carrier, servers = k, own
				if len(own) == 0 {
					servers = c.RoomDNS
				}
				break
			}
		}
	}
	if len(own) > 0 && carrier == "" && n.dnsNote != "no-room" {
		n.log.Warn("own DNS servers need a running room to attach to", "dns", own)
		n.dnsNote = "no-room"
	}
	for k, r := range n.rooms {
		if k != carrier {
			r.room.SetDNS(nil)
		}
	}
	if carrier != "" {
		n.rooms[carrier].room.SetDNS(servers)
	}
}

// lanPrefixesLocked are the networks a kill switch with "allow LAN" keeps
// reachable: this machine's own networks (not rooms), broadcast, multicast
// and IPv6 link-local.
func (n *Node) lanPrefixesLocked() []netip.Prefix {
	out := []netip.Prefix{
		netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}
next:
	for _, p := range n.localPrefixes() {
		if p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() || p.Bits() == 0 {
			continue
		}
		for _, r := range n.rooms {
			if r.cfg.Address.Masked().Overlaps(p) {
				continue next
			}
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// routeConflictLocked explains why a member's network must not be routed
// here ("" if it may): it would shadow a network of this machine, this
// room, another room, or a network another room already routes.
func (n *Node) routeConflictLocked(r netip.Prefix, roomID string, subnet netip.Prefix) string {
	if r.Overlaps(subnet) {
		return "overlaps the room subnet"
	}
	for _, p := range n.localPrefixes() {
		if !p.Addr().IsLoopback() && p.Overlaps(r) {
			return "overlaps a local network (" + p.String() + ")"
		}
	}
	for key, o := range n.rooms {
		if key == roomID {
			continue
		}
		if o.cfg.Address.Masked().Overlaps(r) {
			return "overlaps room " + o.cfg.Name
		}
		for _, x := range o.cfg.Routes {
			if x.Overlaps(r) {
				return "already routed through room " + o.cfg.Name
			}
		}
	}
	return ""
}

// peerEndpoint prefers the path disco confirmed over the controller's guess.
func (n *Node) peerEndpoint(nodeID, guess string) string {
	if n.disco == nil {
		return guess
	}
	return n.disco.endpoint(nodeID, guess)
}

// chooseEndpoint picks how to reach a peer, best first: its LAN address
// when we are behind the same public IP and share a subnet; the port its
// router forwards; its address as seen by STUN; its public IP with the
// local port (right only when there is no port translation).
func chooseEndpoint(p api.Peer, myPublic netip.Addr, myPrefixes []netip.Prefix) string {
	if p.PublicIP.IsValid() && p.PublicIP == myPublic {
		for _, l := range p.Locals {
			for _, pfx := range myPrefixes {
				if pfx.Contains(l.Addr()) {
					return l.String()
				}
			}
		}
	}
	if p.PortMap.IsValid() {
		return p.PortMap.String()
	}
	if len(p.Reflexive) > 0 {
		return p.Reflexive[0].String()
	}
	if p.PublicIP.IsValid() && p.UDPPort != 0 {
		return netip.AddrPortFrom(p.PublicIP, p.UDPPort).String()
	}
	if len(p.Locals) > 0 {
		return p.Locals[0].String()
	}
	return ""
}

// ifnameLocked picks a short unique local name for a controller room.
func (n *Node) ifnameLocked(roomID, name string) string {
	taken := map[string]bool{}
	for _, r := range n.rooms {
		taken[r.cfg.Name] = true
	}
	candidates := []string{slug(name), "r" + roomID[:6]}
	for _, c := range candidates {
		if c != "" && !taken[c] {
			return c
		}
	}
	for i := 2; ; i++ {
		c := fmt.Sprintf("r%s%d", roomID[:4], i)
		if !taken[c] {
			return c
		}
	}
}

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e", 'ж': "zh", 'з': "z", 'и': "i", 'й': "y",
	'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f",
	'х': "h", 'ц': "c", 'ч': "ch", 'ш': "sh", 'щ': "sch", 'ы': "y", 'э': "e", 'ю': "yu", 'я': "ya",
}

// slug turns a room name into an interface-safe name (max 11 chars).
func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case translit[r] != "":
			b.WriteString(translit[r])
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	s := b.String()
	if len(s) > 11 {
		s = s[:11]
	}
	return strings.Trim(s, "-")
}

func (n *Node) localPrefixes() []netip.Prefix {
	var out []netip.Prefix
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if p, err := netip.ParsePrefix(ipn.String()); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

// discoverLocal lists this machine's usable addresses with the node port.
func discoverLocal(port uint16, exclude []netip.Prefix) []netip.AddrPort {
	var out []netip.AddrPort
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		skip := false
		for _, p := range exclude {
			if p.Contains(ip) {
				skip = true
			}
		}
		if !skip && len(out) < 8 {
			out = append(out, netip.AddrPortFrom(ip, port))
		}
	}
	return out
}

func (n *Node) discoPub() identity.Key {
	if n.disco == nil {
		return identity.Key{}
	}
	return n.disco.pub
}

// ensureRelay keeps a session with the first relay a controller offers.
// Only nodes that follow controllers use relays (they need the controller
// to know them).
func (n *Node) ensureRelay(relays []api.Relay) {
	if n.disco == nil {
		return
	}
	n.relayMu.Lock()
	defer n.relayMu.Unlock()
	if len(relays) == 0 {
		return // keep what we have: another controller may have offered it
	}
	want := relays[0]
	if n.relay != nil && n.relayAddr == want.Addr {
		return
	}
	addrs := netcheck.Resolve(n.ctx, []string{want.Addr})
	if len(addrs) == 0 {
		n.log.Warn("cannot resolve relay", "relay", want.Addr)
		return
	}
	if n.relayCancel != nil {
		n.relayCancel()
	}
	ctx, cancel := context.WithCancel(n.ctx)
	c := relay.NewClient(addrs[0], want.Key, n.disco.priv, n.disco.pub, n.relayWrite,
		func(src [relay.NodeIDLen]byte, payload []byte) { n.sock.Receive(payload, src) }, n.log)
	// Peers learn from the controller that we are reachable via the relay.
	c.OnReady = func() {
		n.notifyChanged()
		n.reapplyAll()
	}
	n.sock.SetRelay(addrs[0], c.Handle, c.Send)
	n.relay, n.relayAddr, n.relayCancel = c, want.Addr, cancel
	n.wg.Add(2)
	go func() {
		defer n.wg.Done()
		c.Run(ctx)
	}()
	go func() {
		defer n.wg.Done()
		n.relayTransport(ctx, c, want, addrs[0])
	}()
}

// relayReadyAddr is the relay address peers can reach us through.
func (n *Node) relayReadyAddr() string {
	n.relayMu.Lock()
	defer n.relayMu.Unlock()
	if n.relay != nil && n.relay.Ready() {
		return n.relayAddr
	}
	return ""
}

func (n *Node) pathStats() api.PathStats {
	if n.disco == nil {
		return api.PathStats{}
	}
	return n.disco.stats()
}
