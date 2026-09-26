// SPDX-License-Identifier: MPL-2.0

package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/disco"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

// joinRequest asks the owner of a local room to accept this node.
type joinRequest struct {
	RoomID    string           `json:"r"`
	Token     string           `json:"t"`
	Name      string           `json:"n"`
	EdKey     string           `json:"k"` // node identity (base64)
	WGKey     identity.Key     `json:"w"` // node's public key in the room
	Endpoints []netip.AddrPort `json:"e,omitempty"`
	Sig       string           `json:"s"` // identity signature over signedPart
}

func (r *joinRequest) signedPart() []byte {
	return []byte(fmt.Sprintf("zpt-join-v1|%s|%s|%s|%s", r.RoomID, r.Token, r.Name, r.WGKey))
}

type joinReply struct {
	RoomID string     `json:"r"`
	OK     bool       `json:"ok"`
	IP     netip.Addr `json:"ip,omitzero"`
	Error  string     `json:"err,omitempty"`
}

// localState serialises the daemon's changes of local rooms in the state file.
var localStateMu sync.Mutex

// modifyLocal runs fn on the local room in the state file and saves it.
func (n *Node) modifyLocal(roomID string, fn func(*LocalRoom) error) error {
	localStateMu.Lock()
	defer localStateMu.Unlock()
	st, err := LoadState(n.opts.StatePath)
	if err != nil {
		return err
	}
	for i := range st.Local {
		if st.Local[i].RoomID == roomID {
			if err := fn(&st.Local[i]); err != nil {
				return err
			}
			return st.Save(n.opts.StatePath)
		}
	}
	return fmt.Errorf("no local room %s", roomID)
}

// syncLocal brings the local rooms in line with the state file.
func (n *Node) syncLocal(st *State) {
	want := map[string]bool{}
	for i := range st.Local {
		lr := &st.Local[i]
		url := localPrefix + lr.RoomID
		want[url] = true
		switch {
		case lr.Config != nil:
			nm := localNetmap(lr)
			key := fmt.Sprintf("%x %v", lr.Config.Sig, nm.Peers)
			n.mu.Lock()
			same := n.localApplied[url] == key
			n.localApplied[url] = key
			n.mu.Unlock()
			if !same {
				n.apply(url, nm)
			}
		case lr.Join != nil && lr.Join.IP.IsValid():
			n.startProvisional(lr)
		case lr.Join != nil:
			n.ensureJoining(lr)
		}
	}
	n.mu.Lock()
	var gone []string
	for url := range n.localApplied {
		if !want[url] {
			gone = append(gone, url)
			delete(n.localApplied, url)
		}
	}
	n.mu.Unlock()
	for _, url := range gone {
		n.apply(url, &api.NetMap{})
	}
}

func localNetmap(lr *LocalRoom) *api.NetMap {
	nm := &api.NetMap{Rooms: []api.RoomState{{RoomID: lr.RoomID, Status: "active", Config: lr.Config}}, Peers: map[string]api.Peer{}}
	for id, p := range lr.Peers {
		p.Online = true
		nm.Peers[id] = p
	}
	return nm
}

// ---- joining (the new member's side) ----

func (n *Node) ensureJoining(lr *LocalRoom) {
	n.mu.Lock()
	if n.joining[lr.RoomID] {
		n.mu.Unlock()
		return
	}
	n.joining[lr.RoomID] = true
	n.mu.Unlock()
	link, name := lr.Join.Invite, lr.Join.Name
	go func() {
		defer func() {
			n.mu.Lock()
			delete(n.joining, link.RoomID)
			n.mu.Unlock()
		}()
		n.log.Info("asking the room owner to accept us", "room", lr.Name, "owner", link.Owner, "endpoints", link.Endpoints)
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			if n.ctx.Err() != nil {
				return
			}
			st, err := LoadState(n.opts.StatePath)
			if err != nil {
				return
			}
			lr, err := st.LocalRoomByRef(link.RoomID)
			if err != nil || lr.Join == nil || lr.Join.IP.IsValid() || lr.Config != nil {
				return
			}
			n.sendJoin(link, name)
			select {
			case <-n.ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (n *Node) sendJoin(link LocalLink, name string) {
	if n.disco == nil {
		return
	}
	wg, err := n.ID.RoomKey(link.RoomID)
	if err != nil {
		return
	}
	req := joinRequest{RoomID: link.RoomID, Token: link.Token, Name: name, WGKey: wg.Public(),
		EdKey:     base64.StdEncoding.EncodeToString(n.ID.PublicKey()),
		Endpoints: n.opts.LocalEndpoints(n.sock.Port(), nil)}
	req.Sig = base64.StdEncoding.EncodeToString(n.ID.Sign(req.signedPart()))
	data, err := json.Marshal(req)
	if err != nil || len(data) > disco.MaxData {
		n.log.Warn("join request too large", "size", len(data))
		return
	}
	pkt, err := disco.Seal(disco.Msg{Type: disco.TypeJoin, Tx: disco.NewTxID(), Data: data}, n.disco.priv, n.disco.pub, link.OwnerDisco)
	if err != nil {
		return
	}
	for _, e := range link.Endpoints {
		n.sock.WriteTo(pkt, e)
	}
}

func (n *Node) handleJoinReply(sender identity.Key, data []byte) {
	var rep joinReply
	if json.Unmarshal(data, &rep) != nil {
		return
	}
	err := n.modifyLocal(rep.RoomID, func(lr *LocalRoom) error {
		if lr.Join == nil || lr.Join.Invite.OwnerDisco != sender || lr.Join.IP.IsValid() {
			return errors.New("unexpected reply")
		}
		if !rep.OK {
			n.log.Warn("the room owner refused us", "room", lr.Name, "reason", rep.Error)
			lr.Join = nil // the invite is no good: stop asking
			return nil
		}
		if !lr.Join.Invite.Subnet.Contains(rep.IP) {
			return errors.New("bad address")
		}
		lr.Join.IP = rep.IP
		n.log.Info("the room owner accepted us", "room", lr.Name, "ip", rep.IP)
		return nil
	})
	if err == nil {
		n.Reload()
	}
}

// startProvisional brings up an accepted room with the owner as the only
// peer, then fetches the signed config from the owner through the room.
func (n *Node) startProvisional(lr *LocalRoom) {
	url, link := localPrefix+lr.RoomID, lr.Join.Invite
	n.mu.Lock()
	if _, ok := n.rooms[lr.RoomID]; ok {
		n.mu.Unlock()
		return
	}
	rc := config.Room{
		Name: n.ifnameLocked(lr.RoomID, lr.Name), Secret: link.Secret, MTU: config.DefaultMTU,
		Address: netip.PrefixFrom(lr.Join.IP, link.Subnet.Bits()),
		Peers: []config.Peer{{Name: "owner", PublicKey: link.OwnerWG, Endpoint: link.Endpoints[0].String(),
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(link.OwnerIP, 32)}, Keepalive: PeerKeepalive}},
	}
	owner := api.Peer{DiscoKey: link.OwnerDisco, Locals: link.Endpoints, Online: true}
	n.last[url] = &api.NetMap{Rooms: []api.RoomState{{RoomID: lr.RoomID, Status: "active"}}, Peers: map[string]api.Peer{link.Owner: owner}}
	err := n.startLocked(lr.RoomID, url, rc)
	r := n.rooms[lr.RoomID]
	n.mu.Unlock()
	if err != nil {
		n.log.Error("cannot start the room", "room", lr.Name, "err", err)
		return
	}
	if n.disco != nil {
		n.disco.setPeers(url, map[string]api.Peer{link.Owner: owner}, map[string]bool{link.Owner: true})
	}
	go func() {
		for i := 0; i < 60 && n.ctx.Err() == nil; i++ {
			n.mu.Lock()
			have := n.signed[lr.RoomID] != nil
			n.mu.Unlock()
			if have {
				return
			}
			ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
			err := n.gossipFetch(ctx, lr.RoomID, r.room, link.OwnerIP)
			cancel()
			if err == nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
}

// persistLocal records a newer signed config of a local room (from gossip)
// in the state file, and finishes a join.
func (n *Node) persistLocal(roomID string, s *pki.Signed) {
	n.modifyLocal(roomID, func(lr *LocalRoom) error {
		pub, err := pki.ParseRoomKey(lr.RoomKey)
		if err != nil {
			return err
		}
		cfg, err := pki.VerifyRoomConfig(pub, s)
		if err != nil {
			return err
		}
		if lr.Config != nil {
			if old, err := pki.VerifyRoomConfig(pub, lr.Config); err == nil && old.Version >= cfg.Version {
				return errors.New("not newer")
			}
		}
		lr.Config = s
		if j := lr.Join; j != nil {
			if lr.Peers == nil {
				lr.Peers = map[string]api.Peer{}
			}
			lr.Peers[j.Invite.Owner] = api.Peer{DiscoKey: j.Invite.OwnerDisco, Locals: j.Invite.Endpoints}
			lr.Join = nil
		}
		return nil
	})
}

// ---- accepting (an admin's side) ----

var joinLimiter = struct {
	sync.Mutex
	at  time.Time
	cnt int
}{}

func (n *Node) handleJoin(sender identity.Key, data []byte, from netip.AddrPort) {
	joinLimiter.Lock()
	if time.Since(joinLimiter.at) > time.Second {
		joinLimiter.at, joinLimiter.cnt = time.Now(), 0
	}
	joinLimiter.cnt++
	over := joinLimiter.cnt > 20
	joinLimiter.Unlock()
	if over {
		return
	}
	var req joinRequest
	if json.Unmarshal(data, &req) != nil {
		return
	}
	ed, err := base64.StdEncoding.DecodeString(req.EdKey)
	sig, err2 := base64.StdEncoding.DecodeString(req.Sig)
	if err != nil || err2 != nil || len(ed) != ed25519.PublicKeySize || !ed25519.Verify(ed, req.signedPart(), sig) {
		return
	}
	nodeID := identity.NodeIDFromPublic(ed)
	rep := joinReply{RoomID: req.RoomID}
	var name string
	err = n.modifyLocal(req.RoomID, func(lr *LocalRoom) error {
		if len(lr.SignKey) == 0 {
			return errors.New("not an admin")
		}
		name = lr.Name
		cfg, err := lr.config()
		if err != nil {
			return err
		}
		for _, m := range cfg.Members {
			if m.NodeID == nodeID { // asked again: the same answer
				rep.OK, rep.IP = true, m.IP
				return nil
			}
		}
		if !lr.useInvite(req.Token) {
			rep.Error = "приглашение недействительно: истекло или израсходовано"
			return nil
		}
		memberName := req.Name
		if memberName == "" || len(memberName) > 40 {
			memberName = nodeID[:8]
		}
		if err := lr.Update(func(c *pki.RoomConfig) error {
			ip, err := addMember(c, pki.Member{NodeID: nodeID, Name: memberName, WGKey: req.WGKey})
			rep.IP = ip
			return err
		}); err != nil {
			rep.Error = err.Error()
			return nil
		}
		if lr.Peers == nil {
			lr.Peers = map[string]api.Peer{}
		}
		p := api.Peer{DiscoKey: sender, Reflexive: []netip.AddrPort{from}}
		for _, e := range req.Endpoints {
			if len(p.Locals) < 8 {
				p.Locals = append(p.Locals, e)
			}
		}
		lr.Peers[nodeID] = p
		rep.OK = true
		return nil
	})
	if err != nil && rep.Error == "" && !rep.OK {
		return // not our room: stay silent
	}
	if rep.OK {
		n.log.Info("accepted a new member", "room", name, "member", req.Name, "ip", rep.IP)
		n.Reload()
	}
	out, _ := json.Marshal(rep)
	if pkt, err := disco.Seal(disco.Msg{Type: disco.TypeJoinReply, Tx: disco.NewTxID(), Data: out}, n.disco.priv, n.disco.pub, sender); err == nil {
		n.sock.WriteTo(pkt, from)
	}
}
