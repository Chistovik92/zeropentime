// SPDX-License-Identifier: MPL-2.0

package node

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/acl"
	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/room"
)

// Peer cards: members tell each other through gossip how to reach them,
// so that paths are found without a controller (in rooms without one,
// and when the controller is down and addresses change). A card is
// signed by the node's own identity key and names the node, its disco
// key and its addresses; it is accepted only for members of the signed
// room config. Addresses are still only hints: disco pings them, and
// only the holder of the disco key answers.

const (
	cardsEvery   = 60 * time.Second
	cardTTL      = 2 * time.Hour
	maxCardAddrs = 12
	maxCards     = 256
)

type peerCard struct {
	RoomID    string           `json:"r"`
	NodeID    string           `json:"id"`
	EdKey     string           `json:"k"` // node identity (base64)
	Disco     identity.Key     `json:"d"`
	Endpoints []netip.AddrPort `json:"e"`
	Issued    int64            `json:"t"` // unix seconds
	Sig       string           `json:"s"`
}

func (c *peerCard) signedPart() []byte {
	var eps []string
	for _, e := range c.Endpoints {
		eps = append(eps, e.String())
	}
	return fmt.Appendf(nil, "zpt-card-v1\n%s\n%s\n%s\n%s\n%d", c.RoomID, c.NodeID, c.Disco, strings.Join(eps, ","), c.Issued)
}

func (c *peerCard) verify(roomID string, now time.Time) error {
	if c.RoomID != roomID {
		return errors.New("card for another room")
	}
	pub, err := base64.StdEncoding.DecodeString(c.EdKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || identity.NodeIDFromPublic(pub) != c.NodeID {
		return errors.New("card: key does not match the node")
	}
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil || !ed25519.Verify(pub, c.signedPart(), sig) {
		return errors.New("card: bad signature")
	}
	t := time.Unix(c.Issued, 0)
	if t.After(now.Add(5*time.Minute)) || now.Sub(t) > cardTTL {
		return errors.New("card: too old or from the future")
	}
	if c.Disco.IsZero() || len(c.Endpoints) == 0 || len(c.Endpoints) > maxCardAddrs {
		return errors.New("card: no addresses")
	}
	return nil
}

// ownAddrs are all addresses this node may be reached at, stable order.
func (n *Node) ownAddrs() []netip.AddrPort {
	n.mu.Lock()
	var exclude []netip.Prefix
	for _, r := range n.rooms {
		exclude = append(exclude, r.cfg.Address.Masked())
	}
	var out []netip.AddrPort
	if n.portMap.IsValid() {
		out = append(out, n.portMap)
	}
	urls := make([]string, 0, len(n.reports))
	for u := range n.reports {
		urls = append(urls, u)
	}
	slices.Sort(urls)
	for _, u := range urls {
		out = append(out, n.reports[u].Mapped...)
	}
	n.mu.Unlock()
	out = append(out, n.opts.LocalEndpoints(n.sock.Port(), exclude)...)
	var uniq []netip.AddrPort
	for _, a := range out {
		if a.IsValid() && a.Port() != 0 && !slices.Contains(uniq, a) && len(uniq) < maxCardAddrs {
			uniq = append(uniq, a)
		}
	}
	return uniq
}

func (n *Node) myCard(roomID string) *peerCard {
	if n.disco == nil {
		return nil
	}
	eps := n.ownAddrs()
	if len(eps) == 0 {
		return nil
	}
	c := &peerCard{RoomID: roomID, NodeID: n.ID.NodeID(), EdKey: base64.StdEncoding.EncodeToString(n.ID.PublicKey()),
		Disco: n.discoPub(), Endpoints: eps, Issued: time.Now().Unix()}
	c.Sig = base64.StdEncoding.EncodeToString(n.ID.Sign(c.signedPart()))
	return c
}

// cardsFor are the cards to give a peer: ours and the fresh ones we know.
func (n *Node) cardsFor(roomID string) []*peerCard {
	var out []*peerCard
	if c := n.myCard(roomID); c != nil {
		out = append(out, c)
	}
	now := time.Now()
	n.mu.Lock()
	for _, c := range n.cards[roomID] {
		if now.Sub(time.Unix(c.Issued, 0)) < cardTTL && n.members[roomID][c.NodeID] {
			out = append(out, c)
		}
	}
	n.mu.Unlock()
	return out
}

// mergeCards keeps the newest valid card of every other member and gives
// their addresses to disco.
func (n *Node) mergeCards(roomID string, cards []*peerCard) {
	now, me := time.Now(), n.ID.NodeID()
	var fresh []*peerCard
	n.mu.Lock()
	if n.cards[roomID] == nil {
		n.cards[roomID] = map[string]*peerCard{}
	}
	for _, c := range cards {
		if c == nil || c.NodeID == me || !n.members[roomID][c.NodeID] || c.verify(roomID, now) != nil {
			continue
		}
		if old, ok := n.cards[roomID][c.NodeID]; ok && old.Issued >= c.Issued {
			continue
		}
		if len(n.cards[roomID]) >= maxCards {
			continue
		}
		n.cards[roomID][c.NodeID] = c
		fresh = append(fresh, c)
	}
	var url string
	if r, ok := n.rooms[roomID]; ok {
		url = r.controller
	}
	n.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	if n.disco != nil {
		for _, c := range fresh {
			n.disco.addGossipHints(c.NodeID, c.Endpoints)
		}
	}
	if strings.HasPrefix(url, localPrefix) {
		n.learnLocalPeers(roomID, fresh)
	}
}

// learnLocalPeers records how to reach members of a local room (the
// owner told a new member only about itself).
func (n *Node) learnLocalPeers(roomID string, cards []*peerCard) {
	changed := false
	n.modifyLocal(roomID, func(lr *LocalRoom) error {
		if lr.Peers == nil {
			lr.Peers = map[string]api.Peer{}
		}
		for _, c := range cards {
			old, ok := lr.Peers[c.NodeID]
			if ok && old.DiscoKey == c.Disco && slices.Equal(old.Locals, c.Endpoints) {
				continue
			}
			lr.Peers[c.NodeID] = api.Peer{DiscoKey: c.Disco, Locals: c.Endpoints}
			changed = true
		}
		if !changed {
			return errors.New("nothing new")
		}
		return nil
	})
	if changed {
		n.Reload()
	}
}

// gossipCards swaps cards with a couple of peers every cardsEvery.
func (n *Node) gossipCards(ctx context.Context, roomID string, r *room.Room) {
	t := time.NewTimer(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		peers := n.peerAddrs(roomID)
		rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
		for _, p := range peers[:min(2, len(peers))] {
			if err := n.swapCards(ctx, roomID, r, p); err != nil {
				n.log.Debug("gossip: cards", "peer", p, "err", err)
			}
		}
		next := cardsEvery
		if len(peers) == 0 {
			next = 10 * time.Second
		}
		t.Reset(next)
	}
}

func (n *Node) swapCards(ctx context.Context, roomID string, r *room.Room, peer netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.DialTCP(ctx, netip.AddrPortFrom(peer, acl.GossipPort))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	req, _ := json.Marshal(n.cardsFor(roomID))
	if _, err := fmt.Fprintf(c, "CARDS %s\n%s\n", roomID, req); err != nil {
		return err
	}
	var got []*peerCard
	if err := json.NewDecoder(io.LimitReader(c, gossipMaxSize)).Decode(&got); err != nil {
		return err
	}
	n.mergeCards(roomID, got)
	return nil
}

// serveCards answers a "CARDS" request: takes the peer's cards, gives ours.
func (n *Node) serveCards(roomID string, rd *bufio.Reader, w io.Writer) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	var got []*peerCard
	if json.Unmarshal([]byte(line), &got) != nil {
		return
	}
	out := n.cardsFor(roomID)
	n.mergeCards(roomID, got)
	json.NewEncoder(w).Encode(out)
}
