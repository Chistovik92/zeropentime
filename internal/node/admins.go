// SPDX-License-Identifier: MPL-2.0

package node

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/acl"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

// Co-admins of rooms without a controller: an admin marks a member as
// admin in the signed config ("zpt room admin"), and that member's node
// then fetches the room signing key from another admin through the room
// (gossip port, "KEY ROOM_ID"). Inside the room the source address is
// bound to the member's key by the tunnel, so an admin gives the key only
// to addresses the signed config names as admins. With the key, a
// co-admin accepts members and changes the room like the owner.

// serveSignKey gives the room signing key to another admin.
func (n *Node) serveSignKey(roomID string, c net.Conn) {
	from, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	n.mu.Lock()
	ok := slices.Contains(n.admins[roomID], from.Addr().Unmap())
	n.mu.Unlock()
	if !ok {
		n.log.Warn("room signing key asked by a non-admin", "room_id", roomID, "from", from)
		return
	}
	st, err := LoadState(n.opts.StatePath)
	if err != nil {
		return
	}
	lr, err := st.LocalRoomByRef(roomID)
	if err != nil || len(lr.SignKey) != ed25519.SeedSize {
		return
	}
	n.log.Info("gave the room signing key to a co-admin", "room", lr.Name, "to", from.Addr())
	fmt.Fprintf(c, "%s\n", base64.StdEncoding.EncodeToString(lr.SignKey))
}

// ensureSignKey starts fetching the signing key if the signed config
// makes this node an admin and it has no key yet.
func (n *Node) ensureSignKey(lr *LocalRoom, cfg *pki.RoomConfig) {
	if len(lr.SignKey) > 0 {
		return
	}
	me := n.ID.NodeID()
	var admins []netip.Addr
	amAdmin := false
	for _, m := range cfg.Members {
		switch {
		case m.NodeID == me:
			amAdmin = m.Admin
		case m.Admin:
			admins = append(admins, m.IP)
		}
	}
	key := "key:" + lr.RoomID
	n.mu.Lock()
	if !amAdmin || len(admins) == 0 || n.joining[key] {
		n.mu.Unlock()
		return
	}
	n.joining[key] = true
	n.mu.Unlock()
	roomID, name, pinned := lr.RoomID, lr.Name, lr.RoomKey
	go func() {
		defer func() {
			n.mu.Lock()
			delete(n.joining, key)
			n.mu.Unlock()
		}()
		for i := 0; i < 120 && n.ctx.Err() == nil; i++ {
			for _, a := range admins {
				seed, err := n.fetchSignKey(roomID, a, pinned)
				if err != nil {
					n.log.Debug("room signing key", "from", a, "err", err)
					continue
				}
				if n.modifyLocal(roomID, func(lr *LocalRoom) error {
					lr.SignKey = seed
					return nil
				}) == nil {
					n.log.Info("this node is now an admin of the room", "room", name)
				}
				return
			}
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

func (n *Node) fetchSignKey(roomID string, admin netip.Addr, pinned string) ([]byte, error) {
	n.mu.Lock()
	r, ok := n.rooms[roomID]
	n.mu.Unlock()
	if !ok {
		return nil, errors.New("room is not running")
	}
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	c, err := r.room.DialTCP(ctx, netip.AddrPortFrom(admin, acl.GossipPort))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(c, "KEY %s\n", roomID); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad key")
	}
	if pki.RoomKeyString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) != pinned {
		return nil, errors.New("the key does not match the room")
	}
	return seed, nil
}
