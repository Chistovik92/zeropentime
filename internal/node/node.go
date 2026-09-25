// Package node is the zeropentime daemon: one shared socket, many rooms.
package node

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/magicsock"
	"github.com/Chistovik92/zeropentime/internal/room"
)

// Node is a running daemon.
type Node struct {
	ID    *identity.Identity
	sock  *magicsock.Conn
	rooms []*room.Room
}

// Start opens the shared socket and brings all configured rooms up.
func Start(cfg *config.Config, id *identity.Identity, log *slog.Logger) (_ *Node, err error) {
	sock, err := magicsock.Listen(cfg.Port(), log)
	if err != nil {
		return nil, err
	}
	n := &Node{ID: id, sock: sock}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	log.Info("node starting", "node_id", id.NodeID(), "udp_port", sock.Port(), "rooms", len(cfg.Rooms))

	for _, rc := range cfg.Rooms {
		prof := rc.Secret.Derive()
		bind, err := sock.Bind(prof.TagKey)
		if err != nil {
			return nil, fmt.Errorf("room %s: %w", rc.Name, err)
		}
		key, err := id.RoomKey(rc.Secret.RoomID())
		if err != nil {
			return nil, err
		}
		r, err := room.Up(room.Options{
			Config:    rc,
			Key:       key,
			Bind:      bind,
			Userspace: cfg.Userspace,
			Log:       log,
		})
		if err != nil {
			return nil, err
		}
		n.rooms = append(n.rooms, r)
	}
	return n, nil
}

// Port is the UDP port all rooms share.
func (n *Node) Port() uint16 { return n.sock.Port() }

// Rooms returns the running rooms.
func (n *Node) Rooms() []*room.Room { return n.rooms }

// Room returns a room by name.
func (n *Node) Room(name string) (*room.Room, error) {
	for _, r := range n.rooms {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no room %q", name)
}

// Close stops all rooms and the socket.
func (n *Node) Close() error {
	for _, r := range n.rooms {
		r.Close()
	}
	n.rooms = nil
	return errors.Join(n.sock.Close())
}
