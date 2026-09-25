// SPDX-License-Identifier: AGPL-3.0-only

// Package controller manages rooms, members and invites, signs room configs
// and serves the node API and the admin panel.
package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
	"github.com/Chistovik92/zeropentime/internal/pki"
	"github.com/Chistovik92/zeropentime/internal/store"
)

// OnlineWindow: a node that polled within this time is shown as online.
const OnlineWindow = 90 * time.Second

// Default pool for auto-assigned room subnets.
var subnetPool = netip.MustParsePrefix("10.128.0.0/9")

// Errors mapped to HTTP statuses by the handlers.
var (
	ErrForbidden = errors.New("forbidden")
	ErrInvalid   = errors.New("invalid request")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Service is the controller business logic.
type Service struct {
	st  *store.Store
	hub *hub
	log *slog.Logger
	now func() time.Time
}

// NewService creates the service on an open store.
func NewService(st *store.Store, log *slog.Logger) (*Service, error) {
	var v int64
	if err := st.Read(context.Background(), func(tx *store.Tx) (err error) { v, err = tx.Version(); return }); err != nil {
		return nil, err
	}
	return &Service{st: st, hub: newHub(v), log: log, now: time.Now}, nil
}

// change runs fn in a transaction, bumps the global version and wakes pollers.
func (s *Service) change(ctx context.Context, fn func(*store.Tx) error) error {
	var v int64
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		var err error
		v, err = tx.BumpVersion()
		return err
	})
	if err == nil {
		s.hub.set(v)
	}
	return err
}

func canManage(u *store.User, r *store.Room) bool { return u.IsAdmin || r.OwnerID == u.ID }

func (s *Service) roomFor(tx *store.Tx, u *store.User, roomID string) (*store.Room, error) {
	r, err := tx.RoomByID(roomID)
	if err != nil {
		return nil, err
	}
	if !canManage(u, r) {
		return nil, ErrForbidden
	}
	return r, nil
}

// ---- rooms ----

// ValidateRoomName checks a human-readable room name.
func ValidateRoomName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 40 {
		return "", invalid("название комнаты: от 1 до 40 символов")
	}
	return name, nil
}

func validPolicy(p string) bool { return p == "manual" || p == "auto" }

// CreateRoom creates a room. subnet may be empty for automatic choice.
func (s *Service) CreateRoom(ctx context.Context, u *store.User, name, subnet, policy string) (*store.Room, error) {
	name, err := ValidateRoomName(name)
	if err != nil {
		return nil, err
	}
	if !validPolicy(policy) {
		return nil, invalid("режим вступления: manual или auto")
	}
	secret, err := obfs.NewSecret()
	if err != nil {
		return nil, err
	}
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	r := &store.Room{ID: secret.RoomID(), Name: name, Secret: secret[:], SignKey: signKey, OwnerID: u.ID, JoinPolicy: policy}
	err = s.change(ctx, func(tx *store.Tx) error {
		used, err := tx.AllSubnets()
		if err != nil {
			return err
		}
		if subnet = strings.TrimSpace(subnet); subnet != "" {
			p, err := netip.ParsePrefix(subnet)
			if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 16 || p.Bits() > 29 {
				return invalid("подсеть должна быть частной IPv4-сетью от /16 до /29, например 10.100.1.0/24")
			}
			for _, u := range used {
				if u.Overlaps(p) {
					return invalid("подсеть %s пересекается с подсетью другой комнаты %s", p.Masked(), u)
				}
			}
			r.Subnet = p.Masked()
		} else if r.Subnet, err = pickSubnet(used); err != nil {
			return err
		}
		if err := tx.CreateRoom(r); err != nil {
			return err
		}
		return tx.Audit(u.Login, "room.create", r.ID, fmt.Sprintf("%s %s", name, r.Subnet))
	})
	return r, err
}

func pickSubnet(used []netip.Prefix) (netip.Prefix, error) {
	base := subnetPool.Addr().As4()
	blocks := int64(1) << (24 - subnetPool.Bits())
	for range 200 {
		n, err := rand.Int(rand.Reader, big.NewInt(blocks))
		if err != nil {
			return netip.Prefix{}, err
		}
		i := n.Int64()
		a := [4]byte{base[0], base[1] + byte(i>>8), byte(i), 0}
		p := netip.PrefixFrom(netip.AddrFrom4(a), 24)
		free := true
		for _, u := range used {
			if u.Overlaps(p) {
				free = false
				break
			}
		}
		if free {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("no free subnet in pool")
}

func (s *Service) UpdateRoom(ctx context.Context, u *store.User, roomID, name, policy string) error {
	name, err := ValidateRoomName(name)
	if err != nil {
		return err
	}
	if !validPolicy(policy) {
		return invalid("режим вступления: manual или auto")
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if _, err := s.roomFor(tx, u, roomID); err != nil {
			return err
		}
		if err := tx.UpdateRoom(roomID, name, policy); err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "room.update", roomID, name+" "+policy)
	})
}

func (s *Service) DeleteRoom(ctx context.Context, u *store.User, roomID string) error {
	return s.change(ctx, func(tx *store.Tx) error {
		r, err := s.roomFor(tx, u, roomID)
		if err != nil {
			return err
		}
		if err := tx.DeleteRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "room.delete", roomID, r.Name)
	})
}

// RoomView is a room with its members and invites, for the panel.
type RoomView struct {
	Room    store.Room
	RoomKey string
	Members []store.Member
	Invites []store.Invite
}

func (s *Service) Rooms(ctx context.Context, u *store.User) (rooms []store.Room, err error) {
	owner := u.ID
	if u.IsAdmin {
		owner = 0
	}
	err = s.st.Read(ctx, func(tx *store.Tx) error { rooms, err = tx.ListRooms(owner); return err })
	return
}

func (s *Service) Room(ctx context.Context, u *store.User, roomID string) (*RoomView, error) {
	var v RoomView
	err := s.st.Read(ctx, func(tx *store.Tx) error {
		r, err := s.roomFor(tx, u, roomID)
		if err != nil {
			return err
		}
		v.Room = *r
		v.RoomKey = pki.RoomKeyString(ed25519.PrivateKey(r.SignKey).Public().(ed25519.PublicKey))
		if v.Members, err = tx.ListMembers(roomID); err != nil {
			return err
		}
		v.Invites, err = tx.ListInvites(roomID)
		return err
	})
	return &v, err
}

// ---- invites ----

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

// CreateInvite returns a new invite link. uses <= 0 means unlimited.
func (s *Service) CreateInvite(ctx context.Context, u *store.User, controllerURL, roomID string, uses int, ttl time.Duration, autoApprove bool, note string) (api.Invite, error) {
	if ttl <= 0 || ttl > 365*24*time.Hour {
		return api.Invite{}, invalid("срок действия приглашения: до года")
	}
	if uses <= 0 {
		uses = -1
	}
	if utf8.RuneCountInString(note) > 100 {
		return api.Invite{}, invalid("заметка слишком длинная")
	}
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return api.Invite{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	var inv api.Invite
	err := s.change(ctx, func(tx *store.Tx) error {
		r, err := s.roomFor(tx, u, roomID)
		if err != nil {
			return err
		}
		if _, err := tx.CreateInvite(&store.Invite{
			RoomID: roomID, TokenHash: hashToken(token), UsesLeft: uses, Expires: s.now().Add(ttl),
			AutoApprove: autoApprove, Note: strings.TrimSpace(note), CreatedBy: u.ID,
		}); err != nil {
			return err
		}
		inv = api.Invite{
			Controller: strings.TrimRight(controllerURL, "/"),
			RoomID:     roomID,
			RoomKey:    pki.RoomKeyString(ed25519.PrivateKey(r.SignKey).Public().(ed25519.PublicKey)),
			Token:      token,
		}
		return tx.Audit(u.Login, "invite.create", roomID, fmt.Sprintf("uses=%d ttl=%s auto=%v %s", uses, ttl, autoApprove, note))
	})
	return inv, err
}

func (s *Service) RevokeInvite(ctx context.Context, u *store.User, roomID string, id int64) error {
	return s.change(ctx, func(tx *store.Tx) error {
		if _, err := s.roomFor(tx, u, roomID); err != nil {
			return err
		}
		if err := tx.RevokeInvite(roomID, id); err != nil {
			return err
		}
		return tx.Audit(u.Login, "invite.revoke", roomID, fmt.Sprint(id))
	})
}

// ---- members (admin actions) ----

// MemberAction is an admin operation on a member.
type MemberAction string

const (
	ActApprove MemberAction = "approve"
	ActBan     MemberAction = "ban"
	ActUnban   MemberAction = "unban"
	ActKick    MemberAction = "kick"
)

func (s *Service) MemberAction(ctx context.Context, u *store.User, roomID, nodeID string, act MemberAction) error {
	return s.change(ctx, func(tx *store.Tx) error {
		if _, err := s.roomFor(tx, u, roomID); err != nil {
			return err
		}
		m, err := tx.Member(roomID, nodeID)
		if err != nil {
			return err
		}
		switch act {
		case ActApprove, ActUnban:
			m.Status = store.StatusActive
			err = tx.UpdateMember(m)
		case ActBan:
			m.Status = store.StatusBanned
			err = tx.UpdateMember(m)
		case ActKick:
			err = tx.DeleteMember(roomID, nodeID)
		default:
			return invalid("неизвестное действие %q", act)
		}
		if err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "member."+string(act), roomID, nodeID+" "+m.Name)
	})
}

// UpdateMember changes a member's name, IP and tags.
func (s *Service) UpdateMember(ctx context.Context, u *store.User, roomID, nodeID, name, ip, tags string) error {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 40 {
		return invalid("имя участника: от 1 до 40 символов")
	}
	var tagList []string
	for _, t := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ' ' }) {
		if len(t) > 32 {
			return invalid("тег %q слишком длинный", t)
		}
		tagList = append(tagList, strings.ToLower(t))
	}
	return s.change(ctx, func(tx *store.Tx) error {
		r, err := s.roomFor(tx, u, roomID)
		if err != nil {
			return err
		}
		m, err := tx.Member(roomID, nodeID)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || !usableHost(r.Subnet, addr) {
			return invalid("IP должен быть адресом узла внутри %s", r.Subnet)
		}
		if addr != m.IP {
			members, err := tx.ListMembers(roomID)
			if err != nil {
				return err
			}
			for _, o := range members {
				if o.IP == addr {
					return invalid("IP %s уже занят участником %s", addr, o.Name)
				}
			}
		}
		m.Name, m.IP, m.Tags = name, addr, tagList
		if err := tx.UpdateMember(m); err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "member.update", roomID, fmt.Sprintf("%s name=%s ip=%s tags=%v", nodeID, name, addr, tagList))
	})
}

func usableHost(p netip.Prefix, a netip.Addr) bool {
	if !p.Contains(a) || a == p.Masked().Addr() {
		return false
	}
	return a != lastAddr(p)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func allocateIP(p netip.Prefix, members []store.Member) (netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, m := range members {
		used[m.IP] = true
	}
	for a := p.Masked().Addr().Next(); p.Contains(a); a = a.Next() {
		if usableHost(p, a) && !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, invalid("в подсети комнаты %s закончились адреса", p)
}

// ---- node API ----

func cleanName(name, fallback string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return fallback
	}
	if r := []rune(name); len(r) > 40 {
		name = string(r[:40])
	}
	return name
}

func cleanLocals(e api.Endpoints) []netip.AddrPort {
	var out []netip.AddrPort
	for _, a := range e.Locals {
		if a.IsValid() && len(out) < 16 {
			out = append(out, a)
		}
	}
	return out
}

// Join handles a node joining a room with an invite token.
func (s *Service) Join(ctx context.Context, nodeKey ed25519.PublicKey, req *api.JoinRequest, remote netip.Addr) (*api.JoinResponse, error) {
	nodeID := identity.NodeIDFromPublic(nodeKey)
	if req.WGKey.IsZero() || req.BoxKey.IsZero() {
		return nil, invalid("нужны wg_key и box_key")
	}
	resp := &api.JoinResponse{}
	err := s.change(ctx, func(tx *store.Tx) error {
		r, err := tx.RoomByID(req.RoomID)
		if err != nil {
			return ErrForbidden // do not reveal which rooms exist
		}
		resp.RoomName = r.Name
		if err := tx.UpsertNode(&store.Node{
			ID: nodeID, EdKey: nodeKey, BoxKey: req.BoxKey[:], Name: cleanName(req.Name, nodeID),
			PublicIP: remote, UDPPort: req.Endpoints.UDPPort, Locals: cleanLocals(req.Endpoints), Version: req.ClientVersion,
		}); err != nil {
			return err
		}
		if _, err := tx.UpdateNodeEndpoints(nodeID, remote, req.Endpoints.UDPPort, cleanLocals(req.Endpoints), req.ClientVersion); err != nil {
			return err
		}
		if m, err := tx.Member(r.ID, nodeID); err == nil {
			if m.Status == store.StatusBanned {
				return ErrForbidden
			}
			resp.Status = m.Status
			return nil // already a member: do not spend the invite
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		inv, err := tx.UseInvite(r.ID, hashToken(req.Token))
		if err != nil {
			return ErrForbidden
		}
		members, err := tx.ListMembers(r.ID)
		if err != nil {
			return err
		}
		ip, err := allocateIP(r.Subnet, members)
		if err != nil {
			return err
		}
		resp.Status = store.StatusPending
		if inv.AutoApprove || r.JoinPolicy == "auto" {
			resp.Status = store.StatusActive
		}
		if err := tx.AddMember(&store.Member{
			RoomID: r.ID, NodeID: nodeID, Name: cleanName(req.Name, nodeID), WGKey: req.WGKey[:], IP: ip, Status: resp.Status,
		}); err != nil {
			return err
		}
		if err := tx.BumpRoom(r.ID); err != nil {
			return err
		}
		return tx.Audit("node:"+nodeID, "member.join", r.ID, fmt.Sprintf("%s ip=%s status=%s invite=%d", req.Name, ip, resp.Status, inv.ID))
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("node joined", "node", nodeID, "room", req.RoomID, "status", resp.Status)
	return resp, nil
}

// Leave removes the calling node from a room.
func (s *Service) Leave(ctx context.Context, nodeKey ed25519.PublicKey, roomID string) error {
	nodeID := identity.NodeIDFromPublic(nodeKey)
	return s.change(ctx, func(tx *store.Tx) error {
		m, err := tx.Member(roomID, nodeID)
		if err != nil {
			return err
		}
		if m.Status == store.StatusBanned {
			return nil // a ban stays even if the node leaves
		}
		if err := tx.DeleteMember(roomID, nodeID); err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit("node:"+nodeID, "member.leave", roomID, m.Name)
	})
}

// Poll records the node's endpoints, waits for changes newer than
// req.Since (up to the context deadline) and returns the node's netmap.
func (s *Service) Poll(ctx context.Context, nodeKey ed25519.PublicKey, req *api.PollRequest, remote netip.Addr) (*api.NetMap, identity.Key, error) {
	nodeID := identity.NodeIDFromPublic(nodeKey)
	var boxKey identity.Key
	var changed bool
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		n, err := tx.NodeByID(nodeID)
		if err != nil {
			return ErrForbidden // unknown node: must join first
		}
		copy(boxKey[:], n.BoxKey)
		changed, err = tx.UpdateNodeEndpoints(nodeID, remote, req.Endpoints.UDPPort, cleanLocals(req.Endpoints), req.ClientVersion)
		return err
	})
	if err != nil {
		return nil, boxKey, err
	}
	if changed {
		// Peers need the new address: bump the version for everybody.
		if err := s.change(ctx, func(*store.Tx) error { return nil }); err != nil {
			return nil, boxKey, err
		}
	} else {
		s.hub.wait(ctx, req.Since)
	}
	nm, err := s.netMap(context.WithoutCancel(ctx), nodeID)
	if nm != nil {
		nm.ObservedIP = remote
	}
	return nm, boxKey, err
}

func (s *Service) netMap(ctx context.Context, nodeID string) (*api.NetMap, error) {
	nm := &api.NetMap{Peers: map[string]api.Peer{}}
	err := s.st.Read(ctx, func(tx *store.Tx) error {
		var err error
		if nm.Version, err = tx.Version(); err != nil {
			return err
		}
		mine, err := tx.Memberships(nodeID)
		if err != nil {
			return err
		}
		for _, m := range mine {
			st := api.RoomState{RoomID: m.RoomID, Status: m.Status}
			if m.Status == store.StatusActive {
				r, err := tx.RoomByID(m.RoomID)
				if err != nil {
					return err
				}
				members, err := tx.ListMembers(m.RoomID)
				if err != nil {
					return err
				}
				cfg := &pki.RoomConfig{RoomID: r.ID, Name: r.Name, Subnet: r.Subnet, Version: r.Version, IssuedAt: s.now().UTC()}
				copy(cfg.Secret[:], r.Secret)
				for _, o := range members {
					if o.Status != store.StatusActive {
						continue
					}
					var k identity.Key
					copy(k[:], o.WGKey)
					cfg.Members = append(cfg.Members, pki.Member{NodeID: o.NodeID, Name: o.Name, WGKey: k, IP: o.IP, Tags: o.Tags})
					if o.NodeID != nodeID {
						if _, ok := nm.Peers[o.NodeID]; !ok {
							n, err := tx.NodeByID(o.NodeID)
							if err != nil {
								return err
							}
							nm.Peers[o.NodeID] = api.Peer{
								PublicIP: n.PublicIP, UDPPort: n.UDPPort, Locals: n.Locals,
								Online: s.now().Sub(n.LastSeen) < OnlineWindow,
							}
						}
					}
				}
				if st.Config, err = pki.SignRoomConfig(ed25519.PrivateKey(r.SignKey), cfg); err != nil {
					return err
				}
			}
			nm.Rooms = append(nm.Rooms, st)
		}
		return nil
	})
	return nm, err
}
