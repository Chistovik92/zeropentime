// SPDX-License-Identifier: AGPL-3.0-only

// Package controller manages rooms, members and invites, signs room configs
// and serves the node API and the admin panel.
package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"sync"
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

	pathsMu sync.Mutex
	paths   map[string]api.PathStats // by node ID, as last reported
}

// NewService creates the service on an open store.
func NewService(st *store.Store, log *slog.Logger) (*Service, error) {
	var v int64
	if err := st.Read(context.Background(), func(tx *store.Tx) (err error) { v, err = tx.Version(); return }); err != nil {
		return nil, err
	}
	return &Service{st: st, hub: newHub(v), log: log, now: time.Now, paths: map[string]api.PathStats{}}, nil
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

func (s *Service) UpdateRoom(ctx context.Context, u *store.User, roomID, name, policy, broadcast string) error {
	name, err := ValidateRoomName(name)
	if err != nil {
		return err
	}
	if !validPolicy(policy) {
		return invalid("режим вступления: manual или auto")
	}
	if broadcast != "on" && broadcast != "off" && broadcast != "mdns" {
		return invalid("broadcast: on, off или mdns")
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if _, err := s.roomFor(tx, u, roomID); err != nil {
			return err
		}
		if err := tx.UpdateRoom(roomID, name, policy, broadcast); err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "room.update", roomID, name+" "+policy+" broadcast="+broadcast)
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

// SetMemberExit picks the exit node a member sends its internet traffic
// through ("" = none). The exit must be an approved exit of the same room;
// a choice made on the member's own machine (zpt exit) wins over this one.
func (s *Service) SetMemberExit(ctx context.Context, u *store.User, roomID, nodeID, exitID string) error {
	return s.change(ctx, func(tx *store.Tx) error {
		if _, err := s.roomFor(tx, u, roomID); err != nil {
			return err
		}
		m, err := tx.Member(roomID, nodeID)
		if err != nil {
			return err
		}
		name := "нет"
		if exitID != "" {
			x, err := tx.Member(roomID, exitID)
			if err != nil {
				return invalid("exit-узел не найден в комнате")
			}
			if exitID == nodeID || !x.Exit || !x.ExitOffered || x.Status != store.StatusActive {
				return invalid("%s не одобрен как exit-узел этой комнаты", x.Name)
			}
			name = x.Name
		}
		m.UseExit = exitID
		if err := tx.UpdateMember(m); err != nil {
			return err
		}
		if err := tx.BumpRoom(roomID); err != nil {
			return err
		}
		return tx.Audit(u.Login, "member.use_exit", roomID, nodeID+" "+m.Name+" -> "+name)
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
	// ActRoutes approves the networks the member currently offers;
	// ActNoRoutes withdraws the approval.
	ActRoutes   MemberAction = "routes"
	ActNoRoutes MemberAction = "noroutes"
	// ActExit lets members send their internet traffic through the member
	// (it must offer to be an exit); ActNoExit withdraws that.
	ActExit   MemberAction = "exit"
	ActNoExit MemberAction = "noexit"
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
		case ActRoutes:
			r, rerr := tx.RoomByID(roomID)
			if rerr != nil {
				return rerr
			}
			m.Routes = nil
			for _, p := range m.Offered {
				if !p.Overlaps(r.Subnet) {
					m.Routes = append(m.Routes, p)
				}
			}
			if len(m.Routes) == 0 {
				return invalid("участник не предлагает сетей для маршрутизации (advertise_routes в его конфиге)")
			}
			err = tx.UpdateMember(m)
		case ActNoRoutes:
			m.Routes = nil
			err = tx.UpdateMember(m)
		case ActExit:
			if !m.ExitOffered {
				return invalid("участник не предлагает себя как exit-узел (advertise_exit в его конфиге)")
			}
			m.Exit = true
			err = tx.UpdateMember(m)
		case ActNoExit:
			m.Exit = false
			err = tx.UpdateMember(m)
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

// knownNAT limits the NAT type to values the panel knows how to show.
var knownNAT = map[string]bool{"": true, "none": true, "cone": true, "symmetric": true, "udp-blocked": true, "unknown": true}

// reach turns what a node reports into what is stored, dropping anything
// malformed or oversized (the node is authenticated, but not trusted to be
// well-behaved).
func reach(e api.Endpoints, remote netip.Addr, version string) store.Reach {
	r := store.Reach{PublicIP: remote, UDPPort: e.UDPPort, Locals: cleanLocals(e), Version: version}
	for _, a := range e.Reflexive {
		if a.IsValid() && len(r.Reflexive) < 4 {
			r.Reflexive = append(r.Reflexive, a)
		}
	}
	if knownNAT[e.NAT] {
		r.NAT = e.NAT
	}
	r.Exit, r.ExitDNS = e.Exit, e.Exit && e.ExitDNS
	if e.PortMap.IsValid() {
		r.PortMap = e.PortMap
	}
	if !e.DiscoKey.IsZero() {
		r.DiscoKey = e.DiscoKey[:]
	}
	if len(e.Relay) <= 255 {
		r.Relay = e.Relay
	}
	for _, p := range e.Routes {
		if pki.ValidRoute(p) && len(r.Routes) < 16 && !slices.Contains(r.Routes, p) {
			r.Routes = append(r.Routes, p)
		}
	}
	if len(r.Version) > 32 {
		r.Version = r.Version[:32]
	}
	return r
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
		if _, err := tx.UpdateNodeEndpoints(nodeID, reach(req.Endpoints, remote, req.ClientVersion)); err != nil {
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
		changed, err = tx.UpdateNodeEndpoints(nodeID, reach(req.Endpoints, remote, req.ClientVersion))
		return err
	})
	if err != nil {
		return nil, boxKey, err
	}
	s.pathsMu.Lock()
	s.paths[nodeID] = req.Endpoints.Paths
	s.pathsMu.Unlock()
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
				cfg := &pki.RoomConfig{RoomID: r.ID, Name: r.Name, Subnet: r.Subnet, Version: r.Version, IssuedAt: s.now().UTC(), Broadcast: r.Broadcast}
				copy(cfg.Secret[:], r.Secret)
				for _, o := range members {
					if o.Status != store.StatusActive {
						continue
					}
					var k identity.Key
					copy(k[:], o.WGKey)
					// Only routes both approved and still offered by the node.
					var routes []netip.Prefix
					for _, p := range o.Routes {
						if slices.Contains(o.Offered, p) {
							routes = append(routes, p)
						}
					}
					exit := o.Exit && o.ExitOffered
					cfg.Members = append(cfg.Members, pki.Member{NodeID: o.NodeID, Name: o.Name, WGKey: k, IP: o.IP, Tags: o.Tags, Routes: routes, Exit: exit, ExitDNS: exit && o.ExitDNS})
					if exit && o.NodeID == m.UseExit && o.NodeID != nodeID {
						st.UseExit = o.NodeID
					}
					if o.NodeID != nodeID {
						if _, ok := nm.Peers[o.NodeID]; !ok {
							n, err := tx.NodeByID(o.NodeID)
							if err != nil {
								return err
							}
							nm.Peers[o.NodeID] = api.Peer{
								PublicIP: n.PublicIP, UDPPort: n.UDPPort, Locals: n.Locals,
								Reflexive: n.Reflexive, PortMap: n.PortMap, NAT: n.NAT, Relay: n.Relay,
								Online: s.now().Sub(n.LastSeen) < OnlineWindow,
							}
							if len(n.DiscoKey) == identity.KeyLen {
								p := nm.Peers[o.NodeID]
								copy(p.DiscoKey[:], n.DiscoKey)
								nm.Peers[o.NodeID] = p
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

// Paths returns how a node last said it reaches its peers.
func (s *Service) Paths(nodeID string) api.PathStats {
	s.pathsMu.Lock()
	defer s.pathsMu.Unlock()
	return s.paths[nodeID]
}

// RelayKey returns the controller's relay key pair, creating it once.
func (s *Service) RelayKey(ctx context.Context) (priv, pub identity.Key, err error) {
	err = s.st.Tx(ctx, func(tx *store.Tx) error {
		v, err := tx.Setting("relay_key")
		if err == nil && len(v) == identity.KeyLen {
			copy(priv[:], v)
			return nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := rand.Read(priv[:]); err != nil {
			return err
		}
		priv[0] &= 248
		priv[31] = (priv[31] & 127) | 64
		return tx.SetSetting("relay_key", priv[:])
	})
	return priv, priv.Public(), err
}

// relayAuth lets the relay ask the database who may use it.
type relayAuth struct{ s *Service }

func (a relayAuth) Node(key identity.Key) (string, bool) {
	var id string
	err := a.s.st.Read(context.Background(), func(tx *store.Tx) (err error) { id, err = tx.NodeByDiscoKey(key[:]); return })
	return id, err == nil
}

func (a relayAuth) CanSend(src, dst string) bool {
	var ok bool
	err := a.s.st.Read(context.Background(), func(tx *store.Tx) (err error) { ok, err = tx.ShareActiveRoom(src, dst); return })
	return err == nil && ok
}

// VLESSSecrets are the REALITY key, short ID and VLESS user of this
// controller, created once.
type VLESSSecrets struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	ShortID    [8]byte
	User       [16]byte
}

func (s *Service) VLESSSecrets(ctx context.Context) (VLESSSecrets, error) {
	var v VLESSSecrets
	err := s.st.Tx(ctx, func(tx *store.Tx) error {
		load := func(key string, dst []byte) error {
			b, err := tx.Setting(key)
			if err == nil && len(b) == len(dst) {
				copy(dst, b)
				return nil
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if _, err := rand.Read(dst); err != nil {
				return err
			}
			return tx.SetSetting(key, dst)
		}
		if err := load("reality_key", v.PrivateKey[:]); err != nil {
			return err
		}
		if err := load("reality_short_id", v.ShortID[:]); err != nil {
			return err
		}
		return load("vless_user", v.User[:])
	})
	if err != nil {
		return v, err
	}
	k, err := ecdh.X25519().NewPrivateKey(v.PrivateKey[:])
	if err != nil {
		return v, err
	}
	copy(v.PublicKey[:], k.PublicKey().Bytes())
	return v, nil
}

// WatchExternalChanges notices changes made to the database by other
// processes (zpt-controller room / invite / routes commands while the
// server runs) and wakes the nodes, instead of letting them wait for the
// end of their long poll.
func (s *Service) WatchExternalChanges(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var v int64
			if err := s.st.Read(ctx, func(tx *store.Tx) (err error) { v, err = tx.Version(); return }); err == nil {
				s.hub.set(v)
			}
		}
	}
}
