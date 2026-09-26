// SPDX-License-Identifier: MPL-2.0

package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

// Rooms without a controller ("zpt room create --local"): the owner's node
// keeps the room signing key and signs the room config itself; members
// join with an invite link by asking the owner over disco (the owner must
// be online and reachable then); the signed config then spreads by gossip
// like a controller's. The node is MPL-2.0 and does not use the
// controller's (AGPL) code: this is a separate, small signer.

// localPrefix marks the "controller URL" of local rooms in netmaps.
const localPrefix = "local:"

// LocalRoom is a room without a controller as this node knows it.
type LocalRoom struct {
	RoomID  string `json:"room_id"`
	Name    string `json:"name"`
	RoomKey string `json:"room_key"` // pinned public signing key
	// SignKey is the room signing key (Ed25519 seed): only admins have it.
	SignKey []byte        `json:"sign_key,omitempty"`
	Config  *pki.Signed   `json:"config,omitempty"` // newest known
	Invites []LocalInvite `json:"invites,omitempty"`
	// Join is set until the owner accepts this node.
	Join *LocalJoin `json:"join,omitempty"`
	// Peers are how to reach the members (not signed; learned at joins).
	Peers map[string]api.Peer `json:"peers,omitempty"`
}

// LocalInvite is an invite issued by an admin of a local room.
type LocalInvite struct {
	TokenHash []byte    `json:"token_hash"`
	UsesLeft  int       `json:"uses_left"` // -1: unlimited
	Expires   time.Time `json:"expires"`
}

// LocalJoin is a pending request to join a local room.
type LocalJoin struct {
	Invite LocalLink `json:"invite"`
	Name   string    `json:"name"`
	// IP is the address the owner gave us (set when accepted).
	IP netip.Addr `json:"ip,omitzero"`
}

// LocalLink is the content of a "zpt://local?..." invite.
type LocalLink struct {
	RoomID     string           `json:"room_id"`
	RoomKey    string           `json:"room_key"`
	Secret     obfs.Secret      `json:"secret"`
	Subnet     netip.Prefix     `json:"subnet"`
	Token      string           `json:"token"`
	Owner      string           `json:"owner"`       // node ID
	OwnerDisco identity.Key     `json:"owner_disco"` // disco public key
	OwnerWG    identity.Key     `json:"owner_wg"`    // room public key
	OwnerIP    netip.Addr       `json:"owner_ip"`    // room address
	Endpoints  []netip.AddrPort `json:"endpoints"`
}

// String renders the link.
func (l LocalLink) String() string {
	q := url.Values{}
	q.Set("r", l.RoomID)
	q.Set("k", l.RoomKey)
	q.Set("s", l.Secret.String())
	q.Set("n", l.Subnet.String())
	q.Set("t", l.Token)
	q.Set("o", l.Owner)
	q.Set("d", l.OwnerDisco.String())
	q.Set("w", l.OwnerWG.String())
	q.Set("i", l.OwnerIP.String())
	var eps []string
	for _, e := range l.Endpoints {
		eps = append(eps, e.String())
	}
	q.Set("e", strings.Join(eps, ","))
	return "zpt://local?" + q.Encode()
}

// ParseLocalLink parses a "zpt://local?..." invite.
func ParseLocalLink(s string) (LocalLink, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "zpt" || (u.Host != "local" && u.Opaque != "local") {
		return LocalLink{}, errors.New("ссылка комнаты без контроллера должна начинаться с zpt://local?")
	}
	q := u.Query()
	var l LocalLink
	l.RoomID, l.RoomKey, l.Token, l.Owner = q.Get("r"), q.Get("k"), q.Get("t"), q.Get("o")
	if _, err := pki.ParseRoomKey(l.RoomKey); err != nil {
		return l, err
	}
	if err := l.Secret.UnmarshalText([]byte(q.Get("s"))); err != nil || l.Secret.RoomID() != l.RoomID {
		return l, errors.New("ссылка: неверный секрет комнаты")
	}
	if l.Subnet, err = netip.ParsePrefix(q.Get("n")); err != nil {
		return l, fmt.Errorf("ссылка: подсеть: %w", err)
	}
	if l.OwnerDisco, err = identity.ParseKey(q.Get("d")); err != nil {
		return l, fmt.Errorf("ссылка: ключ владельца: %w", err)
	}
	if l.OwnerWG, err = identity.ParseKey(q.Get("w")); err != nil {
		return l, fmt.Errorf("ссылка: ключ владельца в комнате: %w", err)
	}
	if l.OwnerIP, err = netip.ParseAddr(q.Get("i")); err != nil || !l.Subnet.Contains(l.OwnerIP) {
		return l, errors.New("ссылка: адрес владельца")
	}
	for _, e := range strings.Split(q.Get("e"), ",") {
		if ap, err := netip.ParseAddrPort(e); err == nil {
			l.Endpoints = append(l.Endpoints, ap)
		}
	}
	if l.Token == "" || l.Owner == "" || len(l.Endpoints) == 0 {
		return l, errors.New("ссылка неполная")
	}
	return l, nil
}

// LocalRoomByRef finds a local room by ID or name.
func (s *State) LocalRoomByRef(ref string) (*LocalRoom, error) {
	var found *LocalRoom
	for i := range s.Local {
		if s.Local[i].RoomID == ref || strings.EqualFold(s.Local[i].Name, ref) {
			if found != nil {
				return nil, fmt.Errorf("комнат %q несколько — укажите ID", ref)
			}
			found = &s.Local[i]
		}
	}
	if found == nil {
		return nil, fmt.Errorf("комнаты без контроллера %q нет", ref)
	}
	return found, nil
}

// CreateLocalRoom makes a new local room with this node as its owner.
func (s *State) CreateLocalRoom(id *identity.Identity, name, memberName string, subnet netip.Prefix) (*LocalRoom, error) {
	secret, err := obfs.NewSecret()
	if err != nil {
		return nil, err
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if !subnet.IsValid() {
		var b [2]byte
		rand.Read(b[:])
		subnet = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 100 + b[0]%100, b[1], 0}), 24)
	}
	if !subnet.Addr().Is4() || subnet.Bits() > 29 || subnet.Bits() < 16 || subnet != subnet.Masked() {
		return nil, errors.New("подсеть комнаты: IPv4 от /16 до /29, например 10.100.7.0/24")
	}
	roomID := secret.RoomID()
	wg, err := id.RoomKey(roomID)
	if err != nil {
		return nil, err
	}
	cfg := &pki.RoomConfig{RoomID: roomID, Name: name, Subnet: subnet, Secret: secret, Version: 1,
		Members: []pki.Member{{NodeID: id.NodeID(), Name: memberName, WGKey: wg.Public(), IP: hostAddr(subnet, 1)}}}
	lr := LocalRoom{RoomID: roomID, Name: name, SignKey: sign.Seed(),
		RoomKey: pki.RoomKeyString(sign.Public().(ed25519.PublicKey))}
	if err := lr.sign(cfg); err != nil {
		return nil, err
	}
	s.Local = append(s.Local, lr)
	return &s.Local[len(s.Local)-1], nil
}

func hostAddr(p netip.Prefix, n uint32) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) + n
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// config verifies and returns the newest config.
func (lr *LocalRoom) config() (*pki.RoomConfig, error) {
	if lr.Config == nil {
		return nil, errors.New("конфиг комнаты ещё не получен")
	}
	pub, err := pki.ParseRoomKey(lr.RoomKey)
	if err != nil {
		return nil, err
	}
	return pki.VerifyRoomConfig(pub, lr.Config)
}

// sign stores a new version of the config (admins only).
func (lr *LocalRoom) sign(cfg *pki.RoomConfig) error {
	if len(lr.SignKey) != ed25519.SeedSize {
		return errors.New("этот узел не админ комнаты")
	}
	cfg.IssuedAt = time.Now().UTC()
	s, err := pki.SignRoomConfig(ed25519.NewKeyFromSeed(lr.SignKey), cfg)
	if err != nil {
		return err
	}
	lr.Config = s
	return nil
}

// Update changes the config as an admin and signs the next version.
func (lr *LocalRoom) Update(change func(*pki.RoomConfig) error) error {
	cfg, err := lr.config()
	if err != nil {
		return err
	}
	if err := change(cfg); err != nil {
		return err
	}
	cfg.Version++
	return lr.sign(cfg)
}

// NewInvite issues an invite (admins only) and returns its token.
func (lr *LocalRoom) NewInvite(uses int, ttl time.Duration) (string, error) {
	if len(lr.SignKey) == 0 {
		return "", errors.New("приглашать может только админ комнаты")
	}
	var b [18]byte
	rand.Read(b[:])
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	h := sha256.Sum256([]byte(tok))
	if uses <= 0 {
		uses = -1
	}
	lr.Invites = append(lr.Invites, LocalInvite{TokenHash: h[:], UsesLeft: uses, Expires: time.Now().Add(ttl)})
	return tok, nil
}

// useInvite consumes one use of an invite.
func (lr *LocalRoom) useInvite(tok string) bool {
	h := sha256.Sum256([]byte(tok))
	now := time.Now()
	for i, inv := range lr.Invites {
		if string(inv.TokenHash) == string(h[:]) && now.Before(inv.Expires) && inv.UsesLeft != 0 {
			if inv.UsesLeft > 0 {
				lr.Invites[i].UsesLeft--
			}
			return true
		}
	}
	return false
}

// addMember adds a member with the next free address.
func addMember(cfg *pki.RoomConfig, m pki.Member) (netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, x := range cfg.Members {
		if x.NodeID == m.NodeID {
			return x.IP, nil
		}
		used[x.IP] = true
	}
	size := uint32(1)<<(32-cfg.Subnet.Bits()) - 2
	for n := uint32(1); n <= size; n++ {
		if a := hostAddr(cfg.Subnet, n); !used[a] {
			m.IP = a
			cfg.Members = append(cfg.Members, m)
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("в подсети комнаты нет свободных адресов")
}

// localRoomKey finds the pinned key of a local room for apply.
func (s *State) localRoomKey(url, roomID string) (string, bool) {
	if !strings.HasPrefix(url, localPrefix) || strings.TrimPrefix(url, localPrefix) != roomID {
		return "", false
	}
	for _, lr := range s.Local {
		if lr.RoomID == roomID {
			return lr.RoomKey, true
		}
	}
	return "", false
}
