// SPDX-License-Identifier: MPL-2.0

// Package api defines the node <-> controller protocol.
//
// Requests are JSON, signed with the node key (pki.RequestHeaders).
// Successful responses are JSON sealed to the node's box key (pki.Seal),
// sent as application/octet-stream. Errors are plain JSON {"error": "..."}.
package api

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

const (
	PathJoin  = "/api/v1/node/join"
	PathPoll  = "/api/v1/node/poll"
	PathLeave = "/api/v1/node/leave"

	// PollTimeout is how long the controller holds a poll without changes.
	PollTimeout = 25
)

// Endpoints tell the controller how a node may be reached.
type Endpoints struct {
	UDPPort uint16           `json:"udp_port"`
	Locals  []netip.AddrPort `json:"locals"`
	// Reflexive are the node's external addresses as seen by STUN servers.
	Reflexive []netip.AddrPort `json:"reflexive,omitempty"`
	// NAT is the NAT type from netcheck ("none", "cone", "symmetric", ...).
	NAT string `json:"nat,omitempty"`
	// PortMap is the external address the router forwards (UPnP / NAT-PMP).
	PortMap netip.AddrPort `json:"portmap,omitzero"`
	// DiscoKey is the node's public key for path discovery (package disco).
	DiscoKey identity.Key `json:"disco_key,omitzero"`
	// Relay is the relay the node has a session with ("host:port").
	Relay string `json:"relay,omitempty"`
	// Paths counts the node's peers reached directly and through a relay.
	Paths PathStats `json:"paths,omitzero"`
}

// PathStats counts how a node reaches its peers.
type PathStats struct {
	Direct int `json:"direct"`
	Relay  int `json:"relay"`
}

// Relay is a relay server nodes may use.
type Relay struct {
	Addr string       `json:"addr"` // host:port (UDP)
	Key  identity.Key `json:"key"`
}

type JoinRequest struct {
	RoomID        string       `json:"room_id"`
	Token         string       `json:"token"`
	Name          string       `json:"name"`
	WGKey         identity.Key `json:"wg_key"`
	BoxKey        identity.Key `json:"box_key"`
	Endpoints     Endpoints    `json:"endpoints"`
	ClientVersion string       `json:"client_version"`
}

type JoinResponse struct {
	Status   string `json:"status"` // pending | active
	RoomName string `json:"room_name"`
}

type PollRequest struct {
	Since         int64        `json:"since"`
	BoxKey        identity.Key `json:"box_key"`
	Endpoints     Endpoints    `json:"endpoints"`
	ClientVersion string       `json:"client_version"`
}

type LeaveRequest struct {
	RoomID string `json:"room_id"`
}

// NetMap is everything a node needs to run its rooms from one controller.
type NetMap struct {
	Version    int64           `json:"version"`
	ObservedIP netip.Addr      `json:"observed_ip"`
	Rooms      []RoomState     `json:"rooms"`
	Peers      map[string]Peer `json:"peers"` // by node ID
	// STUN servers ("host:port") the node should use to learn its address.
	STUN []string `json:"stun,omitempty"`
	// Relays forward traffic when no direct path works.
	Relays []Relay `json:"relays,omitempty"`
}

type RoomState struct {
	RoomID string      `json:"room_id"`
	Status string      `json:"status"`           // pending | active | banned
	Config *pki.Signed `json:"config,omitempty"` // only when active
}

// Peer is advisory reachability info (not signed: AmneziaWG authenticates
// peers by key, so a wrong endpoint can only cause a failed connection).
type Peer struct {
	PublicIP  netip.Addr       `json:"public_ip"`
	UDPPort   uint16           `json:"udp_port"`
	Locals    []netip.AddrPort `json:"locals"`
	Reflexive []netip.AddrPort `json:"reflexive,omitempty"`
	PortMap   netip.AddrPort   `json:"portmap,omitzero"`
	NAT       string           `json:"nat,omitempty"`
	DiscoKey  identity.Key     `json:"disco_key,omitzero"`
	Relay     string           `json:"relay,omitempty"`
	Online    bool             `json:"online"`
}

type Error struct {
	Error string `json:"error"`
}

// Invite is the content of a "zpt://join?..." link.
type Invite struct {
	Controller string // base URL, e.g. https://zpt.example.org
	RoomID     string
	RoomKey    string // pki.RoomKeyString
	Token      string
}

// String renders the invite as a link.
func (i Invite) String() string {
	q := url.Values{}
	q.Set("c", i.Controller)
	q.Set("r", i.RoomID)
	q.Set("k", i.RoomKey)
	q.Set("t", i.Token)
	return "zpt://join?" + q.Encode()
}

// ParseInvite parses a link produced by Invite.String.
func ParseInvite(s string) (Invite, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "zpt" || (u.Host != "join" && u.Opaque != "join") {
		return Invite{}, errors.New("invite must look like zpt://join?...")
	}
	q := u.Query()
	inv := Invite{Controller: strings.TrimRight(q.Get("c"), "/"), RoomID: q.Get("r"), RoomKey: q.Get("k"), Token: q.Get("t")}
	if inv.Controller == "" || inv.RoomID == "" || inv.RoomKey == "" || inv.Token == "" {
		return Invite{}, errors.New("invite is incomplete")
	}
	cu, err := url.Parse(inv.Controller)
	if err != nil || (cu.Scheme != "https" && cu.Scheme != "http") || cu.Host == "" {
		return Invite{}, fmt.Errorf("invite has a bad controller address %q", inv.Controller)
	}
	if _, err := pki.ParseRoomKey(inv.RoomKey); err != nil {
		return Invite{}, err
	}
	return inv, nil
}
