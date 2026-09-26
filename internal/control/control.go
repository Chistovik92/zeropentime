// SPDX-License-Identifier: MPL-2.0

// Package control is the local channel between a running node ("zpt up")
// and the zpt command: status, peers, and "apply the new choice now".
//
// It is HTTP with JSON over a Unix socket (Linux, macOS) or a named pipe
// (Windows), reachable only by root / administrators and the system.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"
)

// Status is what "zpt status" shows.
type Status struct {
	NodeID      string             `json:"node_id"`
	Version     string             `json:"version"`
	Started     time.Time          `json:"started"`
	UDPPort     uint16             `json:"udp_port"`
	PortMap     netip.AddrPort     `json:"portmap,omitzero"`
	Relay       string             `json:"relay,omitempty"`
	RelayReady  bool               `json:"relay_ready"`
	RelayVia    string             `json:"relay_via,omitempty"` // "udp" or "vless"
	Controllers []ControllerStatus `json:"controllers"`
	Rooms       []Room             `json:"rooms"`
	Exit        Exit               `json:"exit"`
	KillSwitch  bool               `json:"kill_switch"`
	DNS         []netip.Addr       `json:"dns,omitempty"`
	DNSRoom     string             `json:"dns_room,omitempty"`
}

// ControllerStatus is one followed controller.
type ControllerStatus struct {
	URL      string           `json:"url"`
	LastSync time.Time        `json:"last_sync,omitzero"`
	Error    string           `json:"error,omitempty"`
	NAT      string           `json:"nat,omitempty"`
	Mapped   []netip.AddrPort `json:"mapped,omitempty"`
}

// Exit is the exit choice and whether it is in force.
type Exit struct {
	Choice   string `json:"choice"` // "auto", "off" or "ROOM MEMBER"
	Room     string `json:"room,omitempty"`
	Member   string `json:"member,omitempty"`
	Active   bool   `json:"active"`
	AllowLAN bool   `json:"allow_lan,omitempty"`
}

// Room is a running room.
type Room struct {
	Name      string         `json:"name"`
	ID        string         `json:"id,omitempty"` // "" for static rooms
	Interface string         `json:"interface"`
	Address   netip.Prefix   `json:"address"`
	Broadcast string         `json:"broadcast,omitempty"`
	Routes    []netip.Prefix `json:"routes,omitempty"`  // networks reached through members
	Routing   []netip.Prefix `json:"routing,omitempty"` // networks this node routes
	ExitNode  bool           `json:"exit_node,omitempty"`
	Exit      bool           `json:"exit,omitempty"`
	DNS       []netip.Addr   `json:"dns,omitempty"`
	Zone      string         `json:"zone,omitempty"` // names: NAME.<zone>
	Peers     []Peer         `json:"peers"`
}

// Peer is one peer of a room.
type Peer struct {
	Name          string         `json:"name"`
	NodeID        string         `json:"node_id,omitempty"`
	IP            netip.Addr     `json:"ip"`
	AllowedIPs    []netip.Prefix `json:"allowed_ips"`
	Endpoint      string         `json:"endpoint,omitempty"`
	Path          string         `json:"path"` // "direct", "relay" or "none"
	RTT           time.Duration  `json:"rtt,omitempty"`
	LastHandshake time.Time      `json:"last_handshake,omitzero"`
	RxBytes       uint64         `json:"rx_bytes"`
	TxBytes       uint64         `json:"tx_bytes"`
}

// Node is what the server needs from a running node.
type Node interface {
	Status() Status
	// Reload re-reads the state file now (after "zpt exit", "zpt dns").
	Reload()
}

// ErrNotRunning means no node answers on the control channel.
var ErrNotRunning = errors.New("узел не запущен (zpt up / служба)")

// Serve answers control requests until ctx ends.
func Serve(ctx context.Context, n Node) error {
	ln, err := listen()
	if err != nil {
		return fmt.Errorf("control channel: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(n.Status())
	})
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, _ *http.Request) {
		n.Reload()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Client talks to the running node.
type Client struct{ http *http.Client }

// NewClient returns a client of the local node.
func NewClient() *Client {
	return &Client{http: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		}},
	}}
}

func (c *Client) do(method, path string, out any) error {
	req, _ := http.NewRequest(method, "http://zpt"+path, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, errNoNode) || isNoNode(err) {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("узел ответил %s: %s", resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Status asks the running node for its status.
func (c *Client) Status() (*Status, error) {
	var s Status
	if err := c.do("GET", "/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Reload makes the running node apply the state file now.
func (c *Client) Reload() error { return c.do("POST", "/reload", nil) }

var errNoNode = errors.New("no node")

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
