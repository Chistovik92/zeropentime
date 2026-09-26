// SPDX-License-Identifier: MPL-2.0

// Package config loads the static node configuration.
//
// In phase 0 rooms and peers are described statically in YAML. Later phases
// replace the peer list with signed configs pushed by the controller.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

const (
	DefaultListenPort = 4790
	MinMTU            = 1280
	// MaxMTU keeps the outer packet within 1500 bytes: MTU + AmneziaWG
	// overhead (32) + transport padding S4 (<=32) + room tag (8) + UDP/IPv6 (48).
	MaxMTU     = 1500 - 32 - obfs.MaxTransportPadding - obfs.TagLen - 48
	DefaultMTU = MaxMTU
)

// Room names become part of interface names ("zpt-<name>"), which Linux
// limits to 15 characters.
var roomNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,10}$`)

// Config is the node configuration file.
type Config struct {
	// KeyFile is the path to the node identity. Relative paths are resolved
	// against the directory of the config file.
	KeyFile string `yaml:"key_file"`
	// ListenPort is the UDP port shared by all rooms. 0 picks a random port.
	ListenPort *int `yaml:"listen_port"`
	// Userspace runs rooms on an in-process network stack instead of OS
	// interfaces. It needs no admin rights; used by tests and embedders.
	Userspace bool `yaml:"userspace"`
	// LogLevel is one of debug, info, warn, error.
	LogLevel string `yaml:"log_level"`
	// PortMap asks the router to forward the UDP port (UPnP / NAT-PMP).
	// Default: on.
	PortMap *bool `yaml:"portmap"`
	// RelayTransport: "auto" (UDP, VLESS + REALITY when UDP is blocked),
	// "udp" or "vless". Default: auto.
	RelayTransport string `yaml:"relay_transport"`
	// AdvertiseRoutes offers networks behind this node to the rooms it is
	// in (subnet router, Linux only for now); room admins approve them.
	AdvertiseRoutes []netip.Prefix `yaml:"advertise_routes"`
	// AdvertiseExit offers this node as an exit to the internet for the
	// rooms it is in (Linux only for now); room admins approve it.
	AdvertiseExit bool `yaml:"advertise_exit"`
	// KillSwitch blocks the internet while an exit picked by a room admin
	// is not usable (for "zpt exit" choices it is a flag of that command);
	// KillSwitchAllowLAN keeps the local network reachable meanwhile.
	KillSwitch         bool `yaml:"kill_switch"`
	KillSwitchAllowLAN bool `yaml:"kill_switch_allow_lan"`
	// DNS are this device's own DNS servers for all names (inside a room,
	// in a network behind a node, or on the internet); they win over the
	// servers of rooms and exits. "zpt dns" overrides them.
	DNS []netip.Addr `yaml:"dns"`
	// ExitDNSUpstreams are the resolvers this node, as an exit, asks for
	// its users instead of those in /etc/resolv.conf.
	ExitDNSUpstreams []netip.Addr `yaml:"exit_dns_upstreams"`
	// ExitNAT is how this node forwards as an exit: "kernel" (Linux
	// nftables), "userspace" (built-in NAT, any OS) or "auto" (default:
	// kernel on Linux, userspace elsewhere).
	ExitNAT string `yaml:"exit_nat"`
	// ExitRateLimit and ExitRateLimitTotal limit an exit's speed in Mbit/s,
	// per client and in total, in each direction (0: none).
	ExitRateLimit      float64 `yaml:"exit_rate_limit"`
	ExitRateLimitTotal float64 `yaml:"exit_rate_limit_total"`
	Rooms              []Room  `yaml:"rooms"`
}

// Room is one virtual LAN this node is a member of.
type Room struct {
	Name string `yaml:"name"`
	// Secret is shared by all members of the room ("zpt room new"). All
	// AmneziaWG obfuscation parameters and the extra pre-shared key are
	// derived from it.
	Secret  obfs.Secret  `yaml:"secret"`
	Address netip.Prefix `yaml:"address"`
	MTU     int          `yaml:"mtu"`
	// Broadcast shares LAN broadcast and multicast between members:
	// "on" (default), "off" or "mdns" (only mDNS).
	Broadcast   string       `yaml:"broadcast"`
	Obfuscation *Obfuscation `yaml:"obfuscation"`
	Peers       []Peer       `yaml:"peers"`

	// Set by the node for rooms from controllers (not in the config file):
	// Routes are other members' networks to send into the room; Routing
	// are this node's networks it routes for the room (subnet router).
	Routes  []netip.Prefix `yaml:"-"`
	Routing []netip.Prefix `yaml:"-"`
	// Exit: this node's internet traffic goes into the room (the exit peer
	// has 0.0.0.0/0 in its AllowedIPs). ExitNode: this node is an exit for
	// the room's members.
	Exit     bool `yaml:"-"`
	ExitNode bool `yaml:"-"`
	// ExitDNS is the exit's DNS server (its room address) when it has one.
	ExitDNS netip.Addr `yaml:"-"`
	// RoomDNS are the room's own DNS servers (set by a room admin).
	RoomDNS []netip.Addr `yaml:"-"`
	// PeerNodes maps peer keys to node IDs; ExitPeer is the exit's node ID.
	PeerNodes map[identity.Key]string `yaml:"-"`
	ExitPeer  string                  `yaml:"-"`
}

// Obfuscation overrides AmneziaWG parameters that may differ between members
// of a room. Unset fields keep obfs.DefaultClientParams.
type Obfuscation struct {
	Jc             *int    `yaml:"jc"`
	Jmin           *int    `yaml:"jmin"`
	Jmax           *int    `yaml:"jmax"`
	I1             string  `yaml:"i1"`
	I2             string  `yaml:"i2"`
	I3             string  `yaml:"i3"`
	I4             string  `yaml:"i4"`
	I5             string  `yaml:"i5"`
	ContentPadding *string `yaml:"content_padding"`
}

// ClientParams returns the effective AmneziaWG client-side parameters.
func (r *Room) ClientParams() obfs.ClientParams {
	p := obfs.DefaultClientParams
	o := r.Obfuscation
	if o == nil {
		return p
	}
	if o.Jc != nil {
		p.Jc = *o.Jc
	}
	if o.Jmin != nil {
		p.Jmin = *o.Jmin
	}
	if o.Jmax != nil {
		p.Jmax = *o.Jmax
	}
	if o.ContentPadding != nil {
		p.ContentPadding = *o.ContentPadding
	}
	p.I = [5]string{o.I1, o.I2, o.I3, o.I4, o.I5}
	return p
}

// Peer is another member of the room.
type Peer struct {
	Name      string       `yaml:"name"`
	PublicKey identity.Key `yaml:"public_key"`
	// Endpoint is host:port of the peer. Optional: a peer without an
	// endpoint is reached once it contacts us.
	Endpoint   string         `yaml:"endpoint"`
	AllowedIPs []netip.Prefix `yaml:"allowed_ips"`
	// Keepalive in seconds keeps NAT mappings open. 0 disables it.
	Keepalive int `yaml:"keepalive"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.KeyFile != "" && !filepath.IsAbs(c.KeyFile) {
		c.KeyFile = filepath.Join(filepath.Dir(path), c.KeyFile)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// PortMapEnabled reports whether router port mapping is allowed.
func (c *Config) PortMapEnabled() bool { return c.PortMap == nil || *c.PortMap }

// Port returns the UDP listen port.
func (c *Config) Port() int {
	if c.ListenPort == nil {
		return DefaultListenPort
	}
	return *c.ListenPort
}

// KeyPath returns the identity file path, falling back to the OS default.
func (c *Config) KeyPath() string {
	if c.KeyFile != "" {
		return c.KeyFile
	}
	return DefaultKeyPath()
}

// DefaultKeyPath is where the node key is stored when the config does not say.
func DefaultKeyPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "zeropentime", "node.key")
	}
	return "/var/lib/zeropentime/node.key"
}

// UserspaceExit reports whether this node forwards as an exit with the
// built-in NAT rather than the OS.
func (c *Config) UserspaceExit() bool {
	return c.ExitNAT == "userspace" || (c.ExitNAT == "" || c.ExitNAT == "auto") && runtime.GOOS != "linux"
}

// MbitToBytes converts Mbit/s to bytes per second.
func MbitToBytes(m float64) int { return int(m * 125000) }

// Validate checks the config and fills defaults. A config without rooms is
// valid: rooms may come from controllers ("zpt join").
func (c *Config) Validate() error {
	if p := c.Port(); p < 0 || p > 65535 {
		return fmt.Errorf("listen_port %d out of range", p)
	}
	switch c.ExitNAT {
	case "", "auto", "kernel", "userspace":
	default:
		return fmt.Errorf("exit_nat %q: auto, kernel or userspace", c.ExitNAT)
	}
	if c.ExitNAT == "kernel" && runtime.GOOS != "linux" {
		return fmt.Errorf("exit_nat: kernel works only on Linux")
	}
	if c.ExitRateLimit < 0 || c.ExitRateLimitTotal < 0 {
		return fmt.Errorf("exit_rate_limit: must not be negative")
	}
	if len(c.DNS) > 3 {
		return fmt.Errorf("dns: at most 3 servers")
	}
	for _, a := range append(append([]netip.Addr(nil), c.DNS...), c.ExitDNSUpstreams...) {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return fmt.Errorf("dns / exit_dns_upstreams: %s is not a DNS server address", a)
		}
	}
	for _, p := range c.AdvertiseRoutes {
		if !p.IsValid() || p != p.Masked() || !p.Addr().Is4() || p.Bits() < 8 {
			return fmt.Errorf("advertise_routes: %s must be an IPv4 network like 192.168.1.0/24", p)
		}
	}
	switch c.RelayTransport {
	case "", "auto", "udp", "vless":
	default:
		return fmt.Errorf("relay_transport must be auto, udp or vless, not %q", c.RelayTransport)
	}
	names := map[string]bool{}
	secrets := map[obfs.Secret]bool{}
	var prefixes []netip.Prefix
	for i := range c.Rooms {
		r := &c.Rooms[i]
		if err := r.ValidateRoom(); err != nil {
			return err
		}
		if names[r.Name] {
			return fmt.Errorf("room %q: duplicate name", r.Name)
		}
		names[r.Name] = true
		if secrets[r.Secret] {
			return fmt.Errorf("room %q: secret already used by another room", r.Name)
		}
		secrets[r.Secret] = true
		for _, p := range prefixes {
			if p.Overlaps(r.Address.Masked()) {
				return fmt.Errorf("room %q: subnet %s overlaps another room (%s)", r.Name, r.Address.Masked(), p)
			}
		}
		prefixes = append(prefixes, r.Address.Masked())
	}
	return nil
}

// ValidateRoom checks one room on its own and fills its defaults.
func (r *Room) ValidateRoom() error {
	if !roomNameRe.MatchString(r.Name) {
		return fmt.Errorf("room %q: name must be 1-11 chars of a-z, 0-9, '-'", r.Name)
	}
	if r.Secret.IsZero() {
		return fmt.Errorf("room %q: secret is required (generate one with \"zpt room new\")", r.Name)
	}
	if cp := r.ClientParams(); cp.Jc < 0 || cp.Jc > 128 || cp.Jmin < 0 || cp.Jmin > cp.Jmax || cp.Jmax > 1280 {
		return fmt.Errorf("room %q: obfuscation needs 0 <= jc <= 128 and 0 <= jmin <= jmax <= 1280", r.Name)
	}
	if !r.Address.IsValid() {
		return fmt.Errorf("room %q: address is required, e.g. 10.100.1.1/24", r.Name)
	}
	switch r.Broadcast {
	case "", "on", "off", "mdns":
	default:
		return fmt.Errorf("room %q: broadcast must be on, off or mdns", r.Name)
	}
	if r.MTU == 0 {
		r.MTU = DefaultMTU
	}
	if r.MTU < MinMTU || r.MTU > MaxMTU {
		return fmt.Errorf("room %q: mtu must be %d-%d", r.Name, MinMTU, MaxMTU)
	}
	keys := map[identity.Key]bool{}
	for j, p := range r.Peers {
		if p.PublicKey.IsZero() {
			return fmt.Errorf("room %q peer #%d: public_key is required", r.Name, j+1)
		}
		if keys[p.PublicKey] {
			return fmt.Errorf("room %q peer %q: duplicate public_key", r.Name, p.Name)
		}
		keys[p.PublicKey] = true
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("room %q peer %q: allowed_ips is required", r.Name, p.Name)
		}
		if p.Keepalive < 0 || p.Keepalive > 65535 {
			return fmt.Errorf("room %q peer %q: keepalive out of range", r.Name, p.Name)
		}
	}
	return nil
}
