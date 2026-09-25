// SPDX-License-Identifier: MPL-2.0

package room

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

// Every derived room profile must be accepted by the real AmneziaWG device,
// not just by our reading of its documentation.
func TestDerivedProfilesAcceptedByAmneziaWG(t *testing.T) {
	tdev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, config.DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	id, _ := identity.Generate()
	peer, _ := identity.Generate()
	psk := strings.Repeat("ab", 32)
	for range 300 {
		s, err := obfs.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		key, _ := id.RoomKey(s.RoomID())
		peerKey, _ := peer.RoomKey(s.RoomID())
		rc := config.Room{
			Name: "t", Secret: s, Address: netip.MustParsePrefix("10.9.0.1/24"), MTU: config.DefaultMTU,
			Peers: []config.Peer{{PublicKey: peerKey.Public(), Endpoint: "127.0.0.1:1", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}}},
		}
		peers, _, _ := peersDiff(nil, rc.Peers, psk, identity.Key{})
		uapi := deviceConfig(rc, key) + "replace_peers=true\n" + peers
		if err := dev.IpcSet(uapi); err != nil {
			t.Fatalf("secret %s: %v\n%s", s, err, uapi)
		}
	}
}

func TestPeersDiff(t *testing.T) {
	k1, k2 := identity.Key{1}, identity.Key{2}
	ip := func(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }
	a := config.Peer{PublicKey: k1, Endpoint: "1.1.1.1:1", AllowedIPs: ip("10.0.0.1/32"), Keepalive: 25}
	b := config.Peer{PublicKey: k2, Endpoint: "2.2.2.2:2", AllowedIPs: ip("10.0.0.2/32"), Keepalive: 25}

	uapi, cur, _ := peersDiff(nil, []config.Peer{a, b}, "psk", identity.Key{})
	if strings.Count(uapi, "public_key=") != 2 || strings.Count(uapi, "preshared_key=psk") != 2 {
		t.Fatalf("initial config:\n%s", uapi)
	}
	if uapi, _, _ := peersDiff(cur, []config.Peer{a, b}, "psk", identity.Key{}); uapi != "" {
		t.Fatalf("no-op update produced config:\n%s", uapi)
	}
	b2 := b
	b2.AllowedIPs = ip("10.0.0.3/32")
	uapi, _, _ = peersDiff(cur, []config.Peer{b2}, "psk", identity.Key{})
	if strings.Contains(uapi, "endpoint=") || strings.Contains(uapi, "preshared_key") ||
		!strings.Contains(uapi, "allowed_ip=10.0.0.3/32") || !strings.Contains(uapi, "remove=true") {
		t.Fatalf("diff should change b's ips and remove a, without touching b's session:\n%s", uapi)
	}
}

// Only the side with the larger key postpones keepalive for a new peer.
func TestKeepaliveTieBreak(t *testing.T) {
	small, big := identity.Key{1}, identity.Key{9}
	peer := func(k identity.Key) config.Peer {
		return config.Peer{PublicKey: k, Endpoint: "1.1.1.1:1", Keepalive: 25, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}
	}
	uapi, _, deferred := peersDiff(nil, []config.Peer{peer(small)}, "psk", big)
	if len(deferred) != 1 || !strings.Contains(uapi, "persistent_keepalive_interval=0") {
		t.Fatalf("bigger side must defer keepalive: %v\n%s", deferred, uapi)
	}
	uapi, _, deferred = peersDiff(nil, []config.Peer{peer(big)}, "psk", small)
	if len(deferred) != 0 || !strings.Contains(uapi, "persistent_keepalive_interval=25") {
		t.Fatalf("smaller side must start keepalive at once: %v\n%s", deferred, uapi)
	}
}
