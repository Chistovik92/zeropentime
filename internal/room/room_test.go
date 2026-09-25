package room

import (
	"net/netip"
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
		if err := dev.IpcSet(uapiConfig(rc, key)); err != nil {
			t.Fatalf("secret %s: %v\n%s", s, err, uapiConfig(rc, key))
		}
	}
}
