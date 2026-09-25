// SPDX-License-Identifier: MPL-2.0

package room

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func configureInterface(dev tun.Device, name string, addr netip.Prefix, mtu int, log *slog.Logger) error {
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		return fmt.Errorf("unexpected TUN type %T", dev)
	}
	luid := winipcfg.LUID(nt.LUID())
	// Windows adds the on-link route for the subnet together with the address.
	if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	family := winipcfg.AddressFamily(windows.AF_INET)
	if addr.Addr().Is6() {
		family = windows.AF_INET6
	}
	iface, err := luid.IPInterface(family)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	iface.NLMTU = uint32(mtu)
	iface.ForwardingEnabled = false
	if err := iface.Set(); err != nil {
		return fmt.Errorf("set mtu: %w", err)
	}
	go setPrivateProfile(name, log)
	return nil
}

// privateProfileTimeout bounds how long we wait for Windows to register the
// new network before giving up on switching it to "Private".
const privateProfileTimeout = time.Minute

// setPrivateProfile switches the room interface from the default "Public"
// network profile to "Private", so Windows Firewall allows ping, file
// sharing and LAN discovery inside the room like on a home LAN. The profile
// appears a few seconds after the interface comes up, hence the retries.
func setPrivateProfile(ifname string, log *slog.Logger) {
	if !safeIfname(ifname) {
		log.Warn("unexpected interface name, not changing its network profile", "interface", ifname)
		return
	}
	script := fmt.Sprintf("Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction Stop", ifname)
	deadline := time.Now().Add(privateProfileTimeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
		if err == nil {
			log.Info("network profile set to Private", "interface", ifname)
			return
		}
		last = strings.TrimSpace(string(out))
		time.Sleep(2 * time.Second)
	}
	log.Warn("could not set the network profile to Private: Windows Firewall may block inbound ping and file sharing in the room",
		"interface", ifname, "err", last)
}

// safeIfname allows only names we generate ("zpt-" + a-z, 0-9, '-'), so the
// name can be put into a PowerShell string literal as is.
func safeIfname(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
