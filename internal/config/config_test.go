package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "zpt.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	s1, _ := obfs.NewSecret()
	s2, _ := obfs.NewSecret()
	id, _ := identity.Generate()
	k, _ := id.RoomKey("x")
	cfg, err := Load(write(t, `
key_file: node.key
rooms:
  - name: game
    secret: `+s1.String()+`
    address: 10.100.1.1/24
    obfuscation: {jc: 8, jmin: 50, jmax: 200}
    peers:
      - name: bob
        public_key: `+k.Public().String()+`
        endpoint: 192.0.2.10:4790
        allowed_ips: [10.100.1.2/32]
        keepalive: 25
  - name: work
    secret: `+s2.String()+`
    address: 10.100.2.1/24
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port() != DefaultListenPort || cfg.Rooms[0].MTU != DefaultMTU {
		t.Fatalf("defaults not applied: port %d mtu %d", cfg.Port(), cfg.Rooms[0].MTU)
	}
	if !filepath.IsAbs(cfg.KeyPath()) {
		t.Fatalf("key path not resolved: %s", cfg.KeyPath())
	}
	if cp := cfg.Rooms[0].ClientParams(); cp.Jc != 8 || cp.Jmax != 200 || cp.ContentPadding != obfs.DefaultClientParams.ContentPadding {
		t.Fatalf("obfuscation overrides wrong: %+v", cp)
	}
}

func TestValidateErrors(t *testing.T) {
	s, _ := obfs.NewSecret()
	sec := s.String()
	cases := map[string]string{
		"no rooms":        `rooms: []`,
		"bad name":        "rooms: [{name: Game!, secret: " + sec + ", address: 10.1.0.1/24}]",
		"no secret":       "rooms: [{name: a, address: 10.1.0.1/24}]",
		"same secret":     "rooms: [{name: a, secret: " + sec + ", address: 10.1.0.1/24}, {name: b, secret: " + sec + ", address: 10.2.0.1/24}]",
		"no address":      "rooms: [{name: a, secret: " + sec + "}]",
		"mtu too big":     "rooms: [{name: a, secret: " + sec + ", address: 10.1.0.1/24, mtu: 1500}]",
		"bad obfuscation": "rooms: [{name: a, secret: " + sec + ", address: 10.1.0.1/24, obfuscation: {jmin: 300, jmax: 100}}]",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	s2, _ := obfs.NewSecret()
	_, err := Load(write(t, "rooms: [{name: a, secret: "+sec+", address: 10.1.0.1/16}, {name: b, secret: "+s2.String()+", address: 10.1.5.1/24}]"))
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("overlapping subnets: got %v", err)
	}
}
