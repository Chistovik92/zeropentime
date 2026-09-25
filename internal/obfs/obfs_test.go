// SPDX-License-Identifier: MPL-2.0

package obfs

import (
	"bytes"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/device"
)

func mustSecret(t *testing.T) Secret {
	t.Helper()
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDeriveIsValidAWGProfile(t *testing.T) {
	for range 500 {
		p := mustSecret(t).Derive()
		for i, h := range p.Headers {
			if h.Lo > h.Hi {
				t.Fatalf("H%d: lo > hi: %v", i+1, h)
			}
			if h.Lo <= 4 {
				t.Fatalf("H%d overlaps plain WireGuard types: %v", i+1, h)
			}
			for j := i + 1; j < 4; j++ {
				o := p.Headers[j]
				if h.Lo <= o.Hi && o.Lo <= h.Hi {
					t.Fatalf("H%d %v overlaps H%d %v", i+1, h, j+1, o)
				}
			}
		}
		for i, s := range p.Paddings {
			if s < device.HeaderCipherNonceSize {
				t.Fatalf("S%d=%d < %d, header protection would be rejected", i+1, s, device.HeaderCipherNonceSize)
			}
		}
		if p.Paddings[3] > MaxTransportPadding {
			t.Fatalf("S4=%d > %d", p.Paddings[3], MaxTransportPadding)
		}
		if p.Paddings[0]+148 == p.Paddings[1]+92 {
			t.Fatal("init and response messages have equal size")
		}
	}
}

func TestDeriveDeterministicAndDistinct(t *testing.T) {
	a, b := mustSecret(t), mustSecret(t)
	if a.Derive() != a.Derive() {
		t.Fatal("derive is not deterministic")
	}
	pa, pb := a.Derive(), b.Derive()
	if pa.TagKey == pb.TagKey || pa.PresharedKey == pb.PresharedKey || pa.HeaderProtectionKey == pb.HeaderProtectionKey {
		t.Fatal("different secrets produced equal keys")
	}
	if pa.PresharedKey == pa.HeaderProtectionKey || bytes.Equal(pa.PresharedKey[:16], pa.TagKey[:]) {
		t.Fatal("derived values are not domain-separated")
	}
}

func TestSecretText(t *testing.T) {
	s := mustSecret(t)
	var back Secret
	if err := back.UnmarshalText([]byte(s.String())); err != nil || back != s {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := ParseSecret("short"); err == nil {
		t.Fatal("expected error for bad secret")
	}
}

func TestTagger(t *testing.T) {
	a := NewTagger(mustSecret(t).Derive().TagKey)
	b := NewTagger(mustSecret(t).Derive().TagKey)

	seen := map[string]bool{}
	for range 1000 {
		pkt := make([]byte, TagLen+10)
		a.Put(pkt)
		if !a.Match(pkt) {
			t.Fatal("own tag not matched")
		}
		if b.Match(pkt) {
			t.Fatal("tag matched a foreign room")
		}
		seen[string(pkt[:TagLen])] = true
	}
	if len(seen) < 990 {
		t.Fatalf("tags repeat too often: %d unique of 1000", len(seen))
	}
	if a.Match(make([]byte, TagLen-1)) {
		t.Fatal("short packet matched")
	}
}

func TestDeviceUAPI(t *testing.T) {
	u := mustSecret(t).Derive().DeviceUAPI(DefaultClientParams)
	for _, k := range []string{"jc=", "jmin=", "jmax=", "s1=", "s4=", "h1=", "h4=", "header_protection_key=", "content_padding_addition="} {
		if !strings.Contains(u, "\n"+k) && !strings.HasPrefix(u, k) {
			t.Errorf("UAPI misses %s:\n%s", k, u)
		}
	}
}
