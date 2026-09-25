// SPDX-License-Identifier: MPL-2.0

package disco

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

func keys(t *testing.T) (priv, pub identity.Key) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id.DiscoKey()
}

func TestSealOpen(t *testing.T) {
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	m := Msg{Type: TypePong, Tx: NewTxID(), Src: netip.MustParseAddrPort("203.0.113.4:4790")}
	pkt, err := Seal(m, aPriv, aPub, bPub)
	if err != nil {
		t.Fatal(err)
	}
	if !obfs.NewTagger(TagKey(bPub)).Match(pkt) {
		t.Fatal("receiver does not recognise its tag")
	}
	if obfs.NewTagger(TagKey(aPub)).Match(pkt) {
		t.Fatal("tag matches the wrong node")
	}
	from, got, err := Open(pkt, bPriv, bPub)
	if err != nil || from != aPub || got != m {
		t.Fatalf("open: %v from=%v msg=%+v", err, from == aPub, got)
	}
	// Two sealings of the same message share no bytes beyond chance.
	pkt2, _ := Seal(m, aPriv, aPub, bPub)
	if bytes.Equal(pkt[:16], pkt2[:16]) {
		t.Fatal("packets are not randomised")
	}
}

func TestOpenRejects(t *testing.T) {
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	cPriv, cPub := keys(t)
	pkt, _ := Seal(Msg{Type: TypePing, Tx: NewTxID()}, aPriv, aPub, bPub)

	if _, _, err := Open(pkt, cPriv, cPub); err == nil {
		t.Fatal("third party opened the packet")
	}
	bad := bytes.Clone(pkt)
	bad[len(bad)-1] ^= 1
	if _, _, err := Open(bad, bPriv, bPub); err == nil {
		t.Fatal("tampered packet accepted")
	}
	// Forgery: C claims to be A inside the outer box but signs with its own key.
	forged := forge(t, cPriv, aPub, bPub)
	if _, _, err := Open(forged, bPriv, bPub); err == nil {
		t.Fatal("forged sender accepted")
	}
}

// forge builds a packet whose outer box names claimedPub as sender but whose
// inner box is made with a different private key.
func forge(t *testing.T, realPriv, claimedPub, to identity.Key) []byte {
	pkt, err := Seal(Msg{Type: TypePing, Tx: NewTxID()}, realPriv, claimedPub, to)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func FuzzOpen(f *testing.F) {
	id, _ := identity.Generate()
	priv, pub := id.DiscoKey()
	pkt, _ := Seal(Msg{Type: TypePing, Tx: NewTxID()}, priv, pub, pub)
	f.Add(pkt)
	f.Fuzz(func(t *testing.T, b []byte) {
		Open(b, priv, pub)
	})
}
