// SPDX-License-Identifier: MPL-2.0

// Package disco is the path discovery protocol between nodes: small
// encrypted ping/pong messages sent to every address a peer might have. A
// pong proves the path works (and punches the NAT on the way); the fastest
// working path becomes the peer's AmneziaWG endpoint.
//
// Wire format (random-looking, like room traffic):
//
//	tag(8) || sealedbox_to_receiver( senderPub(32) || nonce(24) || box(payload, receiver, sender) )
//
// The tag lets the receiver recognise disco packets for itself; the outer
// sealed box hides who is talking; the inner box authenticates the sender,
// so nobody but a known peer can make us use a path.
package disco

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/nacl/box"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

// Message types.
const (
	TypePing byte = 1
	TypePong byte = 2
)

const (
	version    = 1
	txLen      = 12
	payloadLen = 1 + 1 + txLen + 18 // version, type, tx, address (16 IP + 2 port)
	// MaxLen bounds what we try to open.
	MaxLen = 512
)

// TxID identifies a ping and its pong.
type TxID [txLen]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	if _, err := rand.Read(t[:]); err != nil {
		panic(err)
	}
	return t
}

// Msg is a disco message.
type Msg struct {
	Type byte
	Tx   TxID
	// Src, in a pong, is the address the ping came from — the sender learns
	// how the receiver sees it.
	Src netip.AddrPort
}

// TagKey derives the demultiplexing tag key of the node with this disco key.
func TagKey(pub identity.Key) [16]byte {
	h := sha256.Sum256(append([]byte("zeropentime/disco-tag/v1"), pub[:]...))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

func encodePayload(m Msg) []byte {
	p := make([]byte, payloadLen)
	p[0] = version
	p[1] = m.Type
	copy(p[2:2+txLen], m.Tx[:])
	if m.Src.IsValid() {
		ip := m.Src.Addr().As16()
		copy(p[2+txLen:], ip[:])
		binary.BigEndian.PutUint16(p[2+txLen+16:], m.Src.Port())
	}
	return p
}

func decodePayload(p []byte) (Msg, error) {
	if len(p) != payloadLen || p[0] != version || (p[1] != TypePing && p[1] != TypePong) {
		return Msg{}, errors.New("disco: bad payload")
	}
	m := Msg{Type: p[1]}
	copy(m.Tx[:], p[2:2+txLen])
	var ip [16]byte
	copy(ip[:], p[2+txLen:2+txLen+16])
	if a := netip.AddrFrom16(ip).Unmap(); !a.IsUnspecified() {
		m.Src = netip.AddrPortFrom(a, binary.BigEndian.Uint16(p[2+txLen+16:]))
	}
	return m, nil
}

// Seal builds a disco packet from us (priv, pub) to the peer's key.
func Seal(m Msg, priv, pub, to identity.Key) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	inner := box.Seal(nil, encodePayload(m), &nonce, (*[32]byte)(&to), (*[32]byte)(&priv))
	plain := make([]byte, 0, 32+24+len(inner))
	plain = append(plain, pub[:]...)
	plain = append(plain, nonce[:]...)
	plain = append(plain, inner...)
	outer, err := box.SealAnonymous(nil, plain, (*[32]byte)(&to), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, obfs.TagLen, obfs.TagLen+len(outer))
	obfs.NewTagger(TagKey(to)).Put(pkt)
	return append(pkt, outer...), nil
}

// Open decrypts a disco packet addressed to us (tag already checked) and
// returns the sender's key and the message.
func Open(pkt []byte, priv, pub identity.Key) (identity.Key, Msg, error) {
	var sender identity.Key
	if len(pkt) < obfs.TagLen || len(pkt) > MaxLen {
		return sender, Msg{}, errors.New("disco: bad size")
	}
	plain, ok := box.OpenAnonymous(nil, pkt[obfs.TagLen:], (*[32]byte)(&pub), (*[32]byte)(&priv))
	if !ok || len(plain) < 32+24 {
		return sender, Msg{}, errors.New("disco: cannot open")
	}
	copy(sender[:], plain[:32])
	var nonce [24]byte
	copy(nonce[:], plain[32:56])
	payload, ok := box.Open(nil, plain[56:], &nonce, (*[32]byte)(&sender), (*[32]byte)(&priv))
	if !ok {
		return sender, Msg{}, errors.New("disco: sender not authenticated")
	}
	m, err := decodePayload(payload)
	return sender, m, err
}
