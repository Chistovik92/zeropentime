// SPDX-License-Identifier: MPL-2.0

// Package relay forwards packets between nodes that cannot reach each other
// directly (symmetric NAT, blocked UDP). The relay only ever sees AmneziaWG
// packets, which stay end-to-end encrypted between the nodes.
//
// A node first registers (a disco-style sealed and authenticated hello) and
// gets a session with a shared key. After that every frame is
//
//	tag(8) || masked session id(8) || nonce(24) || secretbox(inner)
//
// where the tag marks relay traffic for this relay, the session id is XORed
// with a mask derived from the tag (so nothing on the wire repeats), and
// inner is
//
//	type(1) || node id(10) || payload
//
// with the destination node in SEND frames and the source node in RECV
// frames. The same frames can travel over UDP or inside a stream (VLESS).
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

// Frame types inside a session.
const (
	TypeSend byte = 1 // node -> relay: forward payload to node id
	TypeRecv byte = 2 // relay -> node: payload from node id
	TypePing byte = 3 // keepalive, both ways
)

// Handshake message types (sealed like disco).
const (
	hsHello   byte = 0x11 // node -> relay: register me
	hsWelcome byte = 0x12 // relay -> node: session id and key
)

const (
	NodeIDLen  = 10 // raw bytes of a node ID (identity.NodeID is their base32)
	sessLen    = 8
	nonceLen   = 24
	headerLen  = obfs.TagLen + sessLen + nonceLen
	innerHdr   = 1 + NodeIDLen
	overhead   = headerLen + secretbox.Overhead + innerHdr
	maxFrame   = 65535
	maxPayload = maxFrame - overhead
)

// Session is an established node-relay session.
type Session struct {
	ID  [sessLen]byte
	Key [32]byte
}

// TagKey is the tag key of a relay with this public key.
func TagKey(relayPub identity.Key) [16]byte {
	h := sha256.Sum256(append([]byte("zeropentime/relay-tag/v1"), relayPub[:]...))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

func mask(tag []byte, relayPub identity.Key) [sessLen]byte {
	h := sha256.Sum256(append(append([]byte("zeropentime/relay-mask/v1"), relayPub[:]...), tag...))
	var m [sessLen]byte
	copy(m[:], h[:sessLen])
	return m
}

// Seal builds a session frame.
func Seal(s *Session, relayPub identity.Key, typ byte, node [NodeIDLen]byte, payload []byte) ([]byte, error) {
	if len(payload) > maxPayload {
		return nil, errors.New("relay: payload too large")
	}
	out := make([]byte, headerLen, overhead+len(payload))
	obfs.NewTagger(TagKey(relayPub)).Put(out[:obfs.TagLen])
	m := mask(out[:obfs.TagLen], relayPub)
	for i := range sessLen {
		out[obfs.TagLen+i] = s.ID[i] ^ m[i]
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	copy(out[obfs.TagLen+sessLen:], nonce[:])
	inner := make([]byte, 0, innerHdr+len(payload))
	inner = append(inner, typ)
	inner = append(inner, node[:]...)
	inner = append(inner, payload...)
	return secretbox.Seal(out, inner, &nonce, &s.Key), nil
}

// SessionID extracts the session a frame belongs to.
func SessionID(frame []byte, relayPub identity.Key) ([sessLen]byte, bool) {
	var id [sessLen]byte
	if len(frame) < overhead {
		return id, false
	}
	m := mask(frame[:obfs.TagLen], relayPub)
	for i := range sessLen {
		id[i] = frame[obfs.TagLen+i] ^ m[i]
	}
	return id, true
}

// Open decrypts a session frame.
func Open(s *Session, frame []byte) (typ byte, node [NodeIDLen]byte, payload []byte, err error) {
	if len(frame) < overhead || len(frame) > maxFrame {
		return 0, node, nil, errors.New("relay: bad frame size")
	}
	var nonce [nonceLen]byte
	copy(nonce[:], frame[obfs.TagLen+sessLen:headerLen])
	inner, ok := secretbox.Open(nil, frame[headerLen:], &nonce, &s.Key)
	if !ok || len(inner) < innerHdr {
		return 0, node, nil, errors.New("relay: cannot open frame")
	}
	copy(node[:], inner[1:innerHdr])
	return inner[0], node, inner[innerHdr:], nil
}

// ---- handshake ----

// Hello builds a registration request from a node (disco key pair) to the
// relay. The node proves it owns its disco key; the relay answers with
// Welcome sealed to the same key.
func Hello(nodePriv, nodePub, relayPub identity.Key) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	stamp := make([]byte, 9)
	stamp[0] = hsHello
	if _, err := rand.Read(stamp[1:]); err != nil { // uniqueness, not replay protection: a replayed hello only gets the owner a new session
		return nil, err
	}
	inner := box.Seal(nil, stamp, &nonce, (*[32]byte)(&relayPub), (*[32]byte)(&nodePriv))
	plain := append(append(append([]byte{}, nodePub[:]...), nonce[:]...), inner...)
	outer, err := box.SealAnonymous(nil, plain, (*[32]byte)(&relayPub), rand.Reader)
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, obfs.TagLen, obfs.TagLen+len(outer))
	obfs.NewTagger(helloTagKey(relayPub)).Put(pkt)
	return append(pkt, outer...), nil
}

func helloTagKey(relayPub identity.Key) [16]byte {
	h := sha256.Sum256(append([]byte("zeropentime/relay-hello/v1"), relayPub[:]...))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

// IsHello reports whether a packet is a hello for this relay.
func IsHello(pkt []byte, relayPub identity.Key) bool {
	return obfs.NewTagger(helloTagKey(relayPub)).Match(pkt)
}

// OpenHello authenticates a hello and returns the node's disco key.
func OpenHello(pkt []byte, relayPriv, relayPub identity.Key) (identity.Key, error) {
	var node identity.Key
	if len(pkt) < obfs.TagLen || len(pkt) > 512 {
		return node, errors.New("relay: bad hello size")
	}
	plain, ok := box.OpenAnonymous(nil, pkt[obfs.TagLen:], (*[32]byte)(&relayPub), (*[32]byte)(&relayPriv))
	if !ok || len(plain) < 32+24 {
		return node, errors.New("relay: cannot open hello")
	}
	copy(node[:], plain[:32])
	var nonce [24]byte
	copy(nonce[:], plain[32:56])
	stamp, ok := box.Open(nil, plain[56:], &nonce, (*[32]byte)(&node), (*[32]byte)(&relayPriv))
	if !ok || len(stamp) != 9 || stamp[0] != hsHello {
		return node, errors.New("relay: hello not authenticated")
	}
	return node, nil
}

// Welcome builds the answer to a hello: a fresh session sealed to the node.
func Welcome(s *Session, relayPriv, nodePub identity.Key) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	msg := append(append([]byte{hsWelcome}, s.ID[:]...), s.Key[:]...)
	sealed := box.Seal(nonce[:], msg, &nonce, (*[32]byte)(&nodePub), (*[32]byte)(&relayPriv))
	pkt := make([]byte, obfs.TagLen, obfs.TagLen+len(sealed))
	obfs.NewTagger(welcomeTagKey(nodePub)).Put(pkt)
	return append(pkt, sealed...), nil
}

func welcomeTagKey(nodePub identity.Key) [16]byte {
	h := sha256.Sum256(append([]byte("zeropentime/relay-welcome/v1"), nodePub[:]...))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

// IsWelcome reports whether a packet is a welcome for this node.
func IsWelcome(pkt []byte, nodePub identity.Key) bool {
	return obfs.NewTagger(welcomeTagKey(nodePub)).Match(pkt)
}

// OpenWelcome decrypts a welcome from the relay.
func OpenWelcome(pkt []byte, nodePriv, relayPub identity.Key) (*Session, error) {
	if len(pkt) < obfs.TagLen+24 {
		return nil, errors.New("relay: bad welcome size")
	}
	var nonce [24]byte
	copy(nonce[:], pkt[obfs.TagLen:obfs.TagLen+24])
	msg, ok := box.Open(nil, pkt[obfs.TagLen+24:], &nonce, (*[32]byte)(&relayPub), (*[32]byte)(&nodePriv))
	if !ok || len(msg) != 1+sessLen+32 || msg[0] != hsWelcome {
		return nil, errors.New("relay: bad welcome")
	}
	s := &Session{}
	copy(s.ID[:], msg[1:1+sessLen])
	copy(s.Key[:], msg[1+sessLen:])
	return s, nil
}

// NewSession creates a random session.
func NewSession() (*Session, error) {
	s := &Session{}
	if _, err := rand.Read(s.ID[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(s.Key[:]); err != nil {
		return nil, err
	}
	return s, nil
}

// NodeIDBytes and NodeIDString convert between identity.NodeID strings and
// the raw form used on the wire.
func NodeIDBytes(id string) ([NodeIDLen]byte, error) {
	var b [NodeIDLen]byte
	raw, err := nodeIDEncoding.DecodeString(upper(id))
	if err != nil || len(raw) != NodeIDLen {
		return b, errors.New("relay: bad node id")
	}
	copy(b[:], raw)
	return b, nil
}

func NodeIDString(b [NodeIDLen]byte) string { return lower(nodeIDEncoding.EncodeToString(b[:])) }
