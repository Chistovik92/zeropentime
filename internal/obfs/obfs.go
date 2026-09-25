// Package obfs derives everything a room needs on the wire from one shared
// room secret: AmneziaWG 3 obfuscation parameters, the extra pre-shared key
// and the hidden room tag used to demultiplex rooms on the shared socket.
//
// Traffic protection has two independent layers:
//   - encryption: AmneziaWG (Noise IK, Curve25519, ChaCha20-Poly1305) with a
//     per-room pre-shared key mixed in, so only room members can even
//     complete a handshake;
//   - camouflage: AWG 3 header protection, randomised message types
//     (H1-H4), paddings (S1-S4), junk packets, content padding and a random
//     looking room tag instead of a plaintext room number.
//
// Leaking the room secret does not break encryption (Curve25519 keys are
// still needed); it only lets an observer recognise the room's traffic.
package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	SecretLen = 32
	// TagLen is the size of the room tag prepended to every datagram.
	TagLen   = 8
	nonceLen = 4
	hkdfSalt = "zeropentime/room/v1"

	// MaxTransportPadding bounds S4, which is added to every data packet.
	// Default room MTU is chosen so that MTU + WireGuard overhead (32) +
	// S4 + tag + UDP/IPv6 headers (48) fits in 1500 bytes.
	MaxTransportPadding = 32
	// MinPadding is the smallest S1-S4 AmneziaWG accepts with header
	// protection: the padding doubles as the header cipher nonce
	// (device.HeaderCipherNonceSize = 12; the AWG README says 8, the code wants 12).
	MinPadding = 12
)

// Secret is the shared room secret. Every member of a room has the same one.
type Secret [SecretLen]byte

// NewSecret generates a random room secret.
func NewSecret() (Secret, error) {
	var s Secret
	_, err := rand.Read(s[:])
	return s, err
}

// ParseSecret decodes a base64 secret.
func ParseSecret(v string) (Secret, error) {
	var s Secret
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(b) != SecretLen {
		return s, fmt.Errorf("invalid room secret: must be %d bytes in base64", SecretLen)
	}
	copy(s[:], b)
	return s, nil
}

func (s Secret) IsZero() bool                 { return s == Secret{} }
func (s Secret) String() string               { return base64.StdEncoding.EncodeToString(s[:]) }
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
func (s *Secret) UnmarshalText(b []byte) error {
	p, err := ParseSecret(string(b))
	if err != nil {
		return err
	}
	*s = p
	return nil
}

func (s Secret) derive(label string, n int) []byte {
	b, err := hkdf.Key(sha256.New, s[:], []byte(hkdfSalt), label, n)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	return b
}

// RoomID is a stable public identifier of the room derived from its secret.
func (s Secret) RoomID() string { return hex.EncodeToString(s.derive("room-id", 16)) }

// Range is an inclusive uint32 range, "lo-hi" in AWG syntax.
type Range struct{ Lo, Hi uint32 }

func (r Range) String() string {
	if r.Lo == r.Hi {
		return fmt.Sprint(r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// Profile holds the parameters that must be identical on all room members.
type Profile struct {
	Headers             [4]Range  // H1-H4: init, response, cookie, transport
	Paddings            [4]uint16 // S1-S4
	HeaderProtectionKey [32]byte
	PresharedKey        [32]byte
	TagKey              [16]byte
}

// Derive computes the room profile from the secret.
func (s Secret) Derive() Profile {
	var p Profile
	r := s.derive("awg-params", 64)

	// H1-H4: four disjoint ranges, one per quarter of the uint32 space
	// (skipping 1-4, the values of plain WireGuard), quarters shuffled.
	order := [4]int{0, 1, 2, 3}
	for i := 3; i > 0; i-- {
		j := int(r[i]) % (i + 1)
		order[i], order[j] = order[j], order[i]
	}
	const quarter = 1 << 30
	for i := range 4 {
		base := uint64(order[i]) * quarter
		if base == 0 {
			base = 1 << 16
		}
		width := uint64(1<<20) + uint64(binary.BigEndian.Uint32(r[4+4*i:]))%(1<<24)
		span := uint64(quarter) - (base % quarter) - width - 1
		lo := base + uint64(binary.BigEndian.Uint32(r[20+4*i:]))%span
		p.Headers[i] = Range{Lo: uint32(lo), Hi: uint32(lo + width)}
	}

	// S1-S3: handshake paddings 16-143 bytes; S4: transport 12-32 bytes.
	// Header protection needs every padding to be at least MinPadding.
	for i := range 3 {
		p.Paddings[i] = 16 + uint16(r[36+i])%128
	}
	if p.Paddings[0]+148 == p.Paddings[1]+92 { // keep init and response sizes distinct
		p.Paddings[1]++
	}
	p.Paddings[3] = MinPadding + uint16(r[39])%(MaxTransportPadding-MinPadding+1)

	copy(p.HeaderProtectionKey[:], s.derive("awg-header-protection", 32))
	copy(p.PresharedKey[:], s.derive("wireguard-psk", 32))
	copy(p.TagKey[:], s.derive("room-tag", 16))
	return p
}

// ClientParams are AWG parameters that may differ between members: junk
// packets, custom signature packets and content padding.
type ClientParams struct {
	Jc, Jmin, Jmax int
	I              [5]string
	ContentPadding string // AWG range, e.g. "0-32"
}

// DefaultClientParams are used when the config does not override them.
var DefaultClientParams = ClientParams{Jc: 4, Jmin: 40, Jmax: 120, ContentPadding: "0-32"}

// DeviceUAPI renders the device part of an AWG UAPI config.
func (p Profile) DeviceUAPI(c ClientParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", c.Jc, c.Jmin, c.Jmax)
	for i, s := range p.Paddings {
		fmt.Fprintf(&b, "s%d=%d\n", i+1, s)
	}
	for i, h := range p.Headers {
		fmt.Fprintf(&b, "h%d=%s\n", i+1, h)
	}
	for i, v := range c.I {
		if v != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, v)
		}
	}
	fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(p.HeaderProtectionKey[:]))
	if c.ContentPadding != "" {
		fmt.Fprintf(&b, "content_padding_addition=%s\n", c.ContentPadding)
	}
	return b.String()
}

// Tagger writes and checks the hidden room tag:
//
//	nonce(4 random bytes) || AES-128(tagKey, nonce || zero padding)[:4]
//
// On the wire it is indistinguishable from random bytes; without the room
// secret one cannot tell which room (or which protocol) a packet belongs to.
type Tagger struct {
	block cipher.Block
}

// NewTagger creates a tagger for a room.
func NewTagger(key [16]byte) *Tagger {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // 16-byte key never fails
	}
	return &Tagger{block: block}
}

func (t *Tagger) mac(nonce []byte, out *[aes.BlockSize]byte) {
	var in [aes.BlockSize]byte
	copy(in[:], nonce)
	t.block.Encrypt(out[:], in[:])
}

// Put writes a fresh tag into dst[:TagLen].
func (t *Tagger) Put(dst []byte) {
	if _, err := rand.Read(dst[:nonceLen]); err != nil {
		panic(err)
	}
	var m [aes.BlockSize]byte
	t.mac(dst[:nonceLen], &m)
	copy(dst[nonceLen:TagLen], m[:TagLen-nonceLen])
}

// Match reports whether pkt carries this room's tag.
func (t *Tagger) Match(pkt []byte) bool {
	if len(pkt) < TagLen {
		return false
	}
	var m [aes.BlockSize]byte
	t.mac(pkt[:nonceLen], &m)
	return subtle.ConstantTimeCompare(m[:TagLen-nonceLen], pkt[nonceLen:TagLen]) == 1
}
