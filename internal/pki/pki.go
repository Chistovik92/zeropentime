// Package pki holds the signed and encrypted documents exchanged between the
// controller and nodes.
//
//   - RoomConfig: the authoritative member list of a room, signed with the
//     room's Ed25519 key. Nodes pin the room key from the invite, so neither
//     a network attacker nor a replaced controller can forge membership.
//   - Node requests are signed with the node key (no passwords, no tokens).
//   - Controller responses are sealed to the node's X25519 box key, so room
//     secrets never travel in the clear even over plain HTTP.
package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

const (
	roomConfigDomain = "zeropentime/room-config/v1\n"
	requestDomain    = "zeropentime/node-request/v1\n"

	// RequestSkew is how far a signed request's clock may drift.
	RequestSkew = 5 * time.Minute

	HeaderNode = "X-Zpt-Node"
	HeaderTime = "X-Zpt-Time"
	HeaderSig  = "X-Zpt-Sig"
)

// Member is an active member of a room.
type Member struct {
	NodeID string       `json:"node_id"`
	Name   string       `json:"name"`
	WGKey  identity.Key `json:"wg_key"`
	IP     netip.Addr   `json:"ip"`
	Tags   []string     `json:"tags,omitempty"`
}

// RoomConfig is the signed description of a room.
type RoomConfig struct {
	RoomID   string       `json:"room_id"`
	Name     string       `json:"name"`
	Subnet   netip.Prefix `json:"subnet"`
	Secret   obfs.Secret  `json:"secret"`
	Version  int64        `json:"version"`
	IssuedAt time.Time    `json:"issued_at"`
	Members  []Member     `json:"members"`
}

// Signed is a payload with an Ed25519 signature over it. The payload is
// kept as raw bytes, so no canonical JSON form is needed.
type Signed struct {
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

// SignRoomConfig serialises and signs a room config.
func SignRoomConfig(priv ed25519.PrivateKey, c *RoomConfig) (*Signed, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &Signed{Payload: payload, Sig: ed25519.Sign(priv, append([]byte(roomConfigDomain), payload...))}, nil
}

// VerifyRoomConfig checks the signature with the pinned room key before
// parsing anything, then checks internal consistency.
func VerifyRoomConfig(pub ed25519.PublicKey, s *Signed) (*RoomConfig, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("pki: bad room key")
	}
	if !ed25519.Verify(pub, append([]byte(roomConfigDomain), s.Payload...), s.Sig) {
		return nil, errors.New("pki: room config signature is invalid")
	}
	var c RoomConfig
	if err := json.Unmarshal(s.Payload, &c); err != nil {
		return nil, fmt.Errorf("pki: room config: %w", err)
	}
	if c.Secret.RoomID() != c.RoomID {
		return nil, errors.New("pki: room config secret does not match room id")
	}
	if !c.Subnet.IsValid() {
		return nil, errors.New("pki: room config has no subnet")
	}
	seen := map[netip.Addr]bool{}
	for _, m := range c.Members {
		if !c.Subnet.Contains(m.IP) || seen[m.IP] {
			return nil, fmt.Errorf("pki: member %s has invalid or duplicate ip %s", m.NodeID, m.IP)
		}
		seen[m.IP] = true
	}
	return &c, nil
}

// RoomKeyString encodes a room public key for invite links.
func RoomKeyString(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// ParseRoomKey decodes a room public key from an invite link.
func ParseRoomKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("pki: invalid room key")
	}
	return ed25519.PublicKey(b), nil
}

func requestMessage(method, path string, ts int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	var b bytes.Buffer
	b.WriteString(requestDomain)
	b.WriteString(method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n")
	b.Write(sum[:])
	return b.Bytes()
}

// RequestHeaders returns the headers that authenticate a node request.
func RequestHeaders(id *identity.Identity, method, path string, body []byte, now time.Time) map[string]string {
	ts := now.Unix()
	return map[string]string{
		HeaderNode: base64.StdEncoding.EncodeToString(id.PublicKey()),
		HeaderTime: strconv.FormatInt(ts, 10),
		HeaderSig:  base64.StdEncoding.EncodeToString(id.Sign(requestMessage(method, path, ts, body))),
	}
}

// VerifyRequest checks a node request signature and returns the node key.
func VerifyRequest(get func(string) string, method, path string, body []byte, now time.Time) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(get(HeaderNode))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("pki: missing or bad node key")
	}
	ts, err := strconv.ParseInt(get(HeaderTime), 10, 64)
	if err != nil {
		return nil, errors.New("pki: missing timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > RequestSkew || d < -RequestSkew {
		return nil, errors.New("pki: request timestamp too far from server time (check the clock)")
	}
	sig, err := base64.StdEncoding.DecodeString(get(HeaderSig))
	if err != nil || !ed25519.Verify(pub, requestMessage(method, path, ts, body), sig) {
		return nil, errors.New("pki: bad request signature")
	}
	return ed25519.PublicKey(pub), nil
}

// Seal encrypts msg to a node's box key.
func Seal(msg []byte, to identity.Key) ([]byte, error) {
	return box.SealAnonymous(nil, msg, (*[32]byte)(&to), rand.Reader)
}

// Open decrypts a sealed message with the node's box key pair.
func Open(sealed []byte, priv, pub identity.Key) ([]byte, error) {
	msg, ok := box.OpenAnonymous(nil, sealed, (*[32]byte)(&pub), (*[32]byte)(&priv))
	if !ok {
		return nil, errors.New("pki: cannot decrypt controller response")
	}
	return msg, nil
}
