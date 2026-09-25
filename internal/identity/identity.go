// Package identity manages the long-term node key and keys derived from it.
//
// Each node has a single Ed25519 identity. For every room the node derives a
// separate WireGuard (X25519) key via HKDF, so compromising the key of one
// room does not expose traffic of the others.
package identity

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

const (
	keyFilePrefix = "zpt-node-key-v1:"
	wgKeySalt     = "zeropentime/wireguard-room-key/v1"
)

// Identity is the long-term key pair of a node.
type Identity struct {
	priv ed25519.PrivateKey
}

// Generate creates a new random identity.
func Generate() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Identity{priv: priv}, nil
}

// Load reads an identity from a key file created by Save.
func Load(path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, keyFilePrefix) {
		return nil, errors.New("identity: unknown key file format")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyFilePrefix))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity: corrupt key file")
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Save writes the identity to path, readable only by the current user.
// It refuses to overwrite an existing file.
func (id *Identity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	data := keyFilePrefix + base64.StdEncoding.EncodeToString(id.priv.Seed()) + "\n"
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// PublicKey returns the Ed25519 public key.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return id.priv.Public().(ed25519.PublicKey)
}

// NodeID is a short stable identifier derived from the public key.
func (id *Identity) NodeID() string { return NodeIDFromPublic(id.PublicKey()) }

// RoomKey derives the AmneziaWG private key this node uses in the room with
// the given room ID (see obfs.Secret.RoomID).
func (id *Identity) RoomKey(roomID string) (Key, error) {
	b, err := hkdf.Key(sha256.New, id.priv.Seed(), []byte(wgKeySalt), "room:"+roomID, KeyLen)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k[:], b)
	k.clamp()
	return k, nil
}

// Sign signs msg with the node's Ed25519 key.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.priv, msg) }

// BoxKey derives the X25519 key pair controllers use to encrypt responses
// to this node (NaCl sealed boxes), so secrets stay private even without TLS.
func (id *Identity) BoxKey() (priv, pub Key) {
	b, err := hkdf.Key(sha256.New, id.priv.Seed(), []byte(wgKeySalt), "controller-box", KeyLen)
	if err != nil {
		panic(err)
	}
	copy(priv[:], b)
	priv.clamp()
	return priv, priv.Public()
}

// NodeIDFromPublic computes the NodeID for an Ed25519 public key.
func NodeIDFromPublic(pub ed25519.PublicKey) string {
	sum := blake2s.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(sum[:10]))
}

// KeyLen is the size of a WireGuard key.
const KeyLen = 32

// Key is a Curve25519 key in the format (Amnezia)WireGuard uses.
type Key [KeyLen]byte

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != KeyLen {
		return k, fmt.Errorf("invalid key %q: must be 32 bytes in base64", s)
	}
	copy(k[:], b)
	return k, nil
}

func (k *Key) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public returns the public key for a private key.
func (k Key) Public() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// String returns the base64 form used in configs and the CLI.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Key) UnmarshalText(b []byte) error {
	parsed, err := ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
