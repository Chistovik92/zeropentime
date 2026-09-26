// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// With a key encryption key (KEK), the secrets in the database — room
// signing keys, room secrets and the settings (relay and VLESS keys) — are
// sealed with XChaCha20-Poly1305. A copy of the database alone then gives
// away nothing; the KEK lives in a separate file.

// sealedPrefix marks a sealed value; values without it are plaintext
// (databases from before the KEK was set).
var sealedPrefix = []byte("zptkek1:")

// ErrNeedKEK means the database holds sealed secrets and no KEK was given.
var ErrNeedKEK = errors.New("секреты в базе зашифрованы: укажите ключ -kek-file")

// KEKSize is the length of a KEK file.
const KEKSize = chacha20poly1305.KeySize

// NewKEKFile creates a random KEK file readable only by its owner.
func NewKEKFile(path string) error {
	k := make([]byte, KEKSize)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(k); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadKEK reads a KEK file.
func LoadKEK(path string) ([]byte, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(k) != KEKSize {
		return nil, fmt.Errorf("ключ %s: %d байт, нужно %d", path, len(k), KEKSize)
	}
	return k, nil
}

func newAEAD(kek []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(kek) }

func (t *Tx) seal(v []byte) ([]byte, error) {
	if t.kek == nil || v == nil {
		return v, nil
	}
	nonce := make([]byte, t.kek.NonceSize(), len(sealedPrefix)+t.kek.NonceSize()+len(v)+t.kek.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte(nil), sealedPrefix...), nonce...)
	return t.kek.Seal(out, nonce, v, nil), nil
}

func isSealed(v []byte) bool { return bytes.HasPrefix(v, sealedPrefix) }

func (t *Tx) open(v []byte) ([]byte, error) {
	if !isSealed(v) {
		return v, nil
	}
	if t.kek == nil {
		return nil, ErrNeedKEK
	}
	v = v[len(sealedPrefix):]
	ns := t.kek.NonceSize()
	if len(v) < ns {
		return nil, errors.New("store: damaged sealed value")
	}
	out, err := t.kek.Open(nil, v[:ns], v[ns:], nil)
	if err != nil {
		return nil, errors.New("store: wrong KEK or damaged secret")
	}
	return out, nil
}

// sealAll seals plaintext secrets left from before the KEK was set, and
// checks that the KEK opens the ones already sealed.
func (t *Tx) sealAll() error {
	rows, err := t.tx.Query(`SELECT id, secret, sign_key FROM rooms`)
	if err != nil {
		return err
	}
	type room struct {
		id           string
		secret, sign []byte
	}
	var rooms []room
	for rows.Next() {
		var r room
		if err := rows.Scan(&r.id, &r.secret, &r.sign); err != nil {
			rows.Close()
			return err
		}
		rooms = append(rooms, r)
	}
	rows.Close()
	for _, r := range rooms {
		for _, col := range []struct {
			name string
			v    []byte
		}{{"secret", r.secret}, {"sign_key", r.sign}} {
			if isSealed(col.v) {
				if _, err := t.open(col.v); err != nil {
					return err
				}
				continue
			}
			s, err := t.seal(col.v)
			if err != nil {
				return err
			}
			if _, err := t.tx.Exec(`UPDATE rooms SET `+col.name+` = ? WHERE id = ?`, s, r.id); err != nil {
				return err
			}
		}
	}
	srows, err := t.tx.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	settings := map[string][]byte{}
	for srows.Next() {
		var k string
		var v []byte
		if err := srows.Scan(&k, &v); err != nil {
			srows.Close()
			return err
		}
		settings[k] = v
	}
	srows.Close()
	for k, v := range settings {
		if isSealed(v) {
			if _, err := t.open(v); err != nil {
				return err
			}
			continue
		}
		if err := t.SetSetting(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Sealed reports whether the database holds secrets sealed with a KEK.
func (t *Tx) Sealed() (bool, error) {
	var n int
	err := t.tx.QueryRow(`SELECT count(*) FROM rooms WHERE substr(sign_key, 1, 8) = ?`, sealedPrefix).Scan(&n)
	return n > 0, err
}
