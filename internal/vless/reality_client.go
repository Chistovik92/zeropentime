// SPDX-License-Identifier: MPL-2.0
//
// The REALITY client handshake is derived from Xray-core
// (transport/internet/reality/reality.go, https://github.com/XTLS/Xray-core),
// which is also licensed under MPL-2.0.

package vless

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// ClientConfig describes a VLESS + REALITY server.
type ClientConfig struct {
	Addr       string   // host:port of the server (TCP)
	ServerName string   // the website REALITY imitates (SNI)
	PublicKey  [32]byte // server's X25519 public key
	ShortID    [8]byte
	User       UUID
}

// Version bytes put in the session ID; REALITY servers may restrict them.
var clientVersion = [3]byte{26, 3, 27}

// errNotReality means the server answered with a real certificate: we
// reached the imitated website itself, not a REALITY server with our key.
var errNotReality = errors.New("vless: server is not our REALITY server (real certificate received)")

// Dial connects, performs the REALITY handshake, opens a VLESS UDP session
// to dest and returns the packet stream.
func Dial(ctx context.Context, c ClientConfig, dest netip.AddrPort) (*PacketConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	conn, err := realityClient(ctx, raw, c)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if err := WriteRequest(conn, Request{User: c.User, Command: CmdUDP, Dest: dest}); err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	if err := ReadResponse(r); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: no response: %w", err)
	}
	conn.SetDeadline(time.Time{})
	return NewPacketConn(conn, r), nil
}

func realityClient(ctx context.Context, raw net.Conn, c ClientConfig) (net.Conn, error) {
	var authKey []byte
	verified := false
	cfg := &utls.Config{
		ServerName:             c.ServerName,
		InsecureSkipVerify:     true, // REALITY verifies below instead
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errNotReality
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			// A REALITY server proves it knows the shared key: its temporary
			// ed25519 certificate is "signed" with HMAC(authKey, pubkey).
			if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok {
				h := hmac.New(sha512.New, authKey)
				h.Write(pub)
				if bytes.Equal(h.Sum(nil), cert.Signature) {
					verified = true
					return nil
				}
			}
			return errNotReality
		},
	}
	u := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := u.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // fixed place of the session ID
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = clientVersion[0], clientVersion[1], clientVersion[2]
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], c.ShortID[:])

	serverKey, err := ecdh.X25519().NewPublicKey(c.PublicKey[:])
	if err != nil {
		return nil, err
	}
	ecdhe := u.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = u.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("vless: TLS fingerprint without X25519 key share")
	}
	if authKey, err = ecdhe.ECDH(serverKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified {
		return nil, errNotReality
	}
	return u, nil
}
