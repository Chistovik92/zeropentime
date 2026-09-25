// SPDX-License-Identifier: MPL-2.0

// Package vless carries relay frames over VLESS inside a REALITY TLS
// connection to TCP port 443, for networks where UDP is blocked or
// throttled. On the wire it is a TLS 1.3 session with a real website's
// certificate; clients without the right key are transparently forwarded
// to that website, so probing reveals nothing.
//
// Only the parts of VLESS zeropentime needs are implemented: version 0,
// no addons, the UDP command (packets framed with a 2-byte length).
package vless

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
)

const (
	version = 0

	CmdTCP byte = 1
	CmdUDP byte = 2

	addrIPv4   byte = 1
	addrDomain byte = 2
	addrIPv6   byte = 3

	// MaxPacket bounds one UDP packet on the stream.
	MaxPacket = 65535
)

// UUID is the VLESS user ID.
type UUID [16]byte

// ParseUUID parses the canonical 8-4-4-4-12 hex form.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	hex := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			hex = append(hex, s[i])
		}
	}
	if len(hex) != 32 {
		return u, errors.New("vless: bad uuid")
	}
	for i := range 16 {
		var b byte
		if _, err := fmt.Sscanf(string(hex[2*i:2*i+2]), "%02x", &b); err != nil {
			return u, errors.New("vless: bad uuid")
		}
		u[i] = b
	}
	return u, nil
}

func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// Request is a VLESS request header.
type Request struct {
	User    UUID
	Command byte
	Dest    netip.AddrPort
}

// WriteRequest writes a VLESS request header.
func WriteRequest(w io.Writer, r Request) error {
	b := make([]byte, 0, 1+16+1+1+2+1+16)
	b = append(b, version)
	b = append(b, r.User[:]...)
	b = append(b, 0) // no addons
	b = append(b, r.Command)
	b = binary.BigEndian.AppendUint16(b, r.Dest.Port())
	if ip := r.Dest.Addr().Unmap(); ip.Is4() {
		b = append(b, addrIPv4)
		b = append(b, ip.AsSlice()...)
	} else {
		b = append(b, addrIPv6)
		b = append(b, ip.AsSlice()...)
	}
	_, err := w.Write(b)
	return err
}

// ReadRequest reads a VLESS request header. Domain destinations are
// returned as an invalid Dest (zeropentime only relays to itself).
func ReadRequest(r *bufio.Reader) (Request, error) {
	var req Request
	var hdr [18]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return req, err
	}
	if hdr[0] != version {
		return req, errors.New("vless: unsupported version")
	}
	copy(req.User[:], hdr[1:17])
	if n := int(hdr[17]); n > 0 { // skip addons
		if _, err := r.Discard(n); err != nil {
			return req, err
		}
	}
	var cmd [4]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return req, err
	}
	req.Command = cmd[0]
	port := binary.BigEndian.Uint16(cmd[1:3])
	switch cmd[3] {
	case addrIPv4, addrIPv6:
		n := 4
		if cmd[3] == addrIPv6 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return req, err
		}
		a, _ := netip.AddrFromSlice(ip)
		req.Dest = netip.AddrPortFrom(a.Unmap(), port)
	case addrDomain:
		l, err := r.ReadByte()
		if err != nil {
			return req, err
		}
		if _, err := r.Discard(int(l)); err != nil {
			return req, err
		}
	default:
		return req, errors.New("vless: bad address type")
	}
	return req, nil
}

// WriteResponse writes the VLESS response header (version, no addons).
func WriteResponse(w io.Writer) error {
	_, err := w.Write([]byte{version, 0})
	return err
}

// ReadResponse reads the VLESS response header.
func ReadResponse(r *bufio.Reader) error {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	if h[0] != version {
		return errors.New("vless: bad response version")
	}
	_, err := r.Discard(int(h[1]))
	return err
}

// PacketConn sends and receives length-prefixed UDP packets on a VLESS
// stream after the headers.
type PacketConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

// NewPacketConn wraps a stream whose headers are done.
func NewPacketConn(conn net.Conn, r *bufio.Reader) *PacketConn {
	return &PacketConn{conn: conn, r: r}
}

// WritePacket sends one packet.
func (p *PacketConn) WritePacket(b []byte) error {
	if len(b) > MaxPacket {
		return errors.New("vless: packet too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, err := p.conn.Write(buf)
	return err
}

// ReadPacket reads one packet into buf and returns its length.
func (p *PacketConn) ReadPacket(buf []byte) (int, error) {
	var l [2]byte
	if _, err := io.ReadFull(p.r, l[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return 0, errors.New("vless: packet larger than buffer")
	}
	_, err := io.ReadFull(p.r, buf[:n])
	return n, err
}

// Close closes the stream.
func (p *PacketConn) Close() error { return p.conn.Close() }
