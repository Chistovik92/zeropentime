// SPDX-License-Identifier: MPL-2.0

// Package stun implements the part of STUN (RFC 5389) zeropentime needs:
// Binding requests and responses carrying XOR-MAPPED-ADDRESS. Nodes send
// requests from their tunnel socket to learn how the outside world sees
// them; controllers (and later relays) answer.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	headerLen   = 20
	magicCookie = 0x2112A442

	typeBindingRequest  = 0x0001
	typeBindingResponse = 0x0101

	attrMappedAddress    = 0x0001
	attrXORMappedAddress = 0x0020
	attrSoftware         = 0x8022

	familyIPv4 = 0x01
	familyIPv6 = 0x02

	// MaxMessage bounds what we parse.
	MaxMessage = 512
)

// TxID identifies a STUN transaction.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var id TxID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

// Is reports whether b looks like a STUN message: the first two bits are
// zero and the magic cookie is in place. Our tunnel packets never match.
func Is(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xC0 == 0 &&
		binary.BigEndian.Uint32(b[4:8]) == magicCookie &&
		int(binary.BigEndian.Uint16(b[2:4]))+headerLen <= len(b)
}

func header(typ uint16, bodyLen int, id TxID) []byte {
	b := make([]byte, headerLen, headerLen+bodyLen)
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], id[:])
	return b
}

// Request builds a Binding request.
func Request(id TxID) []byte { return header(typeBindingRequest, 0, id) }

// ParseRequest returns the transaction ID of a Binding request.
func ParseRequest(b []byte) (TxID, error) {
	var id TxID
	if !Is(b) || binary.BigEndian.Uint16(b[0:2]) != typeBindingRequest {
		return id, errors.New("stun: not a binding request")
	}
	copy(id[:], b[8:20])
	return id, nil
}

// Response builds a Binding success response telling the client its
// address as seen by the server.
func Response(id TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	ipLen, family := 4, byte(familyIPv4)
	if ip.Is6() {
		ipLen, family = 16, familyIPv6
	}
	attrLen := 4 + ipLen
	b := header(typeBindingResponse, 4+attrLen, id)
	var attr [4 + 4 + 16]byte
	binary.BigEndian.PutUint16(attr[0:2], attrXORMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], uint16(attrLen))
	attr[5] = family
	binary.BigEndian.PutUint16(attr[6:8], addr.Port()^uint16(magicCookie>>16))
	xorIP(attr[8:8+ipLen], ip.AsSlice(), id)
	return append(b, attr[:4+attrLen]...)
}

func xorIP(dst, ip []byte, id TxID) {
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], id[:])
	for i := range ip {
		dst[i] = ip[i] ^ key[i]
	}
}

// ParseResponse returns the transaction ID and mapped address of a Binding
// success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	var id TxID
	if !Is(b) || binary.BigEndian.Uint16(b[0:2]) != typeBindingResponse {
		return id, netip.AddrPort{}, errors.New("stun: not a binding response")
	}
	copy(id[:], b[8:20])
	body := b[headerLen : headerLen+int(binary.BigEndian.Uint16(b[2:4]))]
	var mapped netip.AddrPort
	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[0:2])
		n := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+n > len(body) {
			break
		}
		v := body[4 : 4+n]
		switch typ {
		case attrXORMappedAddress:
			if a, ok := parseAddr(v, id, true); ok {
				return id, a, nil
			}
		case attrMappedAddress:
			if a, ok := parseAddr(v, id, false); ok {
				mapped = a
			}
		}
		next := 4 + (n+3)&^3 // attributes are padded to 4 bytes
		if next > len(body) {
			break // the last attribute may lack its padding
		}
		body = body[next:]
	}
	if mapped.IsValid() {
		return id, mapped, nil
	}
	return id, netip.AddrPort{}, errors.New("stun: response without mapped address")
}

func parseAddr(v []byte, id TxID, xored bool) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	ipLen := map[byte]int{familyIPv4: 4, familyIPv6: 16}[v[1]]
	if ipLen == 0 || len(v) < 4+ipLen {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ip := make([]byte, ipLen)
	copy(ip, v[4:4+ipLen])
	if xored {
		port ^= uint16(magicCookie >> 16)
		xorIP(ip, ip, id)
	}
	a, ok := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(a.Unmap(), port), ok
}
