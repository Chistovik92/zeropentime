// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestIcons(t *testing.T) {
	for _, st := range []string{"on", "idle", "down", "?"} {
		img, err := png.Decode(bytes.NewReader(iconPNG(st, 64)))
		if err != nil || img.Bounds().Dx() != 64 {
			t.Fatalf("%s: png %v", st, err)
		}
		ico := iconICO(st)
		var hdr [3]uint16
		binary.Read(bytes.NewReader(ico), binary.LittleEndian, &hdr)
		if hdr != [3]uint16{0, 1, 1} || ico[6] != 32 {
			t.Fatalf("%s: ico header %v", st, hdr)
		}
		size := binary.LittleEndian.Uint32(ico[14:])
		off := binary.LittleEndian.Uint32(ico[18:])
		if _, err := png.Decode(bytes.NewReader(ico[off : off+size])); err != nil {
			t.Fatalf("%s: png inside ico: %v", st, err)
		}
	}
}
