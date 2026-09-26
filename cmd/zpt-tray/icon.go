// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// The tray icon is drawn here: a ring whose colour tells the state
// (green: rooms up, blue: no active rooms, grey: the node is not running).
var stateColor = map[string]color.RGBA{
	"on":   {0x2e, 0xa0, 0x43, 0xff},
	"idle": {0x3b, 0x82, 0xf6, 0xff},
	"down": {0x80, 0x80, 0x80, 0xff},
}

func iconPNG(state string, size int) []byte {
	c, ok := stateColor[state]
	if !ok {
		c = stateColor["down"]
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	mid := float64(size-1) / 2
	outer, inner, dot := mid, mid*0.62, mid*0.28
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			d := math.Hypot(float64(x)-mid, float64(y)-mid)
			var a float64 // coverage with a soft 1px edge
			switch {
			case d <= dot:
				a = math.Min(1, dot-d+0.5)
			case d >= inner && d <= outer:
				a = math.Min(1, math.Min(d-inner+0.5, outer-d+0.5))
			}
			if a > 0 {
				img.SetNRGBA(x, y, color.NRGBA{c.R, c.G, c.B, uint8(255 * a)})
			}
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// iconICO wraps a PNG into an .ico file (Windows Vista+ reads PNG inside).
func iconICO(state string) []byte {
	const size = 32
	p := iconPNG(state, size)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, 1})
	b.Write([]byte{size, size, 0, 0})
	binary.Write(&b, binary.LittleEndian, [2]uint16{1, 32})
	binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(p)), 6 + 16})
	b.Write(p)
	return b.Bytes()
}
