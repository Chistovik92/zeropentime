// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "zpt-tray пока есть только для Windows и Linux; состояние узла: zpt status")
	os.Exit(1)
}
