// SPDX-License-Identifier: MPL-2.0

//go:build !windows && !linux

package update

import (
	"context"
	"errors"
)

func Detect(string) Kind { return KindArchive }

func runInstaller(context.Context, Kind, string, string) error {
	return errors.New("установщики есть только для Windows и Linux")
}
