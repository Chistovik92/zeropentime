// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// requireAdmin fails early with a clear message instead of a driver error.
func requireAdmin() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return errors.New("zpt up создаёт сетевые интерфейсы: запустите терминал от имени администратора")
}
