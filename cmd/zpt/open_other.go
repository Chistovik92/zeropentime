// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func isAdmin() bool { return os.Geteuid() == 0 }

// relaunchAsAdmin runs "zpt open LINK" again as root through polkit.
func relaunchAsAdmin(link string) error {
	pk, err := exec.LookPath("pkexec")
	if err != nil {
		return errors.New("нужны права root: выполните sudo zpt join \"" + link + "\"")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(pk, []string{pk, exe, "open", link}, os.Environ())
}
