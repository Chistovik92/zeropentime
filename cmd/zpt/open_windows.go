// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// relaunchAsAdmin runs "zpt open LINK" again through UAC.
func relaunchAsAdmin(link string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(windows.EscapeArg("open") + " " + windows.EscapeArg(link))
	if err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_NORMAL); err != nil {
		return err
	}
	os.Exit(0) // the elevated window takes over
	return nil
}
