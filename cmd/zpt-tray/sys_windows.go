// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")

	pOpenClipboard    = user32.NewProc("OpenClipboard")
	pCloseClipboard   = user32.NewProc("CloseClipboard")
	pEmptyClipboard   = user32.NewProc("EmptyClipboard")
	pGetClipboardData = user32.NewProc("GetClipboardData")
	pSetClipboardData = user32.NewProc("SetClipboardData")
	pGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	pGlobalFree       = kernel32.NewProc("GlobalFree")
	pGlobalLock       = kernel32.NewProc("GlobalLock")
	pGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	pShellExecuteEx   = shell32.NewProc("ShellExecuteExW")
)

const (
	cfUnicodeText    = 13
	gmemMoveable     = 0x0002
	seeMaskNoClose   = 0x00000040
	seeMaskNoAsync   = 0x00000100
	maxClipboardText = 4096
)

// globalPtr turns an address from GlobalLock into a pointer: the memory
// belongs to Windows, not to the Go heap.
func globalPtr(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func openClipboard() error {
	if r, _, err := pOpenClipboard.Call(0); r == 0 {
		return err
	}
	return nil
}

func setClipboard(text string) error {
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if err := openClipboard(); err != nil {
		return err
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	size := uintptr(len(u) * 2)
	h, _, err := pGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return err
	}
	p, _, err := pGlobalLock.Call(h)
	if p == 0 {
		pGlobalFree.Call(h)
		return err
	}
	copy(unsafe.Slice((*uint16)(globalPtr(p)), len(u)), u)
	pGlobalUnlock.Call(h)
	if r, _, err := pSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		pGlobalFree.Call(h)
		return err
	}
	return nil // the clipboard owns the memory now
}

func getClipboard() (string, error) {
	if err := openClipboard(); err != nil {
		return "", err
	}
	defer pCloseClipboard.Call()
	h, _, _ := pGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	p, _, err := pGlobalLock.Call(h)
	if p == 0 {
		return "", err
	}
	defer pGlobalUnlock.Call(h)
	var u []uint16
	for i := 0; i < maxClipboardText; i++ {
		c := *(*uint16)(unsafe.Add(globalPtr(p), i*2))
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return windows.UTF16ToString(u), nil
}

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

// shellRun starts file with args through the shell; verb "runas" asks for
// administrator rights (UAC). With wait, it returns when the program ends.
func shellRun(verb, file string, args []string, show int32, wait bool) error {
	var quoted []string
	for _, a := range args {
		quoted = append(quoted, windows.EscapeArg(a))
	}
	v, _ := windows.UTF16PtrFromString(verb)
	f, _ := windows.UTF16PtrFromString(file)
	p, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	info := shellExecuteInfo{fMask: seeMaskNoClose | seeMaskNoAsync, lpVerb: v, lpFile: f, lpParameters: p, nShow: show}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := pShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return err
	}
	if info.hProcess == 0 {
		return nil
	}
	defer windows.CloseHandle(info.hProcess)
	if !wait {
		return nil
	}
	windows.WaitForSingleObject(info.hProcess, windows.INFINITE)
	var code uint32
	if windows.GetExitCodeProcess(info.hProcess, &code) == nil && code != 0 {
		return errors.New("zpt завершился с ошибкой")
	}
	return nil
}

// zptPath is zpt.exe next to the tray, or the one in PATH.
func zptPath() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "zpt.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "zpt.exe"
}

// runZpt runs "zpt ARGS" with administrator rights and waits.
func runZpt(args []string) error {
	return shellRun("runas", zptPath(), args, windows.SW_HIDE, true)
}

// openInvite opens "zpt open LINK" in its own window (it asks for rights
// and for confirmation itself).
func openInvite(link string) error {
	return shellRun("open", zptPath(), []string{"open", link}, windows.SW_SHOWNORMAL, false)
}

// showStatus opens a window with "zpt status".
func showStatus() error {
	return shellRun("open", "cmd.exe", []string{"/k", zptPath(), "status"}, windows.SW_SHOWNORMAL, false)
}
