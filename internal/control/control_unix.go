// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// SocketPath is the control socket; only root may use it. ZPT_CONTROL
// overrides it (several nodes on one machine, tests).
var SocketPath = envOr("ZPT_CONTROL", "/run/zeropentime/zpt.sock")

func listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(SocketPath), 0o755); err != nil {
		return nil, err
	}
	// A socket left by a node that crashed: remove it unless a node answers.
	if c, err := net.Dial("unix", SocketPath); err == nil {
		c.Close()
		return nil, errors.New("another node is already running")
	}
	os.Remove(SocketPath)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", SocketPath)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	os.Chmod(SocketPath, 0o600)
	return ln, nil
}

func dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", SocketPath)
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)) {
		return nil, errNoNode
	}
	if err != nil && errors.Is(err, os.ErrPermission) {
		return nil, errors.New("нет доступа к узлу: запустите через sudo")
	}
	return c, err
}

func isNoNode(err error) bool { return errors.Is(err, errNoNode) }
