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

// statusSocketPath is readable by every local user: the tray runs as the
// user and only reads the status there.
func statusSocketPath() string { return filepath.Join(filepath.Dir(SocketPath), "status.sock") }

func listenSocket(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// A socket left by a node that crashed: remove it unless a node answers.
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, errors.New("another node is already running")
	}
	os.Remove(path)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	os.Chmod(path, mode)
	return ln, nil
}

func listen() (net.Listener, error)       { return listenSocket(SocketPath, 0o600) }
func listenStatus() (net.Listener, error) { return listenSocket(statusSocketPath(), 0o666) }

func dialSocket(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil && (errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)) {
		return nil, errNoNode
	}
	if err != nil && errors.Is(err, os.ErrPermission) {
		return nil, errNoAccess
	}
	return c, err
}

func dial(ctx context.Context) (net.Conn, error)       { return dialSocket(ctx, SocketPath) }
func dialStatus(ctx context.Context) (net.Conn, error) { return dialSocket(ctx, statusSocketPath()) }

func isNoNode(err error) bool { return errors.Is(err, errNoNode) }

const noAccessHint = "нет доступа к узлу: запустите через sudo"
