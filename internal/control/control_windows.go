// SPDX-License-Identifier: MPL-2.0

package control

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/amnezia-vpn/amneziawg-go/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

// PipePath is the control pipe; only SYSTEM and administrators may use it.
var PipePath = envOr("ZPT_CONTROL", `\\.\pipe\zeropentime`)

// pipeSDDL lets only SYSTEM and administrators open the pipe.
var pipeSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"

// statusSDDL also lets users signed in at the computer (INTERACTIVE) read
// the status: the tray runs without administrator rights.
var statusSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

func statusPipePath() string { return PipePath + "-status" }

func listenPipe(path, sddl string) (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
}

func listen() (net.Listener, error)       { return listenPipe(PipePath, pipeSDDL) }
func listenStatus() (net.Listener, error) { return listenPipe(statusPipePath(), statusSDDL) }

func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	c, err := namedpipe.DialContext(ctx, path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, errNoNode
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errNoAccess
	}
	return c, err
}

func dial(ctx context.Context) (net.Conn, error)       { return dialPipe(ctx, PipePath) }
func dialStatus(ctx context.Context) (net.Conn, error) { return dialPipe(ctx, statusPipePath()) }

func isNoNode(err error) bool { return errors.Is(err, errNoNode) }

const noAccessHint = "нет доступа к узлу: запустите терминал от имени администратора"
