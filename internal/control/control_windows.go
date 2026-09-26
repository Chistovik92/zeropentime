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

func listen() (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(PipePath)
}

func dial(ctx context.Context) (net.Conn, error) {
	c, err := namedpipe.DialContext(ctx, PipePath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, errNoNode
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, errors.New("нет доступа к узлу: запустите терминал от имени администратора")
	}
	return c, err
}

func isNoNode(err error) bool { return errors.Is(err, errNoNode) }
