// SPDX-License-Identifier: MPL-2.0

// Package vlesssrv is the server side of VLESS + REALITY (see package
// vless). It lives apart from the client so nodes do not link the REALITY
// server.
package vlesssrv

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/xtls/reality"

	"github.com/Chistovik92/zeropentime/internal/vless"
)

// ServerConfig configures a VLESS + REALITY server.
type ServerConfig struct {
	Listen string // TCP address, usually :443
	// Dest is the real website REALITY imitates ("host:443"); clients
	// without our key are forwarded to it.
	Dest        string
	ServerNames []string
	PrivateKey  [32]byte
	ShortID     [8]byte
	// Allowed reports whether a VLESS user may connect.
	Allowed func(vless.UUID) bool
	// OnUDP gets each authenticated UDP session; it owns the stream.
	OnUDP func(p *vless.PacketConn, dest netip.AddrPort, remote net.Addr)
}

// Serve runs the server until ctx ends.
func Serve(ctx context.Context, cfg ServerConfig, log *slog.Logger) error {
	if cfg.Dest == "" || len(cfg.ServerNames) == 0 {
		return errors.New("vless: REALITY needs a destination site and its server names")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var dialer net.Dialer
	rc := &reality.Config{
		DialContext:            dialer.DialContext,
		Type:                   "tcp",
		Dest:                   cfg.Dest,
		PrivateKey:             cfg.PrivateKey[:],
		ServerNames:            map[string]bool{},
		ShortIds:               map[[8]byte]bool{cfg.ShortID: true},
		MaxTimeDiff:            2 * time.Minute,
		SessionTicketsDisabled: true,
	}
	for _, n := range cfg.ServerNames {
		rc.ServerNames[n] = true
	}
	rl := reality.NewListener(ln, rc)
	log.Info("vless+reality listening", "addr", ln.Addr().String(), "imitates", cfg.Dest)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := rl.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(conn, cfg, log)
	}
}

func handle(conn net.Conn, cfg ServerConfig, log *slog.Logger) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReaderSize(conn, 64<<10)
	req, err := vless.ReadRequest(r)
	if err != nil || !cfg.Allowed(req.User) || req.Command != vless.CmdUDP {
		conn.Close()
		return
	}
	if err := vless.WriteResponse(conn); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	log.Debug("vless session", "remote", conn.RemoteAddr().String())
	cfg.OnUDP(vless.NewPacketConn(conn, r), req.Dest, conn.RemoteAddr())
}
