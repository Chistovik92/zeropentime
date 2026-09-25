// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/relay"
	"github.com/Chistovik92/zeropentime/internal/stun"
	"github.com/Chistovik92/zeropentime/internal/vless"
	"github.com/Chistovik92/zeropentime/internal/vlesssrv"
)

// Config configures the HTTP server.
type Config struct {
	Listen string
	// PublicURL is the address nodes use to reach the controller, put into
	// invite links. Empty: derived from each request.
	PublicURL string
	TLSCert   string
	TLSKey    string
	// TrustProxy honours X-Forwarded-For/-Proto from private addresses.
	TrustProxy bool
	// STUNListen are UDP addresses of the built-in STUN server (two ports
	// let nodes detect symmetric NAT). Empty: no STUN server.
	STUNListen []string
	// STUNPublic are the STUN addresses given to nodes ("host:port"). Empty:
	// the host of PublicURL (or of the request) with the STUNListen ports.
	STUNPublic []string
	// RelayListen is the UDP address of the built-in relay. Empty: no relay.
	RelayListen string
	// RelayPublic is the relay address given to nodes. Empty: the host of
	// PublicURL (or of the request) with the RelayListen port.
	RelayPublic string
	// VLESSListen is the TCP address of the VLESS + REALITY entrance to the
	// relay (usually :443). Empty: off.
	VLESSListen string
	// VLESSDest is the real website REALITY imitates ("host:443").
	VLESSDest string
	// VLESSServerNames are the names (SNI) of that website.
	VLESSServerNames []string
	// VLESSPublic is the address nodes dial. Empty: the host of PublicURL
	// with the VLESSListen port.
	VLESSPublic string
}

// Server is the controller HTTP server: node API and admin panel.
type Server struct {
	cfg     Config
	svc     *Service
	log     *slog.Logger
	panel   *panel
	limiter loginLimiter
	relay   *relay.Server
	vless   *VLESSSecrets
}

// NewServer wires the handlers.
func NewServer(cfg Config, svc *Service, log *slog.Logger) (*Server, error) {
	p, err := newPanel()
	if err != nil {
		return nil, err
	}
	h := &Server{cfg: cfg, svc: svc, log: log, panel: p}
	if cfg.RelayListen != "" {
		priv, pub, err := svc.RelayKey(context.Background())
		if err != nil {
			return nil, err
		}
		h.relay = relay.NewServer(priv, pub, relayAuth{svc}, log)
		if cfg.VLESSListen != "" {
			if cfg.VLESSDest == "" || len(cfg.VLESSServerNames) == 0 {
				return nil, errors.New("VLESS needs the site REALITY imitates: set -vless-dest and -vless-sni")
			}
			v, err := svc.VLESSSecrets(context.Background())
			if err != nil {
				return nil, err
			}
			h.vless = &v
		}
	}
	return h, nil
}

// RunVLESS serves the VLESS + REALITY entrance until ctx ends.
func (h *Server) RunVLESS(ctx context.Context) error {
	if h.vless == nil {
		return nil
	}
	return vlesssrv.Serve(ctx, vlesssrv.ServerConfig{
		Listen: h.cfg.VLESSListen, Dest: h.cfg.VLESSDest, ServerNames: h.cfg.VLESSServerNames,
		PrivateKey: h.vless.PrivateKey, ShortID: h.vless.ShortID,
		Allowed: func(u vless.UUID) bool { return u == vless.UUID(h.vless.User) },
		OnUDP: func(p *vless.PacketConn, _ netip.AddrPort, _ net.Addr) {
			defer p.Close()
			h.relay.ServeStream(p.ReadPacket, p.WritePacket)
		},
	}, h.log)
}

// RunRelay serves the relay until ctx ends (ServeListener calls it).
func (h *Server) RunRelay(ctx context.Context) error {
	if h.relay == nil {
		return nil
	}
	return h.relay.ServeUDP(ctx, h.cfg.RelayListen)
}

// relays returns the relay list for nodes.
func (h *Server) relays(req *http.Request) []api.Relay {
	if h.relay == nil {
		return nil
	}
	addr := h.cfg.RelayPublic
	if addr == "" {
		_, port, err := net.SplitHostPort(h.cfg.RelayListen)
		if err != nil {
			return nil
		}
		addr = net.JoinHostPort(h.publicHost(req), port)
	}
	r := api.Relay{Addr: addr, Key: h.relay.PublicKey()}
	if h.vless != nil {
		vaddr := h.cfg.VLESSPublic
		if vaddr == "" {
			if _, port, err := net.SplitHostPort(h.cfg.VLESSListen); err == nil {
				vaddr = net.JoinHostPort(h.publicHost(req), port)
			}
		}
		r.VLESS = &api.VLESS{
			Addr: vaddr, ServerName: h.cfg.VLESSServerNames[0], PublicKey: identity.Key(h.vless.PublicKey),
			ShortID: hex.EncodeToString(h.vless.ShortID[:]), User: vless.UUID(h.vless.User).String(),
		}
	}
	return []api.Relay{r}
}

// publicHost is the host nodes use to reach this controller.
func (h *Server) publicHost(r *http.Request) string {
	host := r.Host
	if u, err := url.Parse(h.cfg.PublicURL); err == nil && u.Host != "" {
		host = u.Host
	}
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	return host
}

// Handler returns the root HTTP handler.
func (h *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+api.PathJoin, h.handleJoin)
	mux.HandleFunc("POST "+api.PathPoll, h.handlePoll)
	mux.HandleFunc("POST "+api.PathLeave, h.handleLeave)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	h.routesPanel(mux)
	return mux
}

// stunServers returns the STUN addresses nodes should use.
func (h *Server) stunServers(r *http.Request) []string {
	if len(h.cfg.STUNPublic) > 0 {
		return h.cfg.STUNPublic
	}
	host := h.publicHost(r)
	var out []string
	for _, l := range h.cfg.STUNListen {
		if _, port, err := net.SplitHostPort(l); err == nil {
			out = append(out, net.JoinHostPort(host, port))
		}
	}
	return out
}

// Serve runs the server until ctx is cancelled.
func (h *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", h.cfg.Listen)
	if err != nil {
		return err
	}
	return h.ServeListener(ctx, ln)
}

// ServeListener runs the server on an existing listener.
func (h *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	if len(h.cfg.STUNListen) > 0 {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errc := make(chan error, 1)
		go func() { errc <- stun.Serve(sctx, h.cfg.STUNListen, h.log) }()
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-time.After(100 * time.Millisecond): // listening
		}
	}
	if h.relay != nil {
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			if err := h.RunRelay(rctx); err != nil {
				h.log.Error("relay stopped", "err", err)
			}
		}()
		go func() {
			if err := h.RunVLESS(rctx); err != nil {
				h.log.Error("vless stopped", "err", err)
			}
		}()
	}
	srv := &http.Server{
		Handler:           h.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      (api.PollTimeout + 30) * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	h.log.Info("controller listening", "addr", ln.Addr().String(), "tls", h.cfg.TLSCert != "", "public_url", h.cfg.PublicURL)
	if h.cfg.TLSCert != "" {
		err := srv.ServeTLS(ln, h.cfg.TLSCert, h.cfg.TLSKey)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
