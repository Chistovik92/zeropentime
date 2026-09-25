// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/pki"
	"github.com/Chistovik92/zeropentime/internal/store"
)

const maxBody = 64 << 10

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	msg := "internal error"
	switch {
	case errors.Is(err, ErrForbidden):
		status, msg = http.StatusForbidden, "forbidden"
	case errors.Is(err, store.ErrNotFound):
		status, msg = http.StatusNotFound, "not found"
	case errors.Is(err, ErrInvalid):
		status, msg = http.StatusBadRequest, err.Error()
	}
	writeJSON(w, status, api.Error{Error: msg})
}

func sealed(w http.ResponseWriter, v any, to identity.Key) {
	b, err := json.Marshal(v)
	if err == nil {
		b, err = pki.Seal(b, to)
	}
	if err != nil {
		apiError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// nodeRequest verifies the signature and decodes the JSON body.
func (h *Server) nodeRequest(w http.ResponseWriter, r *http.Request, dst any) (ed25519.PublicKey, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, api.Error{Error: "body too large"})
		return nil, false
	}
	key, err := pki.VerifyRequest(r.Header.Get, r.Method, r.URL.Path, body, time.Now())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, api.Error{Error: err.Error()})
		return nil, false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad json"})
		return nil, false
	}
	return key, true
}

func (h *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req api.JoinRequest
	key, ok := h.nodeRequest(w, r, &req)
	if !ok {
		return
	}
	resp, err := h.svc.Join(r.Context(), key, &req, h.remoteIP(r))
	if err != nil {
		apiError(w, err)
		return
	}
	sealed(w, resp, req.BoxKey)
}

func (h *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	var req api.PollRequest
	key, ok := h.nodeRequest(w, r, &req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), api.PollTimeout*time.Second)
	defer cancel()
	nm, boxKey, err := h.svc.Poll(ctx, key, &req, h.remoteIP(r))
	if err != nil {
		apiError(w, err)
		return
	}
	sealed(w, nm, boxKey)
}

func (h *Server) handleLeave(w http.ResponseWriter, r *http.Request) {
	var req api.LeaveRequest
	key, ok := h.nodeRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.svc.Leave(r.Context(), key, req.RoomID); err != nil && !errors.Is(err, store.ErrNotFound) {
		apiError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// remoteIP is the client address, honouring X-Forwarded-For only behind a
// trusted reverse proxy.
func (h *Server) remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	ip := ap.Addr().Unmap()
	if err != nil {
		return netip.Addr{}
	}
	if h.cfg.TrustProxy && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := len(xff) - 1; i >= 0; i-- {
				if xff[i] == ',' {
					xff = xff[i+1:]
					break
				}
			}
			if a, err := netip.ParseAddr(strings.TrimSpace(xff)); err == nil {
				return a.Unmap()
			}
		}
	}
	return ip
}
