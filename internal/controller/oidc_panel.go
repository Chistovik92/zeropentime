// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

const oidcCookie = "zpt_oidc"

// oidcName is the sign-in button label, "" when OIDC is off.
func (h *Server) oidcName() string {
	if h.oidc == nil {
		return ""
	}
	if h.cfg.OIDC.Name != "" {
		return h.cfg.OIDC.Name
	}
	return "единый вход"
}

func (h *Server) oidcRedirect(r *http.Request) string {
	return h.publicURL(r) + "/login/oidc/callback"
}

func (h *Server) oidcFail(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if err != nil {
		h.log.Warn("oidc sign-in failed", "err", err)
	}
	h.limiter.failed(h.remoteIP(r).String(), time.Now())
	h.render(w, r, http.StatusUnauthorized, "login", &view{Title: "Вход", Err: msg, Data: h.oidcName()})
}

func (h *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	if !h.limiter.allowed(h.remoteIP(r).String(), time.Now()) {
		h.render(w, r, http.StatusTooManyRequests, "login", &view{Title: "Вход", Err: "Слишком много неудачных попыток. Подождите 10 минут.", Data: h.oidcName()})
		return
	}
	state, nonce, verifier := randomURLToken(), randomURLToken(), randomURLToken()
	u, err := h.oidc.authURL(r.Context(), h.oidcRedirect(r), state, nonce, verifier)
	if err != nil {
		h.oidcFail(w, r, "Провайдер входа недоступен", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: state + "." + nonce + "." + verifier, Path: "/login/oidc", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: h.secureCookies(r), MaxAge: 600,
	})
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (h *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	c, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/login/oidc", MaxAge: -1, HttpOnly: true})
	if err != nil {
		h.oidcFail(w, r, "Сессия входа истекла, начните заново", nil)
		return
	}
	parts := strings.Split(c.Value, ".")
	q := r.URL.Query()
	if len(parts) != 3 || q.Get("state") == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(parts[0])) != 1 {
		h.oidcFail(w, r, "Неверный ответ провайдера, начните заново", nil)
		return
	}
	if q.Get("error") != "" || q.Get("code") == "" {
		h.oidcFail(w, r, "Провайдер отказал во входе", nil)
		return
	}
	claims, err := h.oidc.exchange(r.Context(), h.oidcRedirect(r), q.Get("code"), parts[1], parts[2])
	if err != nil {
		h.oidcFail(w, r, "Не удалось войти через провайдера", err)
		return
	}
	if !claims.Verified || claims.Email == "" {
		h.oidcFail(w, r, "Провайдер не подтвердил адрес почты", nil)
		return
	}
	token, err := h.svc.LoginOIDC(r.Context(), claims.Email)
	if err != nil {
		h.oidcFail(w, r, "Этот адрес не привязан ни к одному пользователю панели: попросите администратора выполнить zpt-controller user email", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: h.secureCookies(r), MaxAge: int(SessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/rooms", http.StatusSeeOther)
}
