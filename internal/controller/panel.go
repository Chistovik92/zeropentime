package controller

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/Chistovik92/zeropentime/internal/store"
)

//go:embed web/templates/*.html web/static/*
var webFS embed.FS

const sessionCookie = "zpt_session"

type panel struct {
	pages  map[string]*template.Template
	static http.Handler
}

var funcs = template.FuncMap{
	"since": func(t time.Time) string {
		if t.IsZero() || t.Unix() <= 0 {
			return "никогда"
		}
		d := time.Since(t).Round(time.Second)
		switch {
		case d < time.Minute:
			return "только что"
		case d < time.Hour:
			return fmt.Sprintf("%d мин назад", int(d.Minutes()))
		case d < 48*time.Hour:
			return fmt.Sprintf("%d ч назад", int(d.Hours()))
		}
		return t.Format("02.01.2006")
	},
	"online": func(t time.Time) bool { return time.Since(t) < OnlineWindow },
	// actArgs packs the arguments of the "act" (member action button) template.
	"actArgs": func(room, node, action, label, csrf, confirm string) map[string]string {
		return map[string]string{"Room": room, "Node": node, "Action": action, "Label": label, "CSRF": csrf, "Confirm": confirm}
	},
	"date": func(t time.Time) string { return t.Format("02.01.2006 15:04") },
	"join": strings.Join,
	"uses": func(n int) string {
		if n < 0 {
			return "без ограничений"
		}
		return strconv.Itoa(n)
	},
	"status": func(s string) string {
		return map[string]string{store.StatusActive: "активен", store.StatusPending: "ждёт одобрения", store.StatusBanned: "заблокирован"}[s]
	},
}

func newPanel() (*panel, error) {
	p := &panel{pages: map[string]*template.Template{}}
	pages, err := fs.Glob(webFS, "web/templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, page := range pages {
		if strings.HasSuffix(page, "/layout.html") {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(webFS, "web/templates/layout.html", page)
		if err != nil {
			return nil, err
		}
		p.pages[strings.TrimSuffix(page[strings.LastIndex(page, "/")+1:], ".html")] = t
	}
	sub, _ := fs.Sub(webFS, "web/static")
	p.static = http.StripPrefix("/static/", http.FileServerFS(sub))
	return p, nil
}

// view is the data every page gets.
type view struct {
	User  *store.User
	CSRF  string
	Title string
	OK    string
	Err   string
	Data  any
}

func (h *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, v *view) {
	if v.OK == "" {
		v.OK = r.URL.Query().Get("ok")
	}
	if v.Err == "" {
		v.Err = r.URL.Query().Get("err")
	}
	var buf bytes.Buffer
	if err := h.panel.pages[page].Execute(&buf, v); err != nil {
		h.log.Error("render", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type authed func(w http.ResponseWriter, r *http.Request, u *store.User, csrf string)

// auth requires a session; POSTs also require the CSRF token.
func (h *Server) auth(next authed) http.Handler {
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, sess, err := h.svc.Session(r.Context(), c.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
				http.Error(w, "CSRF-токен неверен: обновите страницу", http.StatusForbidden)
				return
			}
		}
		next(w, r, u, sess.CSRF)
	}))
}

func (h *Server) secureCookies(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(h.cfg.PublicURL, "https://") ||
		h.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https"
}

// publicURL is the controller address for invite links.
func (h *Server) publicURL(r *http.Request) string {
	if h.cfg.PublicURL != "" {
		return h.cfg.PublicURL
	}
	scheme := "http"
	if r.TLS != nil || h.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func back(w http.ResponseWriter, r *http.Request, path string, err error, ok string) {
	q := url.Values{}
	if err != nil {
		q.Set("err", userMessage(err))
	} else if ok != "" {
		q.Set("ok", ok)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// userMessage turns an error into text safe to show in the panel.
func userMessage(err error) string {
	switch {
	case errors.Is(err, ErrForbidden):
		return "нет доступа"
	case errors.Is(err, store.ErrNotFound):
		return "не найдено"
	case errors.Is(err, ErrInvalid):
		return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	}
	return "внутренняя ошибка, см. журнал контроллера"
}

func (h *Server) routesPanel(mux *http.ServeMux) {
	mux.Handle("GET /static/", h.panel.static)
	mux.Handle("GET /login", securityHeaders(http.HandlerFunc(h.loginPage)))
	mux.Handle("POST /login", securityHeaders(http.HandlerFunc(h.loginSubmit)))
	mux.Handle("POST /logout", h.auth(h.logout))
	mux.Handle("GET /{$}", h.auth(func(w http.ResponseWriter, r *http.Request, _ *store.User, _ string) {
		http.Redirect(w, r, "/rooms", http.StatusSeeOther)
	}))
	mux.Handle("GET /rooms", h.auth(h.roomsPage))
	mux.Handle("POST /rooms", h.auth(h.roomCreate))
	mux.Handle("GET /rooms/{id}", h.auth(h.roomPage))
	mux.Handle("POST /rooms/{id}/settings", h.auth(h.roomSettings))
	mux.Handle("POST /rooms/{id}/delete", h.auth(h.roomDelete))
	mux.Handle("POST /rooms/{id}/invites", h.auth(h.inviteCreate))
	mux.Handle("POST /rooms/{id}/invites/{inv}/revoke", h.auth(h.inviteRevoke))
	mux.Handle("POST /rooms/{id}/members/{node}/update", h.auth(h.memberUpdate))
	mux.Handle("POST /rooms/{id}/members/{node}/{action}", h.auth(h.memberAction))
	mux.Handle("GET /users", h.auth(h.usersPage))
	mux.Handle("POST /users", h.auth(h.userCreate))
	mux.Handle("POST /users/{uid}/delete", h.auth(h.userDelete))
	mux.Handle("GET /account", h.auth(h.accountPage))
	mux.Handle("POST /account/password", h.auth(h.accountPassword))
	mux.Handle("GET /audit", h.auth(h.auditPage))
}

// ---- login ----

func (h *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "login", &view{Title: "Вход"})
}

func (h *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	addr := h.remoteIP(r).String()
	if !h.limiter.allowed(addr, time.Now()) {
		h.render(w, r, http.StatusTooManyRequests, "login", &view{Title: "Вход", Err: "Слишком много неудачных попыток. Подождите 10 минут."})
		return
	}
	token, err := h.svc.Login(r.Context(), strings.ToLower(strings.TrimSpace(r.PostFormValue("login"))), r.PostFormValue("password"))
	if err != nil {
		h.limiter.failed(addr, time.Now())
		h.render(w, r, http.StatusUnauthorized, "login", &view{Title: "Вход", Err: "Неверный логин или пароль"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: h.secureCookies(r), MaxAge: int(SessionTTL.Seconds()),
	})
	http.Redirect(w, r, "/rooms", http.StatusSeeOther)
}

func (h *Server) logout(w http.ResponseWriter, r *http.Request, _ *store.User, _ string) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.svc.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- rooms ----

func (h *Server) roomsPage(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	rooms, err := h.svc.Rooms(r.Context(), u)
	v := &view{User: u, CSRF: csrf, Title: "Комнаты", Data: rooms}
	if err != nil {
		v.Err = userMessage(err)
	}
	h.render(w, r, http.StatusOK, "rooms", v)
}

func (h *Server) roomCreate(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	room, err := h.svc.CreateRoom(r.Context(), u, r.PostFormValue("name"), r.PostFormValue("subnet"), r.PostFormValue("policy"))
	if err != nil {
		back(w, r, "/rooms", err, "")
		return
	}
	back(w, r, "/rooms/"+room.ID, nil, "Комната создана. Создайте приглашение, чтобы позвать участников.")
}

type roomData struct {
	*RoomView
	NewInvite   string
	NewInviteQR template.URL
}

func (h *Server) roomView(w http.ResponseWriter, r *http.Request, u *store.User, csrf string, extra func(*roomData)) {
	rv, err := h.svc.Room(r.Context(), u, r.PathValue("id"))
	if err != nil {
		back(w, r, "/rooms", err, "")
		return
	}
	d := &roomData{RoomView: rv}
	if extra != nil {
		extra(d)
	}
	h.render(w, r, http.StatusOK, "room", &view{User: u, CSRF: csrf, Title: rv.Room.Name, Data: d})
}

func (h *Server) roomPage(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	h.roomView(w, r, u, csrf, nil)
}

func (h *Server) roomSettings(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	id := r.PathValue("id")
	err := h.svc.UpdateRoom(r.Context(), u, id, r.PostFormValue("name"), r.PostFormValue("policy"))
	back(w, r, "/rooms/"+id, err, "Настройки сохранены")
}

func (h *Server) roomDelete(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	id := r.PathValue("id")
	if err := h.svc.DeleteRoom(r.Context(), u, id); err != nil {
		back(w, r, "/rooms/"+id, err, "")
		return
	}
	back(w, r, "/rooms", nil, "Комната удалена")
}

func (h *Server) inviteCreate(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	id := r.PathValue("id")
	uses, _ := strconv.Atoi(r.PostFormValue("uses"))
	hours, err := strconv.Atoi(r.PostFormValue("hours"))
	if err != nil {
		hours = 24
	}
	inv, err := h.svc.CreateInvite(r.Context(), u, h.publicURL(r), id, uses, time.Duration(hours)*time.Hour,
		r.PostFormValue("auto") == "on", r.PostFormValue("note"))
	if err != nil {
		back(w, r, "/rooms/"+id, err, "")
		return
	}
	link := inv.String()
	var qr template.URL
	if png, err := qrcode.Encode(link, qrcode.Medium, 320); err == nil {
		qr = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	// Rendered directly (not redirected): the token is shown once and never stored.
	h.roomView(w, r, u, csrf, func(d *roomData) { d.NewInvite, d.NewInviteQR = link, qr })
}

func (h *Server) inviteRevoke(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	id := r.PathValue("id")
	inv, err := strconv.ParseInt(r.PathValue("inv"), 10, 64)
	if err == nil {
		err = h.svc.RevokeInvite(r.Context(), u, id, inv)
	}
	back(w, r, "/rooms/"+id, err, "Приглашение отозвано")
}

func (h *Server) memberAction(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	id := r.PathValue("id")
	act := MemberAction(r.PathValue("action"))
	err := h.svc.MemberAction(r.Context(), u, id, r.PathValue("node"), act)
	msg := map[MemberAction]string{ActApprove: "Участник одобрен", ActBan: "Участник заблокирован", ActUnban: "Блокировка снята", ActKick: "Участник исключён"}[act]
	back(w, r, "/rooms/"+id, err, msg)
}

func (h *Server) memberUpdate(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	id := r.PathValue("id")
	err := h.svc.UpdateMember(r.Context(), u, id, r.PathValue("node"), r.PostFormValue("name"), r.PostFormValue("ip"), r.PostFormValue("tags"))
	back(w, r, "/rooms/"+id, err, "Участник обновлён")
}

// ---- users & account ----

func (h *Server) usersPage(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	users, err := h.svc.Users(r.Context(), u)
	if err != nil {
		back(w, r, "/rooms", err, "")
		return
	}
	h.render(w, r, http.StatusOK, "users", &view{User: u, CSRF: csrf, Title: "Пользователи", Data: users})
}

func (h *Server) userCreate(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	login := r.PostFormValue("login")
	pw := RandomPassword()
	if err := h.svc.CreateUser(r.Context(), u, login, pw, r.PostFormValue("admin") == "on"); err != nil {
		back(w, r, "/users", err, "")
		return
	}
	users, _ := h.svc.Users(r.Context(), u)
	h.render(w, r, http.StatusOK, "users", &view{User: u, CSRF: csrf, Title: "Пользователи", Data: users,
		OK: fmt.Sprintf("Пользователь %s создан. Пароль (показывается один раз): %s", strings.ToLower(strings.TrimSpace(login)), pw)})
}

func (h *Server) userDelete(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	uid, err := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	if err == nil {
		err = h.svc.DeleteUser(r.Context(), u, uid)
	}
	back(w, r, "/users", err, "Пользователь удалён")
}

func (h *Server) accountPage(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	h.render(w, r, http.StatusOK, "account", &view{User: u, CSRF: csrf, Title: "Мой аккаунт"})
}

func (h *Server) accountPassword(w http.ResponseWriter, r *http.Request, u *store.User, _ string) {
	if r.PostFormValue("new") != r.PostFormValue("new2") {
		back(w, r, "/account", invalid("новые пароли не совпадают"), "")
		return
	}
	err := h.svc.ChangePassword(r.Context(), u, r.PostFormValue("old"), r.PostFormValue("new"))
	back(w, r, "/account", err, "Пароль изменён")
}

func (h *Server) auditPage(w http.ResponseWriter, r *http.Request, u *store.User, csrf string) {
	entries, err := h.svc.Audit(r.Context(), u, 300)
	if err != nil {
		back(w, r, "/rooms", err, "")
		return
	}
	h.render(w, r, http.StatusOK, "audit", &view{User: u, CSRF: csrf, Title: "Журнал", Data: entries})
}
