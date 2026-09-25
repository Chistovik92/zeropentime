// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc, err := NewService(st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CreateUser(context.Background(), nil, "admin", "correct horse battery", true); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{}, svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, svc
}

type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newBrowser(t *testing.T, base string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: base, c: &http.Client{Jar: jar}}
}

func (b *browser) get(path string) (int, string) {
	b.t.Helper()
	res, err := b.c.Get(b.base + path)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func (b *browser) post(path string, form url.Values) (int, string) {
	b.t.Helper()
	res, err := b.c.PostForm(b.base+path, form)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) csrf(page string) string {
	b.t.Helper()
	_, body := b.get(page)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no csrf token on %s", page)
	}
	return m[1]
}

func TestPanelLoginAndPages(t *testing.T) {
	hs, _ := newTestServer(t)
	b := newBrowser(t, hs.URL)

	if code, body := b.get("/rooms"); code != 200 || !strings.Contains(body, "Вход") {
		t.Fatalf("anonymous user not sent to login: %d", code)
	}
	if code, body := b.post("/login", url.Values{"login": {"admin"}, "password": {"wrong password!"}}); code != 401 || !strings.Contains(body, "Неверный") {
		t.Fatalf("bad password: %d", code)
	}
	if code, _ := b.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}}); code != 200 {
		t.Fatalf("login: %d", code)
	}

	csrf := b.csrf("/rooms")
	code, body := b.post("/rooms", url.Values{"csrf": {csrf}, "name": {"Игры <script>"}, "policy": {"manual"}})
	if code != 200 || !strings.Contains(body, "Комната создана") {
		t.Fatalf("create room: %d %s", code, body)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "Игры &lt;script&gt;") {
		t.Fatal("room name is not HTML-escaped")
	}
	roomPath := regexp.MustCompile(`/rooms/[0-9a-f]{32}`).FindString(body)
	if roomPath == "" {
		t.Fatal("no room link")
	}

	code, body = b.post(roomPath+"/invites", url.Values{"csrf": {csrf}, "uses": {"1"}, "hours": {"24"}, "note": {"для Пети"}})
	if code != 200 || !strings.Contains(body, `zpt join "zpt://join?`) || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatalf("invite not shown with QR: %d", code)
	}

	for _, p := range []string{"/rooms", roomPath, "/users", "/account", "/audit", "/static/style.css", "/static/app.js"} {
		if code, _ := b.get(p); code != 200 {
			t.Errorf("GET %s: %d", p, code)
		}
	}
}

func TestPanelCSRFAndHeaders(t *testing.T) {
	hs, _ := newTestServer(t)
	b := newBrowser(t, hs.URL)
	b.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}})

	if code, _ := b.post("/rooms", url.Values{"name": {"x"}, "policy": {"manual"}}); code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: %d, want 403", code)
	}
	if code, _ := b.post("/rooms", url.Values{"csrf": {"forged"}, "name": {"x"}, "policy": {"manual"}}); code != http.StatusForbidden {
		t.Fatalf("POST with forged CSRF token: %d, want 403", code)
	}

	res, err := b.c.Get(hs.URL + "/rooms")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for h, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	} {
		if !strings.Contains(res.Header.Get(h), want) {
			t.Errorf("%s = %q", h, res.Header.Get(h))
		}
	}
	for _, c := range b.c.Jar.Cookies(res.Request.URL) {
		if c.Name == sessionCookie && c.Value == "" {
			t.Error("empty session cookie")
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	hs, _ := newTestServer(t)
	b := newBrowser(t, hs.URL)
	for range 10 {
		b.post("/login", url.Values{"login": {"admin"}, "password": {"nope nope nope"}})
	}
	if code, _ := b.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}}); code != http.StatusTooManyRequests {
		t.Fatalf("11th attempt: %d, want 429", code)
	}
}

func TestNonOwnerCannotManageRoom(t *testing.T) {
	_, svc := newTestServer(t)
	ctx := context.Background()
	if err := svc.CreateUser(ctx, nil, "bob", "bobs long password", false); err != nil {
		t.Fatal(err)
	}
	session := func(login, pw string) *store.User {
		tok, err := svc.Login(ctx, login, pw)
		if err != nil {
			t.Fatal(err)
		}
		u, _, _ := svc.Session(ctx, tok)
		return u
	}
	admin, bob := session("admin", "correct horse battery"), session("bob", "bobs long password")
	r, err := svc.CreateRoom(ctx, admin, "admins", "", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Room(ctx, bob, r.ID); err != ErrForbidden {
		t.Fatalf("bob read admin's room: %v", err)
	}
	if _, err := svc.CreateInvite(ctx, bob, "http://x", r.ID, 1, 3600e9, true, ""); err != ErrForbidden {
		t.Fatalf("bob created an invite in admin's room: %v", err)
	}
	if rooms, _ := svc.Rooms(ctx, bob); len(rooms) != 0 {
		t.Fatal("bob sees admin's rooms")
	}
	if _, err := svc.Users(ctx, bob); err != ErrForbidden {
		t.Fatal("non-admin listed users")
	}
}
