// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is a minimal OpenID provider: discovery, keys, authorize, token.
type fakeIdP struct {
	*httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	email    string
	verified bool
	nonces   map[string]string // code -> nonce
	aud      string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, nonces: map[string]string{}, verified: true, aud: "zpt"}
	mux := http.NewServeMux()
	enc := base64.RawURLEncoding.EncodeToString
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": p.URL, "authorization_endpoint": p.URL + "/auth", "token_endpoint": p.URL + "/token", "jwks_uri": p.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "no PKCE", 400)
			return
		}
		code := randomURLToken()
		p.mu.Lock()
		p.nonces[code] = q.Get("nonce") + "|" + q.Get("code_challenge")
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		saved := p.nonces[r.PostFormValue("code")]
		p.mu.Unlock()
		nonce, challenge, _ := strings.Cut(saved, "|")
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if saved == "" || enc(sum[:]) != challenge || r.PostFormValue("client_secret") != "s3cret" {
			http.Error(w, "bad", 400)
			return
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": p.URL, "aud": p.aud, "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce,
			"email": p.email, "email_verified": p.verified,
		})
		hdr := enc([]byte(`{"alg":"RS256","kid":"k1"}`))
		body := hdr + "." + enc(claims)
		h := sha256.Sum256([]byte(body))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		json.NewEncoder(w).Encode(map[string]string{"id_token": body + "." + enc(sig)})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func TestOIDCLogin(t *testing.T) {
	idp := newFakeIdP(t)
	hs, svc := newTestServerCfg(t, Config{OIDC: OIDCConfig{Issuer: idp.URL, ClientID: "zpt", ClientSecret: "s3cret", Name: "Fake"}})
	ctx := context.Background()
	if err := svc.BindOIDCEmail(ctx, "admin", "Admin@Example.org"); err != nil {
		t.Fatal(err)
	}

	b := newBrowser(t, hs.URL)
	if _, page := b.get("/login"); !strings.Contains(page, "Войти через Fake") {
		t.Fatal("no OIDC button on the login page")
	}
	try := func(email string, verified bool) (int, string) {
		idp.email, idp.verified = email, verified
		b := newBrowser(t, hs.URL)
		return b.get("/login/oidc") // follows the redirects through the provider
	}
	if code, body := try("admin@example.org", true); code != 200 || !strings.Contains(body, "Комнаты") {
		t.Fatalf("OIDC login: %d %.200s", code, body)
	}
	if code, body := try("nobody@example.org", true); code != 401 || !strings.Contains(body, "не привязан") {
		t.Fatalf("unbound email: %d %.200s", code, body)
	}
	if code, _ := try("admin@example.org", false); code != 401 {
		t.Fatalf("unverified email accepted: %d", code)
	}
	idp.aud = "another-client"
	if code, _ := try("admin@example.org", true); code != 401 {
		t.Fatalf("token for another client accepted: %d", code)
	}
	idp.aud = "zpt"

	// A callback without the cookie of the start of the flow is refused.
	fresh := newBrowser(t, hs.URL)
	if code, _ := fresh.get("/login/oidc/callback?code=x&state=y"); code != 401 {
		t.Fatalf("callback without a started flow: %d", code)
	}
}

func TestOIDCOffByDefault(t *testing.T) {
	hs, _ := newTestServer(t)
	if code, _ := newBrowser(t, hs.URL).get("/login/oidc"); code != 404 {
		t.Fatalf("OIDC route without config: %d", code)
	}
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	idp := newFakeIdP(t)
	o := newOIDC(OIDCConfig{Issuer: idp.URL, ClientID: "zpt"})
	m, err := o.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{"iss": idp.URL, "aud": "zpt", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "n", "email": "a@b", "email_verified": true})
	forged := enc([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc(claims) + "." + enc(make([]byte, 256))
	if _, err := o.verify(context.Background(), m, forged, "n", time.Now()); err == nil {
		t.Fatal("forged signature accepted")
	}
	none := enc([]byte(`{"alg":"none","kid":"k1"}`)) + "." + enc(claims) + "."
	if _, err := o.verify(context.Background(), m, none, "n", time.Now()); err == nil {
		t.Fatal("alg none accepted")
	}
}
