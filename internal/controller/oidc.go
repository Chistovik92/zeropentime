// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig turns on sign-in through an OpenID Connect provider (Google,
// Keycloak, Authentik, ...): the authorization code flow with PKCE.
type OIDCConfig struct {
	Issuer       string // discovery at Issuer/.well-known/openid-configuration
	ClientID     string
	ClientSecret string
	Name         string // the button label, e.g. "Google"
}

// Enabled reports whether OIDC is configured.
func (c OIDCConfig) Enabled() bool { return c.Issuer != "" && c.ClientID != "" }

type oidcClient struct {
	cfg  OIDCConfig
	http *http.Client

	mu   sync.Mutex
	meta *oidcMeta
	keys map[string]crypto.PublicKey // by kid
	got  time.Time
}

type oidcMeta struct {
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
	Issuer   string `json:"issuer"`
}

func newOIDC(cfg OIDCConfig) *oidcClient {
	return &oidcClient{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

func (o *oidcClient) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := o.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("oidc: %s: %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

func (o *oidcClient) discover(ctx context.Context) (*oidcMeta, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.meta != nil {
		return o.meta, nil
	}
	var m oidcMeta
	if err := o.getJSON(ctx, strings.TrimRight(o.cfg.Issuer, "/")+"/.well-known/openid-configuration", &m); err != nil {
		return nil, err
	}
	if m.Issuer != o.cfg.Issuer && m.Issuer != strings.TrimRight(o.cfg.Issuer, "/") {
		return nil, fmt.Errorf("oidc: provider says its issuer is %q, configured %q", m.Issuer, o.cfg.Issuer)
	}
	if m.AuthURL == "" || m.TokenURL == "" || m.JWKSURL == "" {
		return nil, errors.New("oidc: incomplete discovery document")
	}
	o.meta = &m
	return o.meta, nil
}

type jwk struct {
	Kty, Kid, Crv, N, E, X, Y string
}

func b64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b
}

// key returns the signing key kid, refreshing the key set (at most once a
// minute) when it is unknown.
func (o *oidcClient) key(ctx context.Context, m *oidcMeta, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if k, ok := o.keys[kid]; ok {
		return k, nil
	}
	if o.keys != nil && time.Since(o.got) < time.Minute {
		return nil, errors.New("oidc: unknown signing key")
	}
	var set struct{ Keys []jwk }
	if err := o.getJSON(ctx, m.JWKSURL, &set); err != nil {
		return nil, err
	}
	o.keys, o.got = map[string]crypto.PublicKey{}, time.Now()
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, e := new(big.Int).SetBytes(b64(k.N)), new(big.Int).SetBytes(b64(k.E))
			if n.BitLen() >= 2048 && e.IsInt64() && e.Int64() > 2 {
				o.keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
			}
		case "EC":
			if k.Crv == "P-256" {
				x, y := new(big.Int).SetBytes(b64(k.X)), new(big.Int).SetBytes(b64(k.Y))
				if elliptic.P256().IsOnCurve(x, y) {
					o.keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
				}
			}
		}
	}
	if k, ok := o.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("oidc: unknown signing key")
}

// Claims are the ID token claims the panel needs.
type Claims struct {
	Email    string
	Verified bool
}

// verify checks an ID token: signature (RS256 or ES256), issuer, audience,
// expiry and nonce.
func (o *oidcClient) verify(ctx context.Context, m *oidcMeta, token, nonce string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed token")
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(b64(parts[0]), &hdr) != nil {
		return nil, errors.New("oidc: malformed token header")
	}
	key, err := o.key(ctx, m, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig := b64(parts[2])
	switch pk := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" || rsa.VerifyPKCS1v15(pk, crypto.SHA256, sum[:], sig) != nil {
			return nil, errors.New("oidc: bad token signature")
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(pk, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("oidc: bad token signature")
		}
	default:
		return nil, errors.New("oidc: unsupported key")
	}
	var c struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Exp           float64         `json:"exp"`
		Nonce         string          `json:"nonce"`
		Email         string          `json:"email"`
		EmailVerified any             `json:"email_verified"`
	}
	if json.Unmarshal(b64(parts[1]), &c) != nil {
		return nil, errors.New("oidc: malformed token claims")
	}
	if c.Iss != m.Issuer {
		return nil, errors.New("oidc: wrong issuer")
	}
	var auds []string
	if json.Unmarshal(c.Aud, &auds) != nil {
		var one string
		json.Unmarshal(c.Aud, &one)
		auds = []string{one}
	}
	okAud := false
	for _, a := range auds {
		okAud = okAud || a == o.cfg.ClientID
	}
	if !okAud {
		return nil, errors.New("oidc: token is for another client")
	}
	if float64(now.Unix()) >= c.Exp {
		return nil, errors.New("oidc: token expired")
	}
	if c.Nonce == "" || c.Nonce != nonce {
		return nil, errors.New("oidc: wrong nonce")
	}
	v := c.EmailVerified == true || c.EmailVerified == "true"
	return &Claims{Email: strings.ToLower(strings.TrimSpace(c.Email)), Verified: v}, nil
}

func randomURLToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authURL builds the redirect to the provider.
func (o *oidcClient) authURL(ctx context.Context, redirect, state, nonce, verifier string) (string, error) {
	m, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {o.cfg.ClientID}, "redirect_uri": {redirect},
		"scope": {"openid email"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}
	return m.AuthURL + "?" + q.Encode(), nil
}

// exchange trades the code for an ID token and verifies it.
func (o *oidcClient) exchange(ctx context.Context, redirect, code, nonce, verifier string) (*Claims, error) {
	m, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {o.cfg.ClientID}, "client_secret": {o.cfg.ClientSecret}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := o.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tok) != nil || tok.IDToken == "" {
		return nil, fmt.Errorf("oidc: token endpoint: %s", res.Status)
	}
	return o.verify(ctx, m, tok.IDToken, nonce, time.Now())
}
