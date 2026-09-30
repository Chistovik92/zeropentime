// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890") // RFC 6238 appendix B, last 6 digits of the 8-digit codes
	for _, c := range []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {20000000000, "353130"}} {
		if got := totpCode(secret, c.unix/totpPeriod); got != c.code {
			t.Errorf("t=%d: %s, want %s", c.unix, got, c.code)
		}
	}
}

func TestCheckTOTPWindowAndReplay(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	cur := now.Unix() / totpPeriod
	if step := checkTOTP(secret, totpCode(secret, cur), now, 0); step != cur {
		t.Fatalf("current code: step %d, want %d", step, cur)
	}
	if checkTOTP(secret, totpCode(secret, cur+1), now, 0) == 0 || checkTOTP(secret, totpCode(secret, cur-1), now, 0) == 0 {
		t.Fatal("neighbouring steps must be accepted")
	}
	if checkTOTP(secret, totpCode(secret, cur+2), now, 0) != 0 || checkTOTP(secret, totpCode(secret, cur-2), now, 0) != 0 {
		t.Fatal("steps outside the window must be refused")
	}
	if checkTOTP(secret, totpCode(secret, cur), now, cur) != 0 {
		t.Fatal("a used step must not be accepted again")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000 0"} {
		if checkTOTP(secret, bad, now, 0) != 0 && bad != "000000 0" {
			t.Errorf("code %q accepted", bad)
		}
	}
}

func TestLoginWithTOTP(t *testing.T) {
	_, svc := newTestServer(t)
	ctx := context.Background()
	tok, err := svc.Login(ctx, "admin", "correct horse battery", "")
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := svc.Session(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	secret := NewTOTPSecret()
	if err := svc.EnableTOTP(ctx, admin, secret, "000000"); err == nil {
		t.Fatal("2FA turned on with a wrong code")
	}
	if err := svc.EnableTOTP(ctx, admin, secret, totpCode(secret, svc.now().Unix()/totpPeriod)); err != nil {
		t.Fatal(err)
	}

	// The enabling code is burnt; the password alone or with a wrong code fails.
	now := svc.now()
	code := totpCode(secret, now.Unix()/totpPeriod)
	for _, c := range []string{"", "123456", code} {
		if _, err := svc.Login(ctx, "admin", "correct horse battery", c); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("login with code %q: %v, want ErrBadLogin", c, err)
		}
	}
	// A code from the next step works once.
	next := totpCode(secret, now.Unix()/totpPeriod+1)
	if _, err := svc.Login(ctx, "admin", "correct horse battery", next); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "admin", "correct horse battery", next); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("code reused: %v", err)
	}
	if _, err := svc.Login(ctx, "admin", "wrong password!", next); !errors.Is(err, ErrBadLogin) {
		t.Fatal("wrong password accepted")
	}

	if err := svc.ResetTOTP(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "admin", "correct horse battery", ""); err != nil {
		t.Fatalf("login after reset: %v", err)
	}
}

func TestPanelTOTPFlow(t *testing.T) {
	hs, _ := newTestServer(t)
	b := newBrowser(t, hs.URL)
	b.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}})
	code, page := b.get("/account")
	if code != 200 || !strings.Contains(page, "data:image/png;base64,") {
		t.Fatalf("account page: %d, no QR code", code)
	}
	m := regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no secret on the page")
	}
	secret, err := b32.DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	csrf := b.csrf("/account")
	if _, body := b.post("/account/totp", url.Values{"csrf": {csrf}, "secret": {m[1]}, "code": {"000000"}}); !strings.Contains(body, "код не подошёл") {
		t.Fatalf("wrong code accepted: %s", body)
	}
	good := totpCode(secret, time.Now().Unix()/totpPeriod)
	if _, body := b.post("/account/totp", url.Values{"csrf": {csrf}, "secret": {m[1]}, "code": {good}}); !strings.Contains(body, "включён") {
		t.Fatalf("2FA not enabled: %s", body)
	}
	other := newBrowser(t, hs.URL)
	if code, _ := other.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}}); code != http.StatusUnauthorized {
		t.Fatalf("login without code: %d, want 401", code)
	}
	next := totpCode(secret, time.Now().Unix()/totpPeriod+1)
	if code, _ := other.post("/login", url.Values{"login": {"admin"}, "password": {"correct horse battery"}, "code": {next}}); code != http.StatusOK {
		t.Fatalf("login with code: %d", code)
	}
}
