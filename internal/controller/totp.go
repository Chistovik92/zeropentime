// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/store"
)

// Time-based one-time codes, RFC 6238 (HMAC-SHA1, 30 s, 6 digits) — what
// every authenticator app understands.
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // steps accepted before and after the current one
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret.
func NewTOTPSecret() []byte {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// TOTPSecretText is the secret as an authenticator app expects it.
func TOTPSecretText(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURI is the otpauth:// link (shown as a QR code) for an authenticator.
func TOTPURI(issuer, login string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", TOTPSecretText(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+login) + "?" + v.Encode()
}

func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, n%1_000_000)
}

// checkTOTP tests code against the steps around now and returns the step
// it matched, or 0. lastUsed is the last accepted step: it and earlier
// ones are refused so a code cannot be replayed.
func checkTOTP(secret []byte, code string, now time.Time, lastUsed int64) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0
	}
	cur := now.Unix() / totpPeriod
	var hit int64
	for d := int64(-totpSkew); d <= totpSkew; d++ { // no early exit: constant work
		step := cur + d
		if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(secret, step))) == 1 && step > lastUsed && step > hit {
			hit = step
		}
	}
	return hit
}

// checkSecondFactor verifies a one-time code and burns its time step.
func (s *Service) checkSecondFactor(ctx context.Context, uid int64, code string) error {
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		secret, last, err := tx.TOTP(uid)
		if err != nil {
			return err
		}
		step := checkTOTP(secret, code, s.now(), last)
		if len(secret) == 0 || step == 0 {
			return ErrBadLogin
		}
		if ok, err := tx.UseTOTPStep(uid, step); err != nil || !ok {
			if err == nil {
				err = ErrBadLogin
			}
			return err
		}
		return nil
	})
}

// EnableTOTP turns 2FA on for the actor after they prove the app works by
// entering a current code for the secret.
func (s *Service) EnableTOTP(ctx context.Context, actor *store.User, secret []byte, code string) error {
	step := checkTOTP(secret, code, s.now(), 0)
	if step == 0 {
		return invalid("код не подошёл: проверьте время на телефоне и попробуйте снова")
	}
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.SetTOTP(actor.ID, secret); err != nil {
			return err
		}
		if _, err := tx.UseTOTPStep(actor.ID, step); err != nil {
			return err
		}
		return tx.Audit(actor.Login, "user.totp.on", actor.Login, "")
	})
}

// DisableTOTP turns 2FA off for the actor; it needs the password.
func (s *Service) DisableTOTP(ctx context.Context, actor *store.User, pw string) error {
	if !CheckPassword(actor.PassHash, pw) {
		return invalid("неверный пароль")
	}
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.SetTOTP(actor.ID, nil); err != nil {
			return err
		}
		return tx.Audit(actor.Login, "user.totp.off", actor.Login, "")
	})
}

// ResetTOTP turns 2FA off from the CLI (a lost phone).
func (s *Service) ResetTOTP(ctx context.Context, login string) error {
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.UserByLogin(login)
		if err != nil {
			return err
		}
		if err := tx.SetTOTP(u.ID, nil); err != nil {
			return err
		}
		return tx.Audit("cli", "user.totp.off", login, "")
	})
}
