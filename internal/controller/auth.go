// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/Chistovik92/zeropentime/internal/store"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32

	SessionTTL     = 7 * 24 * time.Hour
	MinPasswordLen = 10
)

// HashPassword hashes a password with Argon2id.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// CheckPassword verifies a password against HashPassword output.
func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces a minimum strength.
func ValidatePassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return invalid("пароль должен быть не короче %d символов", MinPasswordLen)
	}
	return nil
}

// RandomPassword generates a password for new accounts.
func RandomPassword() string {
	b := make([]byte, 15)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

// ErrBadLogin is returned for any login failure.
var ErrBadLogin = errors.New("wrong login or password")

// Login checks credentials and creates a session. It returns the session token.
func (s *Service) Login(ctx context.Context, login, pw string) (string, error) {
	var u *store.User
	err := s.st.Read(ctx, func(tx *store.Tx) (err error) { u, err = tx.UserByLogin(login); return })
	if err != nil {
		// Spend the same time as a real check to avoid revealing logins.
		CheckPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g", pw)
		return "", ErrBadLogin
	}
	if !CheckPassword(u.PassHash, pw) {
		return "", ErrBadLogin
	}
	token := randomToken()
	err = s.st.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.CreateSession(tokenHash(token), u.ID, randomToken(), s.now().Add(SessionTTL)); err != nil {
			return err
		}
		return tx.Audit(u.Login, "user.login", u.Login, "")
	})
	return token, err
}

// Session resolves a session token.
func (s *Service) Session(ctx context.Context, token string) (*store.User, *store.Session, error) {
	var u *store.User
	var sess *store.Session
	err := s.st.Read(ctx, func(tx *store.Tx) error {
		var err error
		if sess, err = tx.SessionByToken(tokenHash(token)); err != nil {
			return err
		}
		if s.now().After(sess.Expires) {
			return store.ErrNotFound
		}
		u, err = tx.UserByID(sess.UserID)
		return err
	})
	return u, sess, err
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.st.Tx(ctx, func(tx *store.Tx) error { return tx.DeleteSession(tokenHash(token)) })
}

// ---- users ----

// UserByLogin looks up an account (for the CLI).
func (s *Service) UserByLogin(ctx context.Context, login string) (u *store.User, err error) {
	err = s.st.Read(ctx, func(tx *store.Tx) error { u, err = tx.UserByLogin(strings.ToLower(login)); return err })
	return
}

// ValidateLogin checks a login name.
func ValidateLogin(login string) (string, error) {
	login = strings.TrimSpace(strings.ToLower(login))
	if len(login) < 2 || len(login) > 32 {
		return "", invalid("логин должен быть от 2 до 32 символов")
	}
	for _, r := range login {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", invalid("в логине допустимы a-z, 0-9, '-', '_', '.'")
		}
	}
	return login, nil
}

// CreateUser adds an account. actor is nil when called from the CLI.
func (s *Service) CreateUser(ctx context.Context, actor *store.User, login, pw string, admin bool) error {
	if actor != nil && !actor.IsAdmin {
		return ErrForbidden
	}
	login, err := ValidateLogin(login)
	if err != nil {
		return err
	}
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return err
	}
	who := "cli"
	if actor != nil {
		who = actor.Login
	}
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.UserByLogin(login); err == nil {
			return invalid("пользователь %s уже существует", login)
		}
		if _, err := tx.CreateUser(login, hash, admin); err != nil {
			return err
		}
		return tx.Audit(who, "user.create", login, fmt.Sprintf("admin=%v", admin))
	})
}

func (s *Service) Users(ctx context.Context, actor *store.User) (users []store.User, err error) {
	if !actor.IsAdmin {
		return nil, ErrForbidden
	}
	err = s.st.Read(ctx, func(tx *store.Tx) error { users, err = tx.ListUsers(); return err })
	return
}

func (s *Service) DeleteUser(ctx context.Context, actor *store.User, id int64) error {
	if !actor.IsAdmin || actor.ID == id {
		return ErrForbidden
	}
	return s.change(ctx, func(tx *store.Tx) error {
		u, err := tx.UserByID(id)
		if err != nil {
			return err
		}
		rooms, err := tx.ListRooms(id)
		if err != nil {
			return err
		}
		if len(rooms) > 0 {
			return invalid("у пользователя %s есть комнаты (%d), сначала удалите или передайте их", u.Login, len(rooms))
		}
		if err := tx.DeleteUser(id); err != nil {
			return err
		}
		return tx.Audit(actor.Login, "user.delete", u.Login, "")
	})
}

// ChangePassword changes the actor's own password.
func (s *Service) ChangePassword(ctx context.Context, actor *store.User, oldPw, newPw string) error {
	if !CheckPassword(actor.PassHash, oldPw) {
		return invalid("текущий пароль неверен")
	}
	if err := ValidatePassword(newPw); err != nil {
		return err
	}
	hash, err := HashPassword(newPw)
	if err != nil {
		return err
	}
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		if err := tx.SetPassword(actor.ID, hash); err != nil {
			return err
		}
		return tx.Audit(actor.Login, "user.password", actor.Login, "")
	})
}

// SetPassword sets a password from the CLI (recovery).
func (s *Service) SetPassword(ctx context.Context, login, pw string) error {
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return err
	}
	return s.st.Tx(ctx, func(tx *store.Tx) error {
		u, err := tx.UserByLogin(login)
		if err != nil {
			return err
		}
		if err := tx.SetPassword(u.ID, hash); err != nil {
			return err
		}
		return tx.Audit("cli", "user.password", login, "")
	})
}

func (s *Service) Audit(ctx context.Context, actor *store.User, limit int) (out []store.AuditEntry, err error) {
	if !actor.IsAdmin {
		return nil, ErrForbidden
	}
	err = s.st.Read(ctx, func(tx *store.Tx) error { out, err = tx.ListAudit(limit); return err })
	return
}

// loginLimiter slows down password guessing: at most 10 failures per
// address per 10 minutes.
type loginLimiter struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

func (l *loginLimiter) allowed(addr string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var recent []time.Time
	for _, t := range l.fail[addr] {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	if l.fail == nil {
		l.fail = map[string][]time.Time{}
	}
	l.fail[addr] = recent
	return len(recent) < 10
}

func (l *loginLimiter) failed(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail == nil {
		l.fail = map[string][]time.Time{}
	}
	l.fail[addr] = append(l.fail[addr], now)
}
