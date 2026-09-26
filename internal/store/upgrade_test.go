// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/testutil"
)

// oldDB builds a database stuck at schema version v with a user, a room,
// a node and a member written with the columns of the base schema.
func oldDB(t *testing.T, v int) string {
	t.Helper()
	path := filepath.Join(testutil.TempDir(t), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < v-1; i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			t.Fatalf("migration %d: %v", i+2, err)
		}
	}
	for _, q := range []string{
		`UPDATE meta SET value = ` + itoa(v) + ` WHERE key = 'schema'`,
		`INSERT INTO users(id, login, pass_hash, is_admin, created_at) VALUES(1, 'admin', 'x', 1, 1)`,
		`INSERT INTO rooms(id, name, subnet, secret, sign_key, owner_id, created_at) VALUES('r1', 'Дом', '10.9.9.0/24', x'aa', x'bb', 1, 1)`,
		`INSERT INTO nodes(id, ed_key, box_key, name, last_seen, created_at) VALUES('n1', x'01', x'02', 'laptop', 1, 1)`,
		`INSERT INTO members(room_id, node_id, name, wg_key, ip, status, created_at) VALUES('r1', 'n1', 'laptop', x'03', '10.9.9.1', 'active', 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func itoa(v int) string { return string(rune('0'+v/10)) + string(rune('0'+v%10)) }

// Every released schema version upgrades to the current one keeping the
// data: controllers of any earlier version can be updated in place.
func TestUpgradeFromEveryVersion(t *testing.T) {
	for v := 1; v <= SchemaVersion; v++ {
		st, err := Open(oldDB(t, v))
		if err != nil {
			t.Fatalf("from version %d: %v", v, err)
		}
		err = st.Read(context.Background(), func(tx *Tx) error {
			r, err := tx.RoomByID("r1")
			if err != nil {
				return err
			}
			if r.Name != "Дом" || !bytes.Equal(r.SignKey, []byte{0xbb}) || r.Broadcast != "on" {
				t.Errorf("from %d: room %+v", v, r)
			}
			m, err := tx.Member("r1", "n1")
			if err != nil {
				return err
			}
			if m.Name != "laptop" || m.IP.String() != "10.9.9.1" || m.Exit || m.UseExit != "" {
				t.Errorf("from %d: member %+v", v, m)
			}
			return nil
		})
		st.Close()
		if err != nil {
			t.Fatalf("from %d: %v", v, err)
		}
	}
}

func TestKEK(t *testing.T) {
	dir := testutil.TempDir(t)
	kekPath := filepath.Join(dir, "kek")
	if err := NewKEKFile(kekPath); err != nil {
		t.Fatal(err)
	}
	if err := NewKEKFile(kekPath); err == nil {
		t.Fatal("overwrote an existing KEK")
	}
	kek, err := LoadKEK(kekPath)
	if err != nil {
		t.Fatal(err)
	}
	path := oldDB(t, SchemaVersion) // plaintext secrets, as before the KEK
	st, err := OpenOptions(path, Options{KEK: kek})
	if err != nil {
		t.Fatal(err)
	}
	st.Tx(context.Background(), func(tx *Tx) error { return tx.SetSetting("relay_key", []byte("secret key")) })
	st.Close()

	raw, _ := sql.Open("sqlite", "file:"+path)
	var sign, setting []byte
	raw.QueryRow(`SELECT sign_key FROM rooms WHERE id = 'r1'`).Scan(&sign)
	raw.QueryRow(`SELECT value FROM settings WHERE key = 'relay_key'`).Scan(&setting)
	raw.Close()
	if !isSealed(sign) || !isSealed(setting) || bytes.Contains(setting, []byte("secret key")) {
		t.Fatalf("secrets are not sealed on disk: %q %q", sign, setting)
	}

	if _, err := Open(path); !errors.Is(err, ErrNeedKEK) {
		t.Fatalf("opened sealed database without KEK: %v", err)
	}
	wrong := bytes.Repeat([]byte{7}, KEKSize)
	if _, err := OpenOptions(path, Options{KEK: wrong}); err == nil {
		t.Fatal("opened with a wrong KEK")
	}
	st, err = OpenOptions(path, Options{KEK: kek})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	err = st.Read(context.Background(), func(tx *Tx) error {
		r, err := tx.RoomByID("r1")
		if err != nil {
			return err
		}
		v, err := tx.Setting("relay_key")
		if err != nil {
			return err
		}
		if !bytes.Equal(r.SignKey, []byte{0xbb}) || !bytes.Equal(r.Secret, []byte{0xaa}) || string(v) != "secret key" {
			t.Errorf("unsealed: %x %x %q", r.SignKey, r.Secret, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A backup is a working copy and keeps the secrets sealed.
	bak := filepath.Join(dir, "backup.db")
	if err := st.Backup(context.Background(), bak); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bak); !errors.Is(err, ErrNeedKEK) {
		t.Fatalf("backup without KEK: %v", err)
	}
	b, err := OpenOptions(bak, Options{KEK: kek})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}
