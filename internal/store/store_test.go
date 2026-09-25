// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
)

// A database created by 0.1.x (schema version 1) is upgraded in place and
// keeps its data.
func TestMigrateFromV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(id, ed_key, box_key, name, last_seen, created_at) VALUES('n1', x'01', x'02', 'old node', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	err = st.Tx(context.Background(), func(tx *Tx) error {
		n, err := tx.NodeByID("n1")
		if err != nil {
			return err
		}
		if n.Name != "old node" || n.NAT != "" || n.Reflexive != nil {
			t.Errorf("migrated node: %+v", n)
		}
		_, err = tx.UpdateNodeEndpoints("n1", Reach{NAT: "cone", Reflexive: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:5")}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var v int
	st.db.QueryRow(`SELECT value FROM meta WHERE key = 'schema'`).Scan(&v)
	if v != SchemaVersion {
		t.Fatalf("schema %d, want %d", v, SchemaVersion)
	}
	st.Close()

	// Reopening a migrated database is a no-op.
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
}

func TestRefuseNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.db.Exec(`UPDATE meta SET value = 999 WHERE key = 'schema'`)
	st.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("opened a database from a newer version")
	}
}
