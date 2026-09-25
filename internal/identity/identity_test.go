// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "node.key")
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err == nil {
		t.Fatal("Save overwrote an existing key")
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.NodeID() != id.NodeID() || len(id.NodeID()) != 16 {
		t.Fatalf("node id mismatch or bad length: %q vs %q", back.NodeID(), id.NodeID())
	}
}

func TestRoomKeys(t *testing.T) {
	id, _ := Generate()
	other, _ := Generate()

	a1, _ := id.RoomKey("room-a")
	a2, _ := id.RoomKey("room-a")
	b, _ := id.RoomKey("room-b")
	o, _ := other.RoomKey("room-a")

	if a1 != a2 {
		t.Fatal("room key is not deterministic")
	}
	if a1 == b || a1 == o {
		t.Fatal("room keys must differ between rooms and nodes")
	}
	if a1[0]&7 != 0 || a1[31]&128 != 0 || a1[31]&64 == 0 {
		t.Fatal("key is not clamped")
	}
	if a1.Public() == b.Public() {
		t.Fatal("public keys collide")
	}
	parsed, err := ParseKey(a1.Public().String())
	if err != nil || parsed != a1.Public() {
		t.Fatalf("key text roundtrip failed: %v", err)
	}
}
