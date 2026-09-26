// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/control"
)

func find(items []Item, prefix string) *Item {
	for i := range items {
		if strings.HasPrefix(items[i].Title, prefix) {
			return &items[i]
		}
	}
	return nil
}

func TestModelNodeDown(t *testing.T) {
	m := BuildModel(nil, errors.New("узел не запущен"))
	if m.State != "down" || find(m.Menu, "Вступить по приглашению") == nil || find(m.Menu, "Закрыть трей") == nil {
		t.Fatalf("%+v", m)
	}
}

func TestModelRooms(t *testing.T) {
	s := &control.Status{
		Rooms: []control.Room{{
			Name: "game", ID: "r1", Address: netip.MustParsePrefix("10.7.0.2/24"),
			Peers: []control.Peer{
				{Name: "bob", IP: netip.MustParseAddr("10.7.0.3"), Path: "direct", RTT: 12 * time.Millisecond, ExitOffered: true},
				{Name: "eve", IP: netip.MustParseAddr("10.7.0.4"), Path: "relay"},
			},
		}},
		Off:  []control.OffRoom{{ID: "r2", Name: "work"}},
		Exit: control.Exit{Choice: "game bob", Active: true, Member: "bob"},
	}
	m := BuildModel(s, nil)
	if m.State != "on" || !strings.Contains(m.Tooltip, "1 комната") {
		t.Fatalf("state %q tooltip %q", m.State, m.Tooltip)
	}
	room := find(m.Menu, "game — 10.7.0.2")
	if room == nil {
		t.Fatal("no room item")
	}
	if my := find(room.Children, "Скопировать мой адрес"); my == nil || my.Action.Kind != ActCopy || my.Action.Arg != "10.7.0.2" {
		t.Fatalf("copy my address: %+v", my)
	}
	bob := find(room.Children, "bob — 10.7.0.3 (напрямую)")
	if bob == nil || bob.Action.Arg != "10.7.0.3" {
		t.Fatalf("bob: %+v", room.Children)
	}
	if find(room.Children, "eve — 10.7.0.4 (через ретранслятор)") == nil {
		t.Fatal("eve's path")
	}
	if off := find(room.Children, "Выключить комнату"); off == nil || !slices.Equal(off.Action.Args, []string{"room", "off", "r1"}) {
		t.Fatalf("turn off: %+v", off)
	}
	work := find(m.Menu, "work — выключена")
	if work == nil || !slices.Equal(work.Children[0].Action.Args, []string{"room", "on", "r2"}) {
		t.Fatalf("off room: %+v", work)
	}
	exit := find(m.Menu, "Выход в интернет: через bob")
	if exit == nil {
		t.Fatal("no exit menu")
	}
	pick := find(exit.Children, "bob в комнате game")
	if pick == nil || !pick.Checked || !slices.Equal(pick.Action.Args, []string{"exit", "game", "bob"}) {
		t.Fatalf("exit pick: %+v", exit.Children)
	}
	if auto := find(exit.Children, "Как решили"); auto == nil || auto.Checked {
		t.Fatal("auto must not be checked")
	}
	if find(exit.Children, "eve") != nil {
		t.Fatal("eve offers no exit")
	}
	if BuildModel(s, nil).signature() != m.signature() {
		t.Fatal("signature is not stable")
	}
	s.Rooms[0].Peers[1].Path = "direct"
	if BuildModel(s, nil).signature() == m.signature() {
		t.Fatal("signature ignores a path change")
	}
}

func TestRoomsWord(t *testing.T) {
	for n, want := range map[int]string{0: "нет активных комнат", 1: "1 комната", 3: "3 комнаты", 5: "5 комнат", 11: "11 комнат", 21: "21 комната", 22: "22 комнаты", 12: "12 комнат"} {
		if got := roomsWord(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

func TestIsInvite(t *testing.T) {
	if !IsInvite(" zpt://join?c=x ") || !IsInvite("zpt://local?r=1") || IsInvite("https://evil") {
		t.Fatal("IsInvite")
	}
}
