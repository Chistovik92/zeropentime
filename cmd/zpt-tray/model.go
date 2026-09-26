// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/control"
)

// The tray menu is built from the node status as plain data (tested
// without a desktop), then drawn by ui.go.

// ActionKind is what a menu item does when clicked.
type ActionKind int

const (
	ActNone   ActionKind = iota
	ActCopy              // copy Arg to the clipboard
	ActZpt               // run "zpt Args..." with administrator rights
	ActPaste             // join with the invite in the clipboard
	ActQuit              // close the tray
	ActStatus            // show "zpt status" in a terminal window
)

// Action of a menu item.
type Action struct {
	Kind ActionKind
	Arg  string   // ActCopy
	Args []string // ActZpt
}

// Item is one menu entry; Separator items only draw a line.
type Item struct {
	Title     string
	Tooltip   string
	Checked   bool
	Checkable bool
	Disabled  bool
	Separator bool
	Action    Action
	Children  []Item
}

// Model is the whole tray: its icon state, tooltip and menu.
type Model struct {
	State   string // "on", "idle" (no rooms), "down" (node not running)
	Tooltip string
	Menu    []Item
}

func sep() Item { return Item{Separator: true} }

// pathText has no round-trip time: the menu is redrawn when a title
// changes, and a menu redrawn every few seconds closes under the cursor.
func pathText(p control.Peer) string {
	switch p.Path {
	case "direct":
		return "напрямую"
	case "relay":
		return "через ретранслятор"
	}
	return "нет связи"
}

// BuildModel turns the node status (or the error getting it) into the menu.
func BuildModel(s *control.Status, err error) Model {
	var m Model
	if err != nil {
		m.State, m.Tooltip = "down", "zeropentime: "+err.Error()
		m.Menu = []Item{
			{Title: "Узел не отвечает", Disabled: true},
			{Title: shorten(err.Error(), 60), Disabled: true},
			sep(),
			{Title: "Вступить по приглашению из буфера", Action: Action{Kind: ActPaste}},
			sep(),
			{Title: "Закрыть трей", Action: Action{Kind: ActQuit}},
		}
		return m
	}
	m.State = "on"
	if len(s.Rooms) == 0 {
		m.State = "idle"
	}
	m.Tooltip = fmt.Sprintf("zeropentime: %s", roomsWord(len(s.Rooms)))
	head := "zeropentime — " + roomsWord(len(s.Rooms))
	m.Menu = append(m.Menu, Item{Title: head, Disabled: true}, sep())

	var exits []Item
	for _, r := range s.Rooms {
		my := r.Address.Addr().String()
		room := Item{Title: fmt.Sprintf("%s — %s", r.Name, my)}
		room.Children = append(room.Children,
			Item{Title: "Скопировать мой адрес " + my, Action: Action{Kind: ActCopy, Arg: my}})
		if len(r.Peers) > 0 {
			room.Children = append(room.Children, sep())
		}
		for _, p := range r.Peers {
			title := fmt.Sprintf("%s — %s (%s)", p.Name, p.IP, pathText(p))
			room.Children = append(room.Children, Item{Title: title, Tooltip: "скопировать адрес",
				Action: Action{Kind: ActCopy, Arg: p.IP.String()}})
			if p.ExitOffered && r.ID != "" {
				choice := r.Name + " " + p.Name
				exits = append(exits, Item{Title: fmt.Sprintf("%s в комнате %s", p.Name, r.Name), Checkable: true,
					Checked: s.Exit.Choice == choice, Action: Action{Kind: ActZpt, Args: []string{"exit", r.Name, p.Name}}})
			}
		}
		if r.ID != "" {
			room.Children = append(room.Children, sep(),
				Item{Title: "Выключить комнату на этом устройстве", Action: Action{Kind: ActZpt, Args: []string{"room", "off", r.ID}}})
		}
		m.Menu = append(m.Menu, room)
	}
	for _, o := range s.Off {
		m.Menu = append(m.Menu, Item{Title: o.Name + " — выключена", Children: []Item{
			{Title: "Включить", Action: Action{Kind: ActZpt, Args: []string{"room", "on", o.ID}}},
		}})
	}
	if len(s.Rooms)+len(s.Off) > 0 {
		m.Menu = append(m.Menu, sep())
	}

	exit := Item{Title: "Выход в интернет"}
	if s.Exit.Active {
		exit.Title = fmt.Sprintf("Выход в интернет: через %s", s.Exit.Member)
	}
	exit.Children = append(exit.Children,
		Item{Title: "Как решили админы комнат", Checkable: true, Checked: s.Exit.Choice == "auto" || s.Exit.Choice == "",
			Action: Action{Kind: ActZpt, Args: []string{"exit", "auto"}}},
		Item{Title: "Напрямую, без exit", Checkable: true, Checked: s.Exit.Choice == "off",
			Action: Action{Kind: ActZpt, Args: []string{"exit", "off"}}})
	if len(exits) > 0 {
		exit.Children = append(exit.Children, sep())
		exit.Children = append(exit.Children, exits...)
	}
	m.Menu = append(m.Menu, exit,
		Item{Title: "Вступить по приглашению из буфера", Action: Action{Kind: ActPaste}},
		Item{Title: "Подробное состояние", Action: Action{Kind: ActStatus}},
		sep(),
		Item{Title: "Закрыть трей", Action: Action{Kind: ActQuit}})
	return m
}

func roomsWord(n int) string {
	switch {
	case n == 0:
		return "нет активных комнат"
	case n%10 == 1 && n%100 != 11:
		return fmt.Sprintf("%d комната", n)
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return fmt.Sprintf("%d комнаты", n)
	}
	return fmt.Sprintf("%d комнат", n)
}

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// signature changes whenever the drawn menu would.
func (m Model) signature() string {
	var b strings.Builder
	b.WriteString(m.State + "|" + m.Tooltip)
	var walk func([]Item)
	walk = func(items []Item) {
		for _, it := range items {
			fmt.Fprintf(&b, "|%s/%v/%v/%v[", it.Title, it.Checked, it.Disabled, it.Separator)
			walk(it.Children)
			b.WriteString("]")
		}
	}
	walk(m.Menu)
	return b.String()
}

// IsInvite reports whether the clipboard text looks like an invite link.
func IsInvite(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "zpt://join?") || strings.HasPrefix(s, "zpt://local?")
}
