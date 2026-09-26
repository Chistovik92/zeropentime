// SPDX-License-Identifier: MPL-2.0

//go:build windows || linux

// Command zpt-tray is the zeropentime icon in the notification area: rooms
// with the addresses of their members, the exit choice, turning rooms off
// and joining with an invite from the clipboard. It runs as the signed-in
// user and reads the node status over the read-only control channel;
// changes are made by "zpt" with administrator rights (UAC / polkit).
package main

import (
	"context"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/Chistovik92/zeropentime/internal/control"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		os.Stdout.WriteString("zpt-tray " + version + "\n")
		return
	}
	systray.Run(func() { go newTray().loop() }, func() {})
}

type tray struct {
	client  *control.Client
	refresh chan struct{}

	mu     sync.Mutex
	sig    string
	cancel context.CancelFunc
}

func newTray() *tray {
	return &tray{client: control.NewClient(), refresh: make(chan struct{}, 1)}
}

func (t *tray) loop() {
	systray.SetTitle("zeropentime")
	for {
		s, err := t.client.Status()
		t.draw(BuildModel(s, err))
		select {
		case <-time.After(3 * time.Second):
		case <-t.refresh:
		}
	}
}

func (t *tray) kick() {
	select {
	case t.refresh <- struct{}{}:
	default:
	}
}

func icon(state string) []byte {
	if runtime.GOOS == "windows" {
		return iconICO(state)
	}
	return iconPNG(state, 64)
}

func (t *tray) draw(m Model) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sig := m.signature()
	if sig == t.sig {
		return
	}
	t.sig = sig
	if os.Getenv("ZPT_TRAY_DEBUG") != "" {
		log.Printf("zpt-tray: draw %s: %s", m.State, m.Tooltip)
	}
	if t.cancel != nil {
		t.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	systray.SetIcon(icon(m.State))
	systray.SetTooltip(m.Tooltip)
	systray.ResetMenu()
	for _, it := range m.Menu {
		t.add(ctx, nil, it)
	}
}

func (t *tray) add(ctx context.Context, parent *systray.MenuItem, it Item) {
	if it.Separator {
		if parent == nil {
			systray.AddSeparator()
		} else {
			parent.AddSeparator()
		}
		return
	}
	var mi *systray.MenuItem
	switch {
	case parent == nil && it.Checkable:
		mi = systray.AddMenuItemCheckbox(it.Title, it.Tooltip, it.Checked)
	case parent == nil:
		mi = systray.AddMenuItem(it.Title, it.Tooltip)
	case it.Checkable:
		mi = parent.AddSubMenuItemCheckbox(it.Title, it.Tooltip, it.Checked)
	default:
		mi = parent.AddSubMenuItem(it.Title, it.Tooltip)
	}
	if it.Disabled {
		mi.Disable()
	}
	for _, c := range it.Children {
		t.add(ctx, mi, c)
	}
	if it.Action.Kind == ActNone {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-mi.ClickedCh:
				go t.do(it.Action)
			}
		}
	}()
}

func (t *tray) do(a Action) {
	var err error
	switch a.Kind {
	case ActCopy:
		err = setClipboard(a.Arg)
	case ActZpt:
		err = runZpt(a.Args)
		t.kick()
	case ActPaste:
		var text string
		if text, err = getClipboard(); err == nil {
			err = openInvite(strings.TrimSpace(text))
		}
	case ActStatus:
		err = showStatus()
	case ActQuit:
		systray.Quit()
	}
	if err != nil {
		log.Printf("zpt-tray: %v", err)
	}
}
