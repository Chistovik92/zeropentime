// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"fmt"
	"html/template"
	"math"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/store"
)

// Dashboard sums up what the actor may see.
type Dashboard struct {
	Rooms, Members, Pending int
	Nodes, Online           int // distinct devices in the actor's rooms
	Direct, Relayed         int // paths reported by online nodes
	Exits                   int // approved exit nodes
	Rows                    []DashboardRoom
}

// DashboardRoom is one room's line on the dashboard.
type DashboardRoom struct {
	Room            store.Room
	Members, Online int
	Pending         int
}

// DirectPercent is the share of peer paths that are direct (-1: no data).
func (d *Dashboard) DirectPercent() int {
	if d.Direct+d.Relayed == 0 {
		return -1
	}
	return int(math.Round(100 * float64(d.Direct) / float64(d.Direct+d.Relayed)))
}

// Dashboard collects counters over the rooms the actor may see.
func (s *Service) Dashboard(ctx context.Context, u *store.User) (*Dashboard, error) {
	rooms, err := s.Rooms(ctx, u)
	if err != nil {
		return nil, err
	}
	d := &Dashboard{Rooms: len(rooms)}
	seen := map[string]bool{}
	err = s.st.Read(ctx, func(tx *store.Tx) error {
		for _, r := range rooms {
			ms, err := tx.ListMembers(r.ID)
			if err != nil {
				return err
			}
			row := DashboardRoom{Room: r}
			for _, m := range ms {
				if m.Status == store.StatusPending {
					row.Pending++
					continue
				}
				if m.Status != store.StatusActive {
					continue
				}
				row.Members++
				online := s.now().Sub(m.LastSeen) < OnlineWindow
				if online {
					row.Online++
				}
				if m.Exit && m.ExitOffered {
					d.Exits++
				}
				if seen[m.NodeID] {
					continue
				}
				seen[m.NodeID] = true
				d.Nodes++
				if online {
					d.Online++
					p := s.Paths(m.NodeID)
					d.Direct += p.Direct
					d.Relayed += p.Relay
				}
			}
			d.Members += row.Members
			d.Pending += row.Pending
			d.Rows = append(d.Rows, row)
		}
		return nil
	})
	return d, err
}

// Topology draws a room's members as an SVG: online members are green,
// a line runs from each member to the exit it uses, and routers and exits
// are marked. Every value comes from the store and is escaped.
func Topology(ms []store.Member, online func(store.Member) bool) template.HTML {
	var act []store.Member
	for _, m := range ms {
		if m.Status == store.StatusActive {
			act = append(act, m)
		}
	}
	if len(act) < 2 {
		return ""
	}
	const size, radius = 420.0, 150.0
	pos := map[string][2]float64{}
	for i, m := range act {
		a := 2*math.Pi*float64(i)/float64(len(act)) - math.Pi/2
		pos[m.NodeID] = [2]float64{size/2 + radius*math.Cos(a), size/2 + radius*math.Sin(a)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="topo" viewBox="0 0 %[1]g %[1]g" role="img" aria-label="Схема комнаты">`, size)
	for _, m := range act {
		if to, ok := pos[m.UseExit]; ok {
			from := pos[m.NodeID]
			fmt.Fprintf(&b, `<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" class="exit"/>`, from[0], from[1], to[0], to[1])
		}
	}
	for _, m := range act {
		p := pos[m.NodeID]
		class := "off"
		if online(m) {
			class = "on"
		}
		mark := ""
		switch {
		case m.Exit && m.ExitOffered:
			mark = " ⇱ exit"
		case len(m.Routes) > 0:
			mark = " ⇄ сеть"
		}
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="9" class="%s"/><text x="%.0f" y="%.0f" text-anchor="middle">%s</text>`,
			p[0], p[1], class, p[0], p[1]+24, template.HTMLEscapeString(shorten(m.Name, 16)+mark))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
