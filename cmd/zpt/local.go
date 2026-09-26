// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/control"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/node"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

// Rooms without a controller: "zpt room create -local", invite, list,
// members, kick; "zpt join" understands their zpt://local links.

type localCtx struct {
	cfg       *config.Config
	id        *identity.Identity
	statePath string
	st        *node.State
}

func openLocal(fl *flag.FlagSet, cfgPath *string, explicit func() bool) (*localCtx, error) {
	cfg, err := nodeConfig(*cfgPath, explicit())
	if err != nil {
		return nil, err
	}
	id, _, err := loadOrCreateKey(cfg.KeyPath())
	if err != nil {
		return nil, err
	}
	p := node.StatePath(cfg.KeyPath())
	st, err := node.LoadState(p)
	if err != nil {
		return nil, err
	}
	return &localCtx{cfg: cfg, id: id, statePath: p, st: st}, nil
}

func (l *localCtx) save() error {
	if err := l.st.Save(l.statePath); err != nil {
		return err
	}
	reloadQuiet()
	return nil
}

// reloadQuiet asks a running node to apply the state file now.
func reloadQuiet() { control.NewClient().Reload() }

func cmdRoomLocal(action string, args []string) error {
	fl := flag.NewFlagSet("room "+action, flag.ExitOnError)
	cfgPath, explicit := configFlag(fl)
	host, _ := os.Hostname()
	local := fl.Bool("local", false, "комната без контроллера")
	name := fl.String("name", "", "название комнаты")
	me := fl.String("me", host, "ваше имя в комнате")
	subnet := fl.String("subnet", "", "подсеть (по умолчанию выбирается сама)")
	uses := fl.Int("uses", 1, "сколько раз можно использовать приглашение (0 — без ограничений)")
	hours := fl.Int("hours", 24, "срок действия приглашения, часов")
	endpoints := fl.String("endpoint", "", "адреса, по которым участник достучится до вас (host:port через запятую); по умолчанию — найденные автоматически")
	fl.Parse(args)
	l, err := openLocal(fl, cfgPath, explicit)
	if err != nil {
		return err
	}
	switch action {
	case "create":
		if !*local {
			return errors.New("комнаты с контроллером создаются в панели; без контроллера: zpt room create -local -name ИМЯ")
		}
		if *name == "" {
			return errors.New("укажите -name")
		}
		var sub netip.Prefix
		if *subnet != "" {
			if sub, err = netip.ParsePrefix(*subnet); err != nil {
				return err
			}
		}
		lr, err := l.st.CreateLocalRoom(l.id, *name, *me, sub)
		if err != nil {
			return err
		}
		if err := l.save(); err != nil {
			return err
		}
		fmt.Printf("комната создана: %s (%s)\nпригласить участника: zpt room invite %s\n", lr.Name, lr.RoomID, lr.Name)
		fmt.Println("Этот узел — владелец: он подписывает конфиг комнаты и принимает новых участников, пока запущен.")
		return nil
	case "invite":
		if fl.NArg() != 1 {
			return errors.New("использование: zpt room invite КОМНАТА [-uses 1] [-hours 24] [-endpoint host:port]")
		}
		lr, err := l.st.LocalRoomByRef(fl.Arg(0))
		if err != nil {
			return err
		}
		cfg, err := verifiedConfig(lr)
		if err != nil {
			return err
		}
		tok, err := lr.NewInvite(*uses, time.Duration(*hours)*time.Hour)
		if err != nil {
			return err
		}
		link, err := l.link(lr, cfg, tok, *endpoints)
		if err != nil {
			return err
		}
		if err := l.save(); err != nil {
			return err
		}
		fmt.Printf("Передайте участнику команду (ссылка содержит секрет комнаты — только ему):\n\nzpt join \"%s\"\n\n", link)
		fmt.Println("Ваш узел должен быть запущен и доступен по этим адресам, пока участник вступает:", link.Endpoints)
		return nil
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "КОМНАТА\tID\tРОЛЬ\tУЧАСТНИКИ\tСОСТОЯНИЕ")
		for i := range l.st.Local {
			lr := &l.st.Local[i]
			role, state, members := "участник", "работает", "-"
			if len(lr.SignKey) > 0 {
				role = "админ"
			}
			if cfg, err := verifiedConfig(lr); err == nil {
				members = fmt.Sprint(len(cfg.Members))
			}
			if lr.Join != nil {
				state = "ждёт, пока владелец примет"
				if lr.Join.IP.IsValid() {
					state = "принят, получает конфиг"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", lr.Name, lr.RoomID, role, members, state)
		}
		return w.Flush()
	case "members":
		if fl.NArg() != 1 {
			return errors.New("использование: zpt room members КОМНАТА")
		}
		lr, err := l.st.LocalRoomByRef(fl.Arg(0))
		if err != nil {
			return err
		}
		cfg, err := verifiedConfig(lr)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ИМЯ\tIP\tID УЗЛА")
		for _, m := range cfg.Members {
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.Name, m.IP, m.NodeID)
		}
		return w.Flush()
	case "kick":
		if fl.NArg() != 2 {
			return errors.New("использование: zpt room kick КОМНАТА УЧАСТНИК")
		}
		lr, err := l.st.LocalRoomByRef(fl.Arg(0))
		if err != nil {
			return err
		}
		who := fl.Arg(1)
		err = lr.Update(func(c *pki.RoomConfig) error {
			for i, m := range c.Members {
				if m.Name == who || m.NodeID == who {
					if m.NodeID == l.id.NodeID() {
						return errors.New("нельзя исключить себя")
					}
					c.Members = append(c.Members[:i], c.Members[i+1:]...)
					delete(lr.Peers, m.NodeID)
					return nil
				}
			}
			return fmt.Errorf("в комнате нет участника %q", who)
		})
		if err != nil {
			return err
		}
		if err := l.save(); err != nil {
			return err
		}
		fmt.Println("участник исключён; остальные узнают об этом от вашего узла")
		return nil
	}
	return fmt.Errorf("неизвестная команда room %s", action)
}

func verifiedConfig(lr *node.LocalRoom) (*pki.RoomConfig, error) {
	if lr.Config == nil {
		return nil, errors.New("конфиг комнаты ещё не получен")
	}
	pub, err := pki.ParseRoomKey(lr.RoomKey)
	if err != nil {
		return nil, err
	}
	return pki.VerifyRoomConfig(pub, lr.Config)
}

// link builds an invite with this node as the owner to contact.
func (l *localCtx) link(lr *node.LocalRoom, cfg *pki.RoomConfig, tok, endpoints string) (node.LocalLink, error) {
	link := node.LocalLink{RoomID: lr.RoomID, RoomKey: lr.RoomKey, Secret: cfg.Secret, Subnet: cfg.Subnet, Token: tok, Owner: l.id.NodeID()}
	_, link.OwnerDisco = l.id.DiscoKey()
	wg, err := l.id.RoomKey(lr.RoomID)
	if err != nil {
		return link, err
	}
	link.OwnerWG = wg.Public()
	for _, m := range cfg.Members {
		if m.NodeID == l.id.NodeID() {
			link.OwnerIP = m.IP
		}
	}
	if !link.OwnerIP.IsValid() {
		return link, errors.New("этот узел не участник комнаты")
	}
	if endpoints != "" {
		for _, e := range strings.Split(endpoints, ",") {
			ap, err := netip.ParseAddrPort(strings.TrimSpace(e))
			if err != nil {
				return link, fmt.Errorf("-endpoint %q: %w", e, err)
			}
			link.Endpoints = append(link.Endpoints, ap)
		}
		return link, nil
	}
	port := uint16(l.cfg.Port())
	if s, err := control.NewClient().Status(); err == nil {
		port = s.UDPPort
		if s.PortMap.IsValid() {
			link.Endpoints = append(link.Endpoints, s.PortMap)
		}
		for _, c := range s.Controllers {
			link.Endpoints = append(link.Endpoints, c.Mapped...)
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				ip = ip.Unmap()
				if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !cfg.Subnet.Contains(ip) && len(link.Endpoints) < 6 {
					link.Endpoints = append(link.Endpoints, netip.AddrPortFrom(ip, port))
				}
			}
		}
	}
	if len(link.Endpoints) == 0 {
		return link, errors.New("не нашёл своих адресов: укажите -endpoint host:port")
	}
	return link, nil
}

// joinLocal records a zpt://local invite in the state file.
func joinLocal(l *localCtx, raw, name string) error {
	link, err := node.ParseLocalLink(raw)
	if err != nil {
		return err
	}
	for _, lr := range l.st.Local {
		if lr.RoomID == link.RoomID {
			return errors.New("вы уже в этой комнате (zpt room list)")
		}
	}
	l.st.Local = append(l.st.Local, node.LocalRoom{RoomID: link.RoomID, Name: "room-" + link.RoomID[:6], RoomKey: link.RoomKey,
		Join: &node.LocalJoin{Invite: link, Name: name}})
	if err := l.save(); err != nil {
		return err
	}
	fmt.Println("запрос на вступление отправляется владельцу комнаты; узел должен быть запущен (zpt up / служба).")
	fmt.Println("проверить: zpt room list")
	return nil
}
