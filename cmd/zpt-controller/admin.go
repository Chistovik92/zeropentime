// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Chistovik92/zeropentime/internal/acl"
	"github.com/Chistovik92/zeropentime/internal/controller"
	"github.com/Chistovik92/zeropentime/internal/store"
)

// cliAdmin is the actor of terminal commands in the audit log.
var cliAdmin = &store.User{IsAdmin: true, Login: "cli"}

// admin is one terminal session over the database. It works also while
// the server runs: the server notices the changes within two seconds.
type admin struct {
	ctx  context.Context
	svc  *controller.Service
	json bool
}

func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func table(header string) *tabwriter.Writer {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, header)
	return w
}

// room finds a room by ID or name.
func (a *admin) room(ref string) (*controller.RoomView, error) {
	if ref == "" {
		return nil, errors.New("укажите комнату: -room ID или название")
	}
	rooms, err := a.svc.Rooms(a.ctx, cliAdmin)
	if err != nil {
		return nil, err
	}
	var found []store.Room
	for _, r := range rooms {
		if r.ID == ref || strings.EqualFold(r.Name, ref) {
			found = append(found, r)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("комната %q не найдена (zpt-controller room list)", ref)
	case 1:
		return a.svc.Room(a.ctx, cliAdmin, found[0].ID)
	}
	return nil, fmt.Errorf("комнат с названием %q несколько — укажите ID", ref)
}

// member finds a member by name or node ID.
func member(v *controller.RoomView, ref string) (*store.Member, error) {
	if ref == "" {
		return nil, errors.New("укажите участника: -member ИМЯ или ID узла")
	}
	for i, m := range v.Members {
		if m.Name == ref || m.NodeID == ref {
			return &v.Members[i], nil
		}
	}
	return nil, fmt.Errorf("в комнате %s нет участника %q", v.Room.Name, ref)
}

var statusName = map[string]string{store.StatusActive: "активен", store.StatusPending: "ждёт одобрения", store.StatusBanned: "заблокирован"}

type roomJSON struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Subnet     netip.Prefix `json:"subnet"`
	JoinPolicy string       `json:"join_policy"`
	Broadcast  string       `json:"broadcast"`
	DNS        []netip.Addr `json:"dns,omitempty"`
	Created    time.Time    `json:"created"`
}

func roomOut(r store.Room) roomJSON {
	return roomJSON{r.ID, r.Name, r.Subnet, r.JoinPolicy, r.Broadcast, r.DNS, r.CreatedAt}
}

type memberJSON struct {
	NodeID      string         `json:"node_id"`
	Name        string         `json:"name"`
	IP          netip.Addr     `json:"ip"`
	Tags        []string       `json:"tags,omitempty"`
	Status      string         `json:"status"`
	Online      bool           `json:"online"`
	LastSeen    time.Time      `json:"last_seen"`
	PublicIP    netip.Addr     `json:"public_ip,omitzero"`
	NAT         string         `json:"nat,omitempty"`
	Version     string         `json:"version,omitempty"`
	Routes      []netip.Prefix `json:"routes,omitempty"`
	Offered     []netip.Prefix `json:"offered_routes,omitempty"`
	Exit        bool           `json:"exit,omitempty"`
	ExitOffered bool           `json:"exit_offered,omitempty"`
	UseExit     string         `json:"use_exit,omitempty"`
}

func memberOut(m store.Member) memberJSON {
	return memberJSON{m.NodeID, m.Name, m.IP, m.Tags, m.Status, time.Since(m.LastSeen) < controller.OnlineWindow, m.LastSeen,
		m.PublicIP, m.NAT, m.Version, m.Routes, m.Offered, m.Exit, m.ExitOffered, m.UseExit}
}

type inviteJSON struct {
	ID          int64     `json:"id"`
	Note        string    `json:"note,omitempty"`
	UsesLeft    int       `json:"uses_left"` // -1 = unlimited
	Expires     time.Time `json:"expires"`
	AutoApprove bool      `json:"auto_approve"`
}

func (a *admin) printMembers(v *controller.RoomView) error {
	if a.json {
		out := []memberJSON{}
		for _, m := range v.Members {
			out = append(out, memberOut(m))
		}
		return printJSON(out)
	}
	w := table("ИМЯ\tIP\tСТАТУС\tВ СЕТИ\tВНЕШНИЙ АДРЕС\tNAT\tТЕГИ\tОСОБОЕ\tID УЗЛА")
	for _, m := range v.Members {
		online := "нет, был " + m.LastSeen.Format("02.01 15:04")
		if time.Since(m.LastSeen) < controller.OnlineWindow {
			online = "да"
		}
		var extra []string
		if m.Exit && m.ExitOffered {
			extra = append(extra, "exit")
		} else if m.ExitOffered {
			extra = append(extra, "предлагает exit")
		}
		if len(m.Routes) > 0 {
			extra = append(extra, fmt.Sprintf("сети %v", m.Routes))
		}
		if len(m.Offered) > 0 && fmt.Sprint(m.Offered) != fmt.Sprint(m.Routes) {
			extra = append(extra, fmt.Sprintf("предлагает сети %v", m.Offered))
		}
		if m.UseExit != "" {
			for _, x := range v.Members {
				if x.NodeID == m.UseExit {
					extra = append(extra, "выход через "+x.Name)
				}
			}
		}
		pub := "-"
		if m.PublicIP.IsValid() {
			pub = m.PublicIP.String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, m.IP, statusName[m.Status], online, pub, orDash(m.NAT),
			orDash(strings.Join(m.Tags, ",")), orDash(strings.Join(extra, "; ")), m.NodeID)
	}
	return w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *admin) printInvites(v *controller.RoomView) error {
	if a.json {
		out := []inviteJSON{}
		for _, i := range v.Invites {
			out = append(out, inviteJSON{i.ID, i.Note, i.UsesLeft, i.Expires, i.AutoApprove})
		}
		return printJSON(out)
	}
	w := table("ID\tЗАМЕТКА\tОСТАЛОСЬ\tДЕЙСТВУЕТ ДО\tБЕЗ ОДОБРЕНИЯ")
	for _, i := range v.Invites {
		uses := fmt.Sprint(i.UsesLeft)
		if i.UsesLeft < 0 {
			uses = "без ограничений"
		}
		auto := "нет"
		if i.AutoApprove {
			auto = "да"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", i.ID, orDash(i.Note), uses, i.Expires.Format("02.01.2006 15:04"), auto)
	}
	return w.Flush()
}

var memberActions = map[string]controller.MemberAction{
	"approve": controller.ActApprove, "ban": controller.ActBan, "unban": controller.ActUnban, "kick": controller.ActKick,
}

// runAdmin handles the room, member, invite, routes, exit, user and audit
// commands for people at a terminal and for scripts.
func runAdmin(sub string, args []string) error {
	action := ""
	if sub != "audit" {
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return errors.New("использование:\n" + usage)
		}
		action, args = args[0], args[1:]
	}
	fl := flag.NewFlagSet(strings.TrimSpace(sub+" "+action), flag.ExitOnError)
	db := fl.String("db", "zpt-controller.db", "файл базы данных")
	asJSON := fl.Bool("json", false, "вывод в JSON (для скриптов)")
	roomRef := fl.String("room", "", "комната: ID или название")
	memberRef := fl.String("member", "", "участник: имя или ID узла")
	name := fl.String("name", "", "название / имя")
	subnet := fl.String("subnet", "", "подсеть (по умолчанию выбирается сама)")
	owner := fl.String("owner", "", "логин владельца комнаты")
	policy := fl.String("policy", "", "вступление: manual (с одобрением) или auto")
	broadcast := fl.String("broadcast", "", "широковещание: on, off или mdns")
	servers := fl.String("servers", "", "DNS-серверы через запятую (пусто — убрать)")
	ip := fl.String("ip", "", "IP в комнате")
	tags := fl.String("tags", "\x00", "теги через запятую")
	url := fl.String("url", "", "внешний адрес контроллера для ссылки, например https://zpt.example.org")
	uses := fl.Int("uses", 1, "сколько раз можно использовать (0 — без ограничений)")
	hours := fl.Int("hours", 24, "срок действия, часов")
	auto := fl.Bool("auto", false, "вступление без одобрения")
	note := fl.String("note", "", "заметка")
	id := fl.Int64("id", 0, "ID приглашения")
	via := fl.String("via", "", "exit-узел: имя участника (пусто — напрямую)")
	login := fl.String("login", "", "логин")
	isAdmin := fl.Bool("admin", false, "администратор инстанса")
	limit := fl.Int("n", 50, "сколько последних записей")
	file := fl.String("file", "", "файл с правилами (- — стандартный ввод; пусто — убрать правила)")
	from := fl.String("from", "", "откуда: участник")
	to := fl.String("to", "", "куда: участник или IP")
	proto := fl.String("proto", "tcp", "протокол: tcp, udp или icmp")
	port := fl.Int("port", 0, "порт")
	fl.Parse(args)
	svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	defer closeDB()
	a := &admin{ctx: context.Background(), svc: svc, json: *asJSON}
	done := func(err error) error {
		if err == nil && !a.json {
			fmt.Println("готово")
		}
		return err
	}

	switch sub + " " + action {
	case "room create":
		u, err := svc.UserByLogin(a.ctx, *owner)
		if err != nil {
			return fmt.Errorf("пользователь %q не найден (-owner)", *owner)
		}
		p := *policy
		if p == "" {
			p = "manual"
		}
		r, err := svc.CreateRoom(a.ctx, u, *name, *subnet, p)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(roomOut(*r))
		}
		fmt.Printf("room id: %s\nsubnet:  %s\n", r.ID, r.Subnet)
		return nil
	case "room list":
		rooms, err := svc.Rooms(a.ctx, cliAdmin)
		if err != nil {
			return err
		}
		if a.json {
			out := []roomJSON{}
			for _, r := range rooms {
				out = append(out, roomOut(r))
			}
			return printJSON(out)
		}
		for _, r := range rooms {
			fmt.Printf("%s  %-18s  %s\n", r.ID, r.Subnet, r.Name)
		}
		return nil
	case "room show":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		if a.json {
			members, invites := []memberJSON{}, []inviteJSON{}
			for _, m := range v.Members {
				members = append(members, memberOut(m))
			}
			for _, i := range v.Invites {
				invites = append(invites, inviteJSON{i.ID, i.Note, i.UsesLeft, i.Expires, i.AutoApprove})
			}
			return printJSON(map[string]any{"room": roomOut(v.Room), "room_key": v.RoomKey, "members": members, "invites": invites})
		}
		r := v.Room
		fmt.Printf("комната:        %s (%s)\nподсеть:        %s\nвступление:     %s\nшироковещание:  %s\n", r.Name, r.ID, r.Subnet, r.JoinPolicy, r.Broadcast)
		if len(r.DNS) > 0 {
			fmt.Printf("DNS:            %v\n", r.DNS)
		}
		fmt.Printf("ключ подписи:   %s\n\nУчастники:\n", v.RoomKey)
		if err := a.printMembers(v); err != nil {
			return err
		}
		fmt.Println("\nПриглашения:")
		return a.printInvites(v)
	case "room set":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		n, p, b := v.Room.Name, v.Room.JoinPolicy, v.Room.Broadcast
		if *name != "" {
			n = *name
		}
		if *policy != "" {
			p = *policy
		}
		if *broadcast != "" {
			b = *broadcast
		}
		return done(svc.UpdateRoom(a.ctx, cliAdmin, v.Room.ID, n, p, b))
	case "room dns":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		return done(svc.SetRoomDNS(a.ctx, cliAdmin, v.Room.ID, *servers))
	case "room delete":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		return done(svc.DeleteRoom(a.ctx, cliAdmin, v.Room.ID))

	case "member list":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		return a.printMembers(v)
	case "member approve", "member ban", "member unban", "member kick":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		m, err := member(v, *memberRef)
		if err != nil {
			return err
		}
		return done(svc.MemberAction(a.ctx, cliAdmin, v.Room.ID, m.NodeID, memberActions[action]))
	case "member set":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		m, err := member(v, *memberRef)
		if err != nil {
			return err
		}
		n, addr, t := m.Name, m.IP.String(), strings.Join(m.Tags, ",")
		if *name != "" {
			n = *name
		}
		if *ip != "" {
			addr = *ip
		}
		if *tags != "\x00" {
			t = *tags
		}
		return done(svc.UpdateMember(a.ctx, cliAdmin, v.Room.ID, m.NodeID, n, addr, t))

	case "invite create":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		if *url == "" {
			return errors.New("укажите -url — адрес контроллера, по которому узлы к нему подключаются")
		}
		inv, err := svc.CreateInvite(a.ctx, cliAdmin, strings.TrimRight(*url, "/"), v.Room.ID, *uses, time.Duration(*hours)*time.Hour, *auto, *note)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(map[string]string{"invite": inv.String(), "command": `zpt join "` + inv.String() + `"`})
		}
		fmt.Println(inv.String())
		return nil
	case "invite list":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		return a.printInvites(v)
	case "invite revoke":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		return done(svc.RevokeInvite(a.ctx, cliAdmin, v.Room.ID, *id))

	case "routes approve", "routes revoke", "exit approve", "exit revoke":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		m, err := member(v, *memberRef)
		if err != nil {
			return err
		}
		act := map[string]controller.MemberAction{"routes approve": controller.ActRoutes, "routes revoke": controller.ActNoRoutes,
			"exit approve": controller.ActExit, "exit revoke": controller.ActNoExit}[sub+" "+action]
		return done(svc.MemberAction(a.ctx, cliAdmin, v.Room.ID, m.NodeID, act))
	case "exit use":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		m, err := member(v, *memberRef)
		if err != nil {
			return err
		}
		viaID := ""
		if *via != "" {
			x, err := member(v, *via)
			if err != nil {
				return err
			}
			viaID = x.NodeID
		}
		return done(svc.SetMemberExit(a.ctx, cliAdmin, v.Room.ID, m.NodeID, viaID))

	case "acl show":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		if a.json {
			rules, err := acl.Parse(v.Room.ACL)
			if err != nil {
				return err
			}
			if rules == nil {
				rules = []acl.Rule{}
			}
			return printJSON(rules)
		}
		if v.Room.ACL == "" {
			fmt.Println("# правил нет: в комнате разрешено всё")
			return nil
		}
		fmt.Print(v.Room.ACL)
		return nil
	case "acl set":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		var text []byte
		switch *file {
		case "":
		case "-":
			if text, err = io.ReadAll(os.Stdin); err != nil {
				return err
			}
		default:
			if text, err = os.ReadFile(*file); err != nil {
				return err
			}
		}
		return done(svc.SetRoomACL(a.ctx, cliAdmin, v.Room.ID, string(text)))
	case "acl test":
		v, err := a.room(*roomRef)
		if err != nil {
			return err
		}
		ok, rule, err := svc.TestACL(a.ctx, cliAdmin, v.Room.ID, *from, *to, *proto, *port)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(map[string]any{"allowed": ok, "rule": rule})
		}
		switch {
		case ok && rule == "":
			fmt.Println("разрешено: правил нет, в комнате разрешено всё")
		case ok:
			fmt.Println("разрешено правилом:", rule)
		default:
			fmt.Println("запрещено: ни одно правило это не разрешает")
		}
		return nil

	case "user add":
		pw := controller.RandomPassword()
		if err := svc.CreateUser(a.ctx, nil, *login, pw, *isAdmin); err != nil {
			return err
		}
		fmt.Printf("пользователь создан: %s\nпароль: %s\n(сохраните его, повторно он не показывается)\n", strings.ToLower(*login), pw)
		return nil
	case "user list":
		users, err := svc.Users(a.ctx, cliAdmin)
		if err != nil {
			return err
		}
		if a.json {
			type userJSON struct {
				Login   string    `json:"login"`
				Admin   bool      `json:"admin"`
				Created time.Time `json:"created"`
			}
			out := []userJSON{}
			for _, u := range users {
				out = append(out, userJSON{u.Login, u.IsAdmin, u.Created})
			}
			return printJSON(out)
		}
		w := table("ЛОГИН\tАДМИН\tСОЗДАН")
		for _, u := range users {
			adm := "нет"
			if u.IsAdmin {
				adm = "да"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", u.Login, adm, u.Created.Format("02.01.2006 15:04"))
		}
		return w.Flush()
	case "user delete":
		u, err := svc.UserByLogin(a.ctx, *login)
		if err != nil {
			return fmt.Errorf("пользователь %q не найден", *login)
		}
		return done(svc.DeleteUser(a.ctx, cliAdmin, u.ID))
	case "user passwd":
		pw := controller.RandomPassword()
		if err := svc.SetPassword(a.ctx, strings.ToLower(*login), pw); err != nil {
			return err
		}
		fmt.Printf("новый пароль для %s: %s\n", *login, pw)
		return nil

	case "audit ":
		entries, err := svc.Audit(a.ctx, cliAdmin, *limit)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(entries)
		}
		w := table("ВРЕМЯ\tКТО\tДЕЙСТВИЕ\tОБЪЕКТ\tПОДРОБНОСТИ")
		for _, e := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Time.Format("02.01.2006 15:04:05"), e.Actor, e.Action, e.Target, e.Details)
		}
		return w.Flush()
	}
	return fmt.Errorf("неизвестная команда %s %s\n\n%s", sub, action, usage)
}
