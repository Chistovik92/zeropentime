// SPDX-License-Identifier: AGPL-3.0-only

// Command zpt-controller runs the zeropentime controller: the admin panel and
// the API nodes use to join rooms and follow changes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Chistovik92/zeropentime/internal/controller"
	"github.com/Chistovik92/zeropentime/internal/store"
)

var version = "0.2.2-dev"

const usage = `zpt-controller — контроллер zeropentime (админ-панель + API для узлов)

  zpt-controller serve   -db ФАЙЛ [-listen :8080] [-url https://...] [-tls-cert Ф -tls-key Ф] [-trust-proxy]
                         [-stun :3478,:3479] [-stun-public host:3478,host:3479] [-relay :3480] [-relay-public host:3480]
                         [-vless :443 -vless-dest www.example.com:443 [-vless-sni ...] [-vless-public host:443]]
  zpt-controller useradd -db ФАЙЛ -login ЛОГИН [-admin]
  zpt-controller room create   -db ФАЙЛ -owner ЛОГИН -name ИМЯ [-subnet 10.100.1.0/24] [-policy manual|auto]
  zpt-controller room list     -db ФАЙЛ
  zpt-controller invite create -db ФАЙЛ -room ID -url https://... [-uses 1] [-hours 24] [-auto] [-note ТЕКСТ]
  zpt-controller passwd  -db ФАЙЛ -login ЛОГИН
  zpt-controller version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func run(sub string, args []string) error {
	fl := flag.NewFlagSet(sub, flag.ExitOnError)
	db := fl.String("db", "zpt-controller.db", "файл базы данных")
	switch sub {
	case "serve":
		listen := fl.String("listen", ":8080", "адрес HTTP(S)")
		pub := fl.String("url", "", "внешний адрес контроллера для ссылок-приглашений, например https://zpt.example.org")
		cert := fl.String("tls-cert", "", "TLS-сертификат (PEM)")
		key := fl.String("tls-key", "", "TLS-ключ (PEM)")
		trust := fl.Bool("trust-proxy", false, "доверять X-Forwarded-For/-Proto от обратного прокси")
		stunListen := fl.String("stun", ":3478,:3479", "UDP-адреса встроенного STUN-сервера через запятую (два порта нужны для определения симметричного NAT); пусто — выключить")
		stunPublic := fl.String("stun-public", "", "STUN-адреса для узлов (host:port через запятую); по умолчанию — хост из -url с портами из -stun")
		relayListen := fl.String("relay", ":3480", "UDP-адрес встроенного relay (пересылка, когда прямой путь не работает); пусто — выключить")
		relayPublic := fl.String("relay-public", "", "адрес relay для узлов (host:port); по умолчанию — хост из -url с портом из -relay")
		vlessListen := fl.String("vless", "", "TCP-адрес входа в relay через VLESS + REALITY (обычно :443) для сетей, где закрыт UDP; пусто — выключено")
		vlessDest := fl.String("vless-dest", "", "настоящий сайт, который имитирует REALITY (host:443), например www.microsoft.com:443")
		vlessSNI := fl.String("vless-sni", "", "имена (SNI) этого сайта через запятую; по умолчанию — хост из -vless-dest")
		vlessPublic := fl.String("vless-public", "", "адрес VLESS для узлов (host:port); по умолчанию — хост из -url с портом из -vless")
		level := fl.String("log-level", "info", "debug|info|warn|error")
		fl.Parse(args)
		var l slog.Level
		if err := l.UnmarshalText([]byte(*level)); err != nil {
			return fmt.Errorf("log-level: %w", err)
		}
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
		svc, closeDB, err := openService(*db, log)
		if err != nil {
			return err
		}
		defer closeDB()
		srv, err := controller.NewServer(controller.Config{
			Listen: *listen, PublicURL: strings.TrimRight(*pub, "/"), TLSCert: *cert, TLSKey: *key, TrustProxy: *trust,
			STUNListen: splitList(*stunListen), STUNPublic: splitList(*stunPublic),
			RelayListen: *relayListen, RelayPublic: *relayPublic,
			VLESSListen: *vlessListen, VLESSDest: *vlessDest, VLESSServerNames: sniList(*vlessSNI, *vlessDest), VLESSPublic: *vlessPublic,
		}, svc, log)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return srv.Serve(ctx)
	case "useradd":
		login := fl.String("login", "", "логин")
		admin := fl.Bool("admin", false, "администратор инстанса")
		fl.Parse(args)
		svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer closeDB()
		pw := controller.RandomPassword()
		if err := svc.CreateUser(context.Background(), nil, *login, pw, *admin); err != nil {
			return err
		}
		fmt.Printf("пользователь создан: %s\nпароль: %s\n(сохраните его, повторно он не показывается)\n", strings.ToLower(*login), pw)
		return nil
	case "passwd":
		login := fl.String("login", "", "логин")
		fl.Parse(args)
		svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer closeDB()
		pw := controller.RandomPassword()
		if err := svc.SetPassword(context.Background(), strings.ToLower(*login), pw); err != nil {
			return err
		}
		fmt.Printf("новый пароль для %s: %s\n", *login, pw)
		return nil
	case "room", "invite":
		return runAdmin(sub, args)
	case "version":
		fmt.Println("zpt-controller", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return errors.New("неизвестная команда " + sub + "\n\n" + usage)
}

// runAdmin handles "room ..." and "invite ..." for scripts and automation.
// It works on the database directly, also while the server is running.
func runAdmin(sub string, args []string) error {
	if len(args) == 0 {
		return errors.New("использование:\n" + usage)
	}
	action, args := args[0], args[1:]
	fl := flag.NewFlagSet(sub+" "+action, flag.ExitOnError)
	db := fl.String("db", "zpt-controller.db", "файл базы данных")
	ctx := context.Background()
	switch sub + " " + action {
	case "room create":
		owner := fl.String("owner", "", "логин владельца комнаты")
		name := fl.String("name", "", "название комнаты")
		subnet := fl.String("subnet", "", "подсеть (по умолчанию выбирается сама)")
		policy := fl.String("policy", "manual", "вступление: manual (с одобрением) или auto")
		fl.Parse(args)
		svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer closeDB()
		u, err := svc.UserByLogin(ctx, *owner)
		if err != nil {
			return fmt.Errorf("пользователь %q не найден", *owner)
		}
		r, err := svc.CreateRoom(ctx, u, *name, *subnet, *policy)
		if err != nil {
			return err
		}
		fmt.Printf("room id: %s\nsubnet:  %s\n", r.ID, r.Subnet)
		return nil
	case "room list":
		fl.Parse(args)
		svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer closeDB()
		rooms, err := svc.Rooms(ctx, &store.User{IsAdmin: true})
		if err != nil {
			return err
		}
		for _, r := range rooms {
			fmt.Printf("%s  %-18s  %s\n", r.ID, r.Subnet, r.Name)
		}
		return nil
	case "invite create":
		room := fl.String("room", "", "ID комнаты")
		pub := fl.String("url", "", "внешний адрес контроллера, например https://zpt.example.org")
		uses := fl.Int("uses", 1, "сколько раз можно использовать (0 — без ограничений)")
		hours := fl.Int("hours", 24, "срок действия, часов")
		auto := fl.Bool("auto", false, "вступление без одобрения")
		note := fl.String("note", "", "заметка")
		fl.Parse(args)
		if *pub == "" {
			return errors.New("нужен -url: по нему узлы найдут контроллер")
		}
		svc, closeDB, err := openService(*db, slog.New(slog.DiscardHandler))
		if err != nil {
			return err
		}
		defer closeDB()
		inv, err := svc.CreateInvite(ctx, &store.User{IsAdmin: true, Login: "cli"}, strings.TrimRight(*pub, "/"), *room,
			*uses, time.Duration(*hours)*time.Hour, *auto, *note)
		if err != nil {
			return err
		}
		fmt.Println(inv.String())
		return nil
	}
	return fmt.Errorf("неизвестная команда %s %s", sub, action)
}

// sniList defaults the REALITY server names to the destination host.
func sniList(sni, dest string) []string {
	if l := splitList(sni); len(l) > 0 {
		return l
	}
	if host, _, err := net.SplitHostPort(dest); err == nil {
		return []string{host}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func openService(db string, log *slog.Logger) (*controller.Service, func(), error) {
	st, err := store.Open(db)
	if err != nil {
		return nil, nil, err
	}
	svc, err := controller.NewService(st, log)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return svc, func() { st.Close() }, nil
}
