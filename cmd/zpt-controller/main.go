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
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Chistovik92/zeropentime/internal/controller"
	"github.com/Chistovik92/zeropentime/internal/store"
)

var version = "0.1.2-dev"

const usage = `zpt-controller — контроллер zeropentime (админ-панель + API для узлов)

  zpt-controller serve   -db ФАЙЛ [-listen :8080] [-url https://...] [-tls-cert Ф -tls-key Ф] [-trust-proxy]
  zpt-controller useradd -db ФАЙЛ -login ЛОГИН [-admin]
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
	case "version":
		fmt.Println("zpt-controller", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return errors.New("неизвестная команда " + sub + "\n\n" + usage)
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
