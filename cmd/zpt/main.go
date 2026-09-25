// Command zpt is the zeropentime node and controller.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/client"
	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/controller"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/node"
	"github.com/Chistovik92/zeropentime/internal/obfs"
	"github.com/Chistovik92/zeropentime/internal/store"
)

var version = "0.1.0-dev"

const usage = `zpt — zeropentime: децентрализованные виртуальные LAN на AmneziaWG

Узел:
  zpt keygen  [-key ФАЙЛ]                  создать ключ узла (если его ещё нет)
  zpt join    [-c КОНФИГ] [-name ИМЯ] ССЫЛКА  вступить в комнату по приглашению
  zpt leave   [-c КОНФИГ] ID_КОМНАТЫ        выйти из комнаты
  zpt up      [-c КОНФИГ]                   запустить узел
  zpt pubkey  -c КОНФИГ                     публичные ключи узла в статических комнатах
  zpt room new                              секрет статической комнаты (без контроллера)

Контроллер (админ-панель + API для узлов):
  zpt controller serve   -db ФАЙЛ [-listen :8080] [-url https://...] [-tls-cert Ф -tls-key Ф] [-trust-proxy]
  zpt controller useradd -db ФАЙЛ -login ЛОГИН [-admin]
  zpt controller passwd  -db ФАЙЛ -login ЛОГИН

  zpt version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "keygen":
		err = cmdKeygen(args)
	case "room":
		err = cmdRoom(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "join":
		err = cmdJoin(args)
	case "leave":
		err = cmdLeave(args)
	case "up":
		err = cmdUp(args)
	case "controller":
		err = cmdController(args)
	case "version":
		fmt.Println("zpt", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func newLogger(level string) (*slog.Logger, error) {
	l := slog.LevelInfo
	if level != "" {
		if err := l.UnmarshalText([]byte(level)); err != nil {
			return nil, fmt.Errorf("log_level: %w", err)
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

func cmdKeygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	path := fl.String("key", config.DefaultKeyPath(), "путь к файлу ключа")
	fl.Parse(args)
	id, created, err := loadOrCreateKey(*path)
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("ключ создан: %s\n", *path)
	} else {
		fmt.Printf("ключ уже существует: %s\n", *path)
	}
	fmt.Printf("node id: %s\n", id.NodeID())
	return nil
}

func loadOrCreateKey(path string) (*identity.Identity, bool, error) {
	id, err := identity.Load(path)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	if id, err = identity.Generate(); err != nil {
		return nil, false, err
	}
	if err := id.Save(path); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

func cmdRoom(args []string) error {
	if len(args) == 0 || args[0] != "new" {
		return errors.New("использование: zpt room new")
	}
	s, err := obfs.NewSecret()
	if err != nil {
		return err
	}
	fmt.Printf("room id: %s\nsecret:  %s\n\nРаздайте секрет всем участникам комнаты (поле secret в конфиге).\n", s.RoomID(), s)
	return nil
}

// nodeConfig loads the config file if it exists; without one, defaults
// are used (a node that only follows controllers needs no config).
func nodeConfig(path string, explicit bool) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		cfg = &config.Config{}
		return cfg, cfg.Validate()
	}
	return cfg, err
}

func configFlag(fl *flag.FlagSet) (*string, func() bool) {
	p := fl.String("c", "zpt.yaml", "путь к конфигу (необязателен для узлов с контроллером)")
	return p, func() bool {
		set := false
		fl.Visit(func(f *flag.Flag) { set = set || f.Name == "c" })
		return set
	}
}

func cmdPubkey(args []string) error {
	fl := flag.NewFlagSet("pubkey", flag.ExitOnError)
	cfgPath, _ := configFlag(fl)
	fl.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	id, err := identity.Load(cfg.KeyPath())
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("нет ключа узла %s — выполните: zpt keygen -key %q", cfg.KeyPath(), cfg.KeyPath())
	} else if err != nil {
		return err
	}
	fmt.Printf("node id: %s\n", id.NodeID())
	for _, r := range cfg.Rooms {
		k, err := id.RoomKey(r.Secret.RoomID())
		if err != nil {
			return err
		}
		fmt.Printf("room %-11s public_key: %s\n", r.Name, k.Public())
	}
	return nil
}

func cmdJoin(args []string) error {
	fl := flag.NewFlagSet("join", flag.ExitOnError)
	cfgPath, explicit := configFlag(fl)
	host, _ := os.Hostname()
	name := fl.String("name", host, "имя устройства в комнате")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("использование: zpt join [-name ИМЯ] \"zpt://join?...\"")
	}
	inv, err := api.ParseInvite(fl.Arg(0))
	if err != nil {
		return err
	}
	cfg, err := nodeConfig(*cfgPath, explicit())
	if err != nil {
		return err
	}
	id, _, err := loadOrCreateKey(cfg.KeyPath())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.New(inv.Controller, id, version).Join(ctx, inv, *name, api.Endpoints{UDPPort: uint16(cfg.Port())})
	if err != nil {
		if client.IsForbidden(err) {
			return errors.New("приглашение недействительно: истекло, отозвано, израсходовано или вы заблокированы в комнате")
		}
		return err
	}
	statePath := node.StatePath(cfg.KeyPath())
	st, err := node.LoadState(statePath)
	if err != nil {
		return err
	}
	st.Pin(inv.Controller, inv.RoomID, inv.RoomKey)
	if err := st.Save(statePath); err != nil {
		return err
	}
	fmt.Printf("комната: %s\n", resp.RoomName)
	switch resp.Status {
	case "active":
		fmt.Println("статус: вы участник. Если узел запущен (zpt up), комната появится в течение нескольких секунд.")
	default:
		fmt.Println("статус: ждёт одобрения администратора. Комната включится автоматически после одобрения.")
	}
	return nil
}

func cmdLeave(args []string) error {
	fl := flag.NewFlagSet("leave", flag.ExitOnError)
	cfgPath, explicit := configFlag(fl)
	fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("использование: zpt leave ID_КОМНАТЫ")
	}
	roomID := fl.Arg(0)
	cfg, err := nodeConfig(*cfgPath, explicit())
	if err != nil {
		return err
	}
	id, err := identity.Load(cfg.KeyPath())
	if err != nil {
		return err
	}
	statePath := node.StatePath(cfg.KeyPath())
	st, err := node.LoadState(statePath)
	if err != nil {
		return err
	}
	ctrl, ok := st.Unpin(roomID)
	if !ok {
		return fmt.Errorf("комната %s не найдена в %s", roomID, statePath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.New(ctrl, id, version).Leave(ctx, roomID); err != nil {
		fmt.Fprintln(os.Stderr, "предупреждение: контроллер не ответил, комната удалена только локально:", err)
	}
	if err := st.Save(statePath); err != nil {
		return err
	}
	fmt.Println("вы вышли из комнаты")
	return nil
}

func cmdUp(args []string) error {
	fl := flag.NewFlagSet("up", flag.ExitOnError)
	cfgPath, explicit := configFlag(fl)
	fl.Parse(args)
	cfg, err := nodeConfig(*cfgPath, explicit())
	if err != nil {
		return err
	}
	id, err := identity.Load(cfg.KeyPath())
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("нет ключа узла %s — выполните zpt keygen или zpt join", cfg.KeyPath())
	} else if err != nil {
		return err
	}
	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		return err
	}
	statePath := node.StatePath(cfg.KeyPath())
	if st, err := node.LoadState(statePath); err == nil && len(st.Controllers) == 0 && len(cfg.Rooms) == 0 {
		return errors.New("нет ни одной комнаты: вступите по приглашению (zpt join) или опишите комнаты в конфиге")
	}
	n, err := node.Start(node.Options{Config: cfg, Identity: id, Log: log, StatePath: statePath, Version: version})
	if err != nil {
		return err
	}
	defer n.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Info("остановка")
	return nil
}

func cmdController(args []string) error {
	if len(args) == 0 {
		return errors.New("использование: zpt controller serve|useradd|passwd ...")
	}
	sub, args := args[0], args[1:]
	fl := flag.NewFlagSet("controller "+sub, flag.ExitOnError)
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
		log, err := newLogger(*level)
		if err != nil {
			return err
		}
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
	}
	return fmt.Errorf("неизвестная подкоманда controller %q", sub)
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
