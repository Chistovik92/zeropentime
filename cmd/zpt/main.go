// Command zpt is the zeropentime node, and later also controller and relay.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Chistovik92/zeropentime/internal/config"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/node"
	"github.com/Chistovik92/zeropentime/internal/obfs"
)

var version = "0.0.0-dev"

const usage = `zpt — zeropentime: децентрализованные виртуальные LAN на AmneziaWG

Использование:
  zpt keygen  [-key ФАЙЛ]     создать ключ узла (если его ещё нет)
  zpt room new                 сгенерировать секрет новой комнаты
  zpt pubkey  -c КОНФИГ        показать публичные ключи узла по комнатам
  zpt up      -c КОНФИГ        запустить узел
  zpt version                  версия
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
	case "up":
		err = cmdUp(args)
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

func cmdKeygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	path := fl.String("key", config.DefaultKeyPath(), "путь к файлу ключа")
	fl.Parse(args)

	if id, err := identity.Load(*path); err == nil {
		fmt.Printf("ключ уже существует: %s\nnode id: %s\n", *path, id.NodeID())
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	id, err := identity.Generate()
	if err != nil {
		return err
	}
	if err := id.Save(*path); err != nil {
		return err
	}
	fmt.Printf("ключ создан: %s\nnode id: %s\n", *path, id.NodeID())
	return nil
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

func loadConfigAndKey(args []string, name string) (*config.Config, *identity.Identity, error) {
	fl := flag.NewFlagSet(name, flag.ExitOnError)
	cfgPath := fl.String("c", "zpt.yaml", "путь к конфигу")
	fl.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil, nil, err
	}
	id, err := identity.Load(cfg.KeyPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("нет ключа узла %s — выполните: zpt keygen -key %q", cfg.KeyPath(), cfg.KeyPath())
	}
	return cfg, id, err
}

func cmdPubkey(args []string) error {
	cfg, id, err := loadConfigAndKey(args, "pubkey")
	if err != nil {
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

func cmdUp(args []string) error {
	cfg, id, err := loadConfigAndKey(args, "up")
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if cfg.LogLevel != "" {
		if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
			return fmt.Errorf("log_level: %w", err)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	n, err := node.Start(cfg, id, log)
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
