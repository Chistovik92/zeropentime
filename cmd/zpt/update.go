// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/update"
)

// "zpt update": find a newer signed release and install it the way this
// node was installed (MSI, deb/rpm or the binary from an archive).
func cmdUpdate(args []string) error {
	fl := flag.NewFlagSet("update", flag.ExitOnError)
	cfgPath, explicit := configFlag(fl)
	check := fl.Bool("check", false, "только проверить, есть ли обновление")
	channel := fl.String("channel", "", "канал: stable или beta (по умолчанию — update_channel из конфига)")
	yes := fl.Bool("yes", false, "не спрашивать подтверждения")
	fl.Parse(args)
	ch := *channel
	if ch == "" {
		if cfg, err := nodeConfig(*cfgPath, explicit()); err == nil {
			ch = cfg.UpdateChannelName()
		} else {
			ch = "stable"
		}
	}
	if ch == "off" {
		ch = "stable" // "off" only stops the automatic checks
	}
	if ch != "stable" && ch != "beta" {
		return errors.New("-channel: stable или beta")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	fmt.Printf("текущая версия: %s, канал: %s\n", version, ch)
	r, err := update.Check(ctx, version, ch)
	if err != nil {
		return err
	}
	if r == nil {
		fmt.Println("обновлений нет")
		return nil
	}
	fmt.Printf("доступна версия %s (подпись релиза проверена)\n", r.Version)
	if *check {
		return nil
	}
	if err := requireAdmin(); err != nil {
		return errors.New("установка обновления: запустите от имени администратора (sudo)")
	}
	if !*yes {
		fmt.Printf("Установить %s? [д/Н]: ", r.Version)
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "д", "да", "y", "yes":
		default:
			fmt.Println("отменено")
			return nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	kind, restart, err := update.Install(ctx, r, exe)
	if err != nil {
		return err
	}
	fmt.Printf("установлена версия %s (%s)\n", r.Version, kind)
	if restart {
		if err := serviceControl("restart"); err != nil {
			fmt.Println("перезапустите узел, чтобы работала новая версия:", err)
		} else {
			fmt.Println("служба перезапущена")
		}
	}
	return nil
}
