// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/node"
)

// "zpt open ССЫЛКА" is what the system runs for zpt:// links (installed by
// the MSI and the deb/rpm packages). A link may come from any web page, so
// it shows where the link leads and joins only after the user agrees.
func cmdOpen(args []string) error {
	if len(args) != 1 {
		return errors.New("использование: zpt open \"zpt://…\"")
	}
	link := strings.TrimSpace(args[0])
	err := openLink(link)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
	}
	pause()
	if err != nil {
		os.Exit(1)
	}
	return nil
}

func openLink(link string) error {
	var what string
	switch {
	case strings.HasPrefix(link, "zpt://local"):
		l, err := node.ParseLocalLink(link)
		if err != nil {
			return err
		}
		what = fmt.Sprintf("комната без контроллера %s, её админ — узел %s (%v)", l.RoomID, l.Owner, l.Endpoints)
	case strings.HasPrefix(link, "zpt://join"):
		inv, err := api.ParseInvite(link)
		if err != nil {
			return err
		}
		what = fmt.Sprintf("комната %s на контроллере %s", inv.RoomID, inv.Controller)
	default:
		return errors.New("это не приглашение zeropentime (zpt://join?… или zpt://local?…)")
	}
	if !isAdmin() {
		fmt.Println("Для вступления нужны права администратора — запрашиваю их…")
		return relaunchAsAdmin(link)
	}
	fmt.Println("Приглашение в zeropentime:")
	fmt.Println("  ", what)
	fmt.Print("Вступить в эту комнату с этого устройства? [д/Н]: ")
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "д", "да", "y", "yes":
	default:
		fmt.Println("отменено")
		return nil
	}
	return cmdJoin([]string{link})
}

func pause() {
	fmt.Print("\nНажмите Enter, чтобы закрыть окно…")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
