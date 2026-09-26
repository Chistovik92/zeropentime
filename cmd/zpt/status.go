// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Chistovik92/zeropentime/internal/control"
)

func fetchStatus(args []string, name string) (*control.Status, *flag.FlagSet, bool, error) {
	fl := flag.NewFlagSet(name, flag.ExitOnError)
	asJSON := fl.Bool("json", false, "вывод в JSON (для скриптов)")
	fl.Parse(args)
	s, err := control.NewClient().Status()
	return s, fl, *asJSON, err
}

func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	d := time.Since(t).Round(time.Second)
	switch {
	case d < 5*time.Second:
		return "только что"
	case d < time.Minute:
		return fmt.Sprintf("%d с назад", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин назад", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d ч назад", int(d.Hours()))
	}
}

func bytesStr(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f КБ", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d Б", b)
	}
}

var pathName = map[string]string{"direct": "напрямую", "relay": "через relay", "none": "нет связи"}

func cmdStatus(args []string) error {
	s, _, asJSON, err := fetchStatus(args, "status")
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(s)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "узел:\t%s (zpt %s), работает с %s\n", s.NodeID, s.Version, s.Started.Format("02.01.2006 15:04"))
	port := fmt.Sprintf("UDP %d", s.UDPPort)
	if s.PortMap.IsValid() {
		port += ", проброшен на роутере как " + s.PortMap.String()
	}
	fmt.Fprintf(w, "порт:\t%s\n", port)
	for _, c := range s.Controllers {
		state := "связь есть, обновлено " + ago(c.LastSync)
		if c.Error != "" {
			state = "нет связи: " + c.Error
		}
		fmt.Fprintf(w, "контроллер:\t%s — %s\n", c.URL, state)
		if c.NAT != "" {
			fmt.Fprintf(w, "  NAT:\t%s, внешний адрес %v\n", c.NAT, c.Mapped)
		}
	}
	if s.Relay != "" {
		state := "подключение…"
		if s.RelayReady {
			state = "готов, через " + strings.ToUpper(s.RelayVia)
		}
		fmt.Fprintf(w, "relay:\t%s — %s\n", s.Relay, state)
	}
	exit := "не используется"
	switch {
	case s.Exit.Active:
		exit = fmt.Sprintf("через %s в комнате %s", s.Exit.Member, s.Exit.Room)
	case s.Exit.Choice == "off":
		exit = "выключен (zpt exit off)"
	case s.Exit.Choice != "auto":
		exit = "выбран " + s.Exit.Choice + ", но сейчас недоступен"
	}
	fmt.Fprintf(w, "exit:\t%s\n", exit)
	if s.KillSwitch {
		lan := "закрыта"
		if s.Exit.AllowLAN {
			lan = "доступна"
		}
		fmt.Fprintf(w, "kill switch:\tвключён (без exit интернета нет), локальная сеть %s\n", lan)
	}
	if len(s.DNS) > 0 {
		fmt.Fprintf(w, "DNS:\t%v (через комнату %s)\n", s.DNS, s.DNSRoom)
	} else {
		fmt.Fprintf(w, "DNS:\tсистемный\n")
	}
	fmt.Fprintf(w, "комнаты:\t%d\n", len(s.Rooms))
	w.Flush()
	if len(s.Rooms) > 0 {
		fmt.Println()
		return printRooms(s)
	}
	return nil
}

func printRooms(s *control.Status) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "КОМНАТА\tИНТЕРФЕЙС\tАДРЕС\tПИРЫ\tОСОБОЕ")
	for _, r := range s.Rooms {
		online := 0
		for _, p := range r.Peers {
			if p.Path != "none" {
				online++
			}
		}
		var extra []string
		if r.Exit {
			extra = append(extra, "интернет через exit")
		}
		if r.ExitNode {
			extra = append(extra, "этот узел — exit")
		}
		if len(r.Routing) > 0 {
			extra = append(extra, fmt.Sprintf("раздаёт сети %v", r.Routing))
		}
		if len(r.Routes) > 0 {
			extra = append(extra, fmt.Sprintf("сети участников %v", r.Routes))
		}
		if len(r.DNS) > 0 {
			extra = append(extra, fmt.Sprintf("DNS %v", r.DNS))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d из %d на связи\t%s\n", r.Name, r.Interface, r.Address, online, len(r.Peers), strings.Join(extra, "; "))
	}
	return w.Flush()
}

func cmdRooms(args []string) error {
	s, _, asJSON, err := fetchStatus(args, "rooms")
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(s.Rooms)
	}
	if len(s.Rooms) == 0 {
		fmt.Println("комнат нет: вступите по приглашению (zpt join) или дождитесь одобрения")
		return nil
	}
	return printRooms(s)
}

func cmdPeers(args []string) error {
	s, fl, asJSON, err := fetchStatus(args, "peers")
	if err != nil {
		return err
	}
	rooms := s.Rooms
	if fl.NArg() == 1 {
		rooms = nil
		for _, r := range s.Rooms {
			if r.Name == fl.Arg(0) || r.ID == fl.Arg(0) {
				rooms = append(rooms, r)
			}
		}
		if len(rooms) == 0 {
			return fmt.Errorf("комната %q не запущена", fl.Arg(0))
		}
	} else if fl.NArg() > 1 {
		return errors.New("использование: zpt peers [КОМНАТА] [-json]")
	}
	if asJSON {
		return printJSON(rooms)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "КОМНАТА\tПИР\tIP\tСВЯЗЬ\tRTT\tАДРЕС\tРУКОПОЖАТИЕ\tПРИНЯТО\tОТПРАВЛЕНО")
	for _, r := range rooms {
		for _, p := range r.Peers {
			rtt := "-"
			if p.RTT > 0 {
				rtt = p.RTT.Round(100 * time.Microsecond).String()
			}
			ep := p.Endpoint
			if ep == "" || p.Path == "relay" {
				ep = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, p.Name, p.IP, pathName[p.Path], rtt, ep,
				ago(p.LastHandshake), bytesStr(p.RxBytes), bytesStr(p.TxBytes))
		}
	}
	return w.Flush()
}

// reloadNode asks a running node to apply the state file now.
func reloadNode() {
	err := control.NewClient().Reload()
	switch {
	case err == nil:
		fmt.Println("применено")
	case errors.Is(err, control.ErrNotRunning):
		fmt.Println("сохранено; узел не запущен — выбор применится при запуске")
	default:
		fmt.Println("сохранено; запущенный узел применит за пару секунд (", err, ")")
	}
}
