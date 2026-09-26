// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "zeropentime"

var defaultConfigPath = filepath.Join(programData(), "zeropentime", "zpt.yaml")

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

// logFile is where the service writes its log ("zpt logs" reads it).
func logFile() string { return filepath.Join(programData(), "zeropentime", "zpt.log") }

func runningAsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

type handler struct {
	run func(stop <-chan struct{}) error
}

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- h.run(stop) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "ошибка:", err)
				return false, 1
			}
			return false, 0
		}
	}
}

func serveAsService(run func(stop <-chan struct{}) error) error {
	return svc.Run(serviceName, handler{run})
}

func serviceInstall(exe, cfg string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("службы Windows: %w (запустите терминал от имени администратора)", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return errors.New("служба уже установлена: zpt service uninstall, затем install")
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "zeropentime",
		Description: "Узел zeropentime: виртуальные LAN на AmneziaWG",
		StartType:   mgr.StartAutomatic,
	}, "up", "-c", cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 3 * time.Second}}, 60)
	return s.Start()
}

func openService() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("службы Windows: %w (запустите терминал от имени администратора)", err)
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, errors.New("служба не установлена: zpt service install")
	}
	return m, s, nil
}

func waitState(s *mgr.Service, want svc.State) error {
	for range 100 {
		q, err := s.Query()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("служба не ответила за 10 с")
}

func serviceUninstall() error {
	m, s, err := openService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if q, err := s.Query(); err == nil && q.State != svc.Stopped {
		s.Control(svc.Stop)
		waitState(s, svc.Stopped)
	}
	return s.Delete()
}

var stateName = map[svc.State]string{
	svc.Stopped: "остановлена", svc.StartPending: "запускается", svc.StopPending: "останавливается",
	svc.Running: "работает", svc.ContinuePending: "продолжается", svc.PausePending: "приостанавливается", svc.Paused: "приостановлена",
}

func serviceControl(action string) error {
	m, s, err := openService()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	switch action {
	case "start":
		if err := s.Start(); err != nil {
			return err
		}
		return waitState(s, svc.Running)
	case "stop":
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		return waitState(s, svc.Stopped)
	case "restart":
		if q, _ := s.Query(); q.State != svc.Stopped {
			s.Control(svc.Stop)
			if err := waitState(s, svc.Stopped); err != nil {
				return err
			}
		}
		if err := s.Start(); err != nil {
			return err
		}
		return waitState(s, svc.Running)
	case "status":
		q, err := s.Query()
		if err != nil {
			return err
		}
		c, _ := s.Config()
		fmt.Printf("служба %s: %s\nзапуск: %s\nжурнал: %s\n", serviceName, stateName[q.State], c.BinaryPathName, logFile())
		return nil
	}
	return fmt.Errorf("неизвестное действие %q", action)
}

// showLogs prints the end of the service log and, with follow, new lines.
func showLogs(follow bool, lines int) error {
	f, err := os.Open(logFile())
	if err != nil {
		return fmt.Errorf("%w (журнал пишет служба; узел, запущенный вручную, пишет в свой терминал)", err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	const tailBytes = 256 << 10
	off := max(fi.Size()-tailBytes, 0)
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(f)
	var starts []int
	for i, c := range b {
		if c == '\n' && i+1 < len(b) {
			starts = append(starts, i+1)
		}
	}
	from := 0
	if len(starts) >= lines {
		from = starts[len(starts)-lines]
	}
	os.Stdout.Write(b[from:])
	for follow {
		time.Sleep(500 * time.Millisecond)
		if _, err := io.Copy(os.Stdout, f); err != nil {
			return err
		}
	}
	return nil
}

func ensureConfigDir(cfg string) error { return os.MkdirAll(filepath.Dir(cfg), 0o755) }
