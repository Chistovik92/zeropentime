// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	unitPath          = "/etc/systemd/system/zpt.service"
	defaultConfigPath = "/etc/zeropentime/zpt.yaml"
)

func runningAsService() bool                                { return false }
func serveAsService(func(stop <-chan struct{}) error) error { return nil }

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func serviceInstall(exe, cfg string) error {
	unit := fmt.Sprintf(`# Установлено командой zpt service install.
[Unit]
Description=zeropentime node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s up -c %s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, exe, cfg)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("%w (нужен root: sudo)", err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", "zpt")
}

func serviceUninstall() error {
	systemctl("disable", "--now", "zpt")
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return systemctl("daemon-reload")
}

func serviceControl(action string) error {
	switch action {
	case "start", "stop", "restart":
		return systemctl(action, "zpt")
	case "status":
		err := systemctl("status", "--no-pager", "zpt")
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil // systemctl status exits non-zero for stopped units
		}
		return err
	}
	return fmt.Errorf("неизвестное действие %q", action)
}

func showLogs(follow bool, lines int) error {
	args := []string{"-u", "zpt", "--no-pager", "-n", fmt.Sprint(lines)}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.Command("journalctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("journalctl: %w (журнал узла, запущенного не службой, — в его терминале)", err)
	}
	return nil
}

func logFile() string { return "" }

func ensureConfigDir(cfg string) error { return os.MkdirAll(filepath.Dir(cfg), 0o755) }
