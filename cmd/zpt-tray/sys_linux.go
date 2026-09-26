// SPDX-License-Identifier: MPL-2.0

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Clipboard through the usual command-line tools (Wayland or X11).
func setClipboard(text string) error {
	for _, c := range [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "-ib"}} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	return errors.New("нет wl-copy, xclip или xsel")
}

func getClipboard() (string, error) {
	for _, c := range [][]string{{"wl-paste", "-n"}, {"xclip", "-o", "-selection", "clipboard"}, {"xsel", "-ob"}} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			return "", err
		}
		if err := cmd.Start(); err != nil {
			return "", err
		}
		b, _ := io.ReadAll(io.LimitReader(out, 4096))
		cmd.Wait()
		return string(b), nil
	}
	return "", errors.New("нет wl-paste, xclip или xsel")
}

func zptPath() string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "zpt")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "zpt"
}

// runZpt runs "zpt ARGS" as root through polkit and waits.
func runZpt(args []string) error {
	return exec.Command("pkexec", append([]string{zptPath()}, args...)...).Run()
}

// inTerminal runs a command in a terminal window.
func inTerminal(args ...string) error {
	for _, t := range [][]string{{"x-terminal-emulator", "-e"}, {"gnome-terminal", "--"}, {"konsole", "-e"}, {"xfce4-terminal", "-x"}, {"xterm", "-e"}} {
		if _, err := exec.LookPath(t[0]); err == nil {
			return exec.Command(t[0], append(t[1:], args...)...).Start()
		}
	}
	return errors.New("не нашёл терминал")
}

func openInvite(link string) error { return inTerminal(zptPath(), "open", link) }

func showStatus() error {
	return inTerminal("sh", "-c", `"$0" status; printf '\nНажмите Enter…'; read _`, zptPath())
}
