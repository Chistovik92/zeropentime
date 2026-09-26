// SPDX-License-Identifier: MPL-2.0

// Command signrelease writes release.json (the version and the SHA-256 of
// every file in a directory) and release.json.sig, signed with the release
// key from ZPT_RELEASE_KEY (base64 Ed25519 seed). Used by the release
// workflow:
//
//	go run ./tools/signrelease -version 0.6.2 [-prerelease] DIR
//
// With -verify it checks a downloaded release instead: the signature with
// the key built into zpt and the hash of every file listed.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Chistovik92/zeropentime/internal/update"
)

func main() {
	ver := flag.String("version", "", "версия релиза (без v)")
	pre := flag.Bool("prerelease", false, "предварительный релиз (канал beta)")
	verify := flag.Bool("verify", false, "проверить подпись и файлы вместо подписи")
	flag.Parse()
	var err error
	if *verify {
		err = check(*ver, flag.Arg(0))
	} else {
		err = run(*ver, *pre, flag.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "signrelease:", err)
		os.Exit(1)
	}
}

func run(ver string, pre bool, dir string) error {
	if ver == "" || dir == "" {
		return fmt.Errorf("использование: signrelease -version X.Y.Z [-prerelease] КАТАЛОГ")
	}
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("ZPT_RELEASE_KEY"))
	if err != nil {
		return fmt.Errorf("ZPT_RELEASE_KEY: %w", err)
	}
	m := &update.Manifest{Version: ver, Prerelease: pre, Assets: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == update.ManifestName || e.Name() == update.SigName {
			continue
		}
		h, err := update.HashFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		m.Assets[e.Name()] = h
	}
	payload, sig, err := update.Sign(seed, m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, update.ManifestName), payload, 0o644); err != nil {
		return err
	}
	fmt.Printf("подписано файлов: %d\n", len(m.Assets))
	return os.WriteFile(filepath.Join(dir, update.SigName), []byte(sig+"\n"), 0o644)
}

func check(ver, dir string) error {
	payload, err := os.ReadFile(filepath.Join(dir, update.ManifestName))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dir, update.SigName))
	if err != nil {
		return err
	}
	m, err := update.Verify(payload, string(sig))
	if err != nil {
		return err
	}
	if ver != "" && m.Version != ver {
		return fmt.Errorf("манифест подписан для %s, ожидалась %s", m.Version, ver)
	}
	for name, want := range m.Assets {
		h, err := update.HashFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if h != want {
			return fmt.Errorf("%s: хеш не совпадает", name)
		}
	}
	fmt.Printf("подпись верна, версия %s, файлов: %d\n", m.Version, len(m.Assets))
	return nil
}
