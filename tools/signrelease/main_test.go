// SPDX-License-Identifier: MPL-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/Chistovik92/zeropentime/internal/update"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("ZPT_RELEASE_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
	old := update.PublicKey
	update.PublicKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { update.PublicKey = old }()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "zpt_0.6.2_linux_amd64.tar.gz"), []byte("bin"), 0o644)
	os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte("sums"), 0o644)
	if err := run("0.6.2", false, dir); err != nil {
		t.Fatal(err)
	}
	if err := check("0.6.2", dir); err != nil {
		t.Fatal(err)
	}
	if err := check("0.6.3", dir); err == nil {
		t.Fatal("wrong version accepted")
	}
	os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte("evil"), 0o644)
	if err := check("0.6.2", dir); err == nil {
		t.Fatal("changed file accepted")
	}
}
