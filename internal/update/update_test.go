// SPDX-License-Identifier: MPL-2.0

package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.6.2", "0.6.1", true}, {"0.6.1", "0.6.2", false}, {"0.6.2", "0.6.2", false},
		{"0.10.0", "0.9.9", true}, {"1.0.0", "0.99.99", true}, {"v0.6.2", "0.6.1", true},
		{"0.6.2", "0.6.2-rc.1", true}, {"0.6.2-rc.1", "0.6.2", false}, {"0.6.2-rc.2", "0.6.2-rc.1", true},
		{"0.6.2", "0.6.2-dev", true}, {"0.6.2", "dev", true}, {"junk", "0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestAssetName(t *testing.T) {
	for k, want := range map[Kind]string{
		KindMSI: "zpt_0.6.2_windows_amd64.msi", KindDeb: "zeropentime_0.6.2_linux_amd64.deb",
		KindRPM: "zeropentime_0.6.2_linux_amd64.rpm",
	} {
		goos := "linux"
		if k == KindMSI {
			goos = "windows"
		}
		if got := AssetName(k, "0.6.2", goos, "amd64"); got != want {
			t.Errorf("%v: %s", k, got)
		}
	}
	if AssetName(KindArchive, "0.6.2", "windows", "arm64") != "zpt_0.6.2_windows_arm64.zip" ||
		AssetName(KindArchive, "0.6.2", "linux", "arm64") != "zpt_0.6.2_linux_arm64.tar.gz" {
		t.Error("archive names")
	}
}

// fakeHub is a GitHub with releases signed by a test key.
type fakeHub struct {
	srv      *httptest.Server
	seed     []byte
	releases []map[string]any
	files    map[string][]byte
}

func newHub(t *testing.T) *fakeHub {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &fakeHub{seed: priv.Seed(), files: map[string][]byte{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repo/releases" {
			json.NewEncoder(w).Encode(h.releases)
			return
		}
		b, ok := h.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(h.srv.Close)
	oldAPI, oldKey := API, PublicKey
	API, PublicKey = h.srv.URL+"/repo", base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { API, PublicKey = oldAPI, oldKey })
	return h
}

// add publishes a release; tamper changes a file after signing; signVer
// is the version put into the manifest ("" = the tag's).
func (h *fakeHub) add(t *testing.T, tag string, pre bool, files map[string][]byte, signVer string, tamper bool) {
	v := strings.TrimPrefix(tag, "v")
	if signVer == "" {
		signVer = v
	}
	m := &Manifest{Version: signVer, Prerelease: pre, Assets: map[string]string{}}
	var assets []map[string]string
	for name, b := range files {
		sum := sha256.Sum256(b)
		m.Assets[name] = hex.EncodeToString(sum[:])
		if tamper {
			b = append([]byte("evil"), b...)
		}
		h.files["/dl/"+tag+"/"+name] = b
		assets = append(assets, map[string]string{"name": name, "browser_download_url": h.srv.URL + "/dl/" + tag + "/" + name})
	}
	payload, sig, err := Sign(h.seed, m)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{ManifestName: payload, SigName: []byte(sig)} {
		h.files["/dl/"+tag+"/"+name] = b
		assets = append(assets, map[string]string{"name": name, "browser_download_url": h.srv.URL + "/dl/" + tag + "/" + name})
	}
	h.releases = append(h.releases, map[string]any{"tag_name": tag, "prerelease": pre, "assets": assets})
}

func TestCheckChannelsAndDownload(t *testing.T) {
	h := newHub(t)
	h.add(t, "v0.6.2", false, map[string][]byte{"a.bin": []byte("stable")}, "", false)
	h.add(t, "v0.6.3-rc.1", true, map[string][]byte{"a.bin": []byte("beta")}, "", false)
	h.releases = append(h.releases, map[string]any{"tag_name": "v0.9.0", "assets": []any{}}) // unsigned: ignored
	ctx := context.Background()

	r, err := Check(ctx, "0.6.1", "stable")
	if err != nil || r == nil || r.Version != "0.6.2" {
		t.Fatalf("stable: %+v %v", r, err)
	}
	p, err := r.Download(ctx, "a.bin", t.TempDir())
	if b, _ := os.ReadFile(p); err != nil || string(b) != "stable" {
		t.Fatalf("download: %v %q", err, b)
	}
	if r, err := Check(ctx, "0.6.1", "beta"); err != nil || r == nil || r.Version != "0.6.3-rc.1" {
		t.Fatalf("beta: %+v %v", r, err)
	}
	if r, err := Check(ctx, "0.6.2", "stable"); err != nil || r != nil {
		t.Fatalf("up to date: %+v %v", r, err)
	}
}

func TestCheckRejects(t *testing.T) {
	ctx := context.Background()

	h := newHub(t)
	h.add(t, "v0.6.2", false, map[string][]byte{"a.bin": []byte("x")}, "", true)
	r, err := Check(ctx, "0.6.1", "stable")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Download(ctx, "a.bin", t.TempDir()); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("tampered file: %v", err)
	}

	h = newHub(t)
	h.add(t, "v0.9.9", false, map[string][]byte{"a.bin": []byte("x")}, "0.5.0", false) // an old manifest under a new tag
	if _, err := Check(ctx, "0.6.1", "stable"); err == nil {
		t.Fatal("manifest of another version accepted")
	}

	h = newHub(t)
	h.add(t, "v0.6.2", false, map[string][]byte{"a.bin": []byte("x")}, "", false)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	PublicKey = base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	if _, err := Check(ctx, "0.6.1", "stable"); err == nil || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("foreign key: %v", err)
	}
}

func TestReplaceFromArchive(t *testing.T) {
	dir := t.TempDir()
	exe := "zpt"
	os.WriteFile(filepath.Join(dir, exe), []byte("old"), 0o755)
	// tar.gz
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"zpt": "new", "README.md": "doc", "zpt-tray": "tray"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	arc := filepath.Join(t.TempDir(), "zpt_0.6.2_linux_amd64.tar.gz")
	os.WriteFile(arc, tb.Bytes(), 0o644)
	if err := replaceFromArchive(arc, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "zpt")); string(b) != "new" {
		t.Fatalf("zpt: %q", b)
	}
	for _, n := range []string{"README.md", "zpt-tray"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("%s must not be added", n)
		}
	}
	// zip
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	f, _ := zw.Create("zpt.exe")
	fmt.Fprint(f, "newexe")
	zw.Close()
	os.WriteFile(filepath.Join(dir, "zpt.exe"), []byte("oldexe"), 0o755)
	zarc := filepath.Join(t.TempDir(), "zpt_0.6.2_windows_amd64.zip")
	os.WriteFile(zarc, zb.Bytes(), 0o644)
	if err := replaceFromArchive(zarc, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "zpt.exe")); string(b) != "newexe" {
		t.Fatalf("zpt.exe: %q", b)
	}
}

func TestBuiltInKey(t *testing.T) {
	if b, err := base64.StdEncoding.DecodeString(PublicKey); err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey: %v", err)
	}
}

// A test binary is not installed by a package manager or the MSI.
func TestDetectArchive(t *testing.T) {
	exe, _ := os.Executable()
	if k := Detect(exe); k != KindArchive {
		t.Fatalf("test binary detected as %v", k)
	}
}
