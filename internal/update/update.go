// SPDX-License-Identifier: MPL-2.0

// Package update finds, verifies and installs new releases of the node.
//
// Every release since 0.6.2 carries release.json — the version and the
// SHA-256 of every file of the release — and release.json.sig, its
// Ed25519 signature by the release key, whose public half is built in
// here. The private half lives only in the release workflow (a repository
// secret). A file is installed only if the manifest is signed by that key,
// names this very version and lists the file's hash, and the version is
// newer than the running one: a hijacked download server can neither
// change a file nor roll back to an older release.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PublicKey verifies release manifests (base64 Ed25519).
var PublicKey = "RV5enp93MHfpzewxhebFOxWh8Zi/oYICtjRG5MYbuYk="

// API is the GitHub API of the repository with the releases.
var API = "https://api.github.com/repos/Chistovik92/zeropentime"

const (
	ManifestName = "release.json"
	SigName      = "release.json.sig"
	sigDomain    = "zeropentime-release-v1\n"
	maxManifest  = 1 << 20
	maxAsset     = 512 << 20
)

var httpClient = &http.Client{Timeout: 10 * time.Minute}

// Manifest is the signed description of one release.
type Manifest struct {
	Version    string            `json:"version"`
	Prerelease bool              `json:"prerelease"`
	Assets     map[string]string `json:"assets"` // file name -> SHA-256 (hex)
}

// Sign returns the manifest bytes and their signature (base64).
func Sign(seed []byte, m *Manifest) (payload []byte, sig string, err error) {
	if len(seed) != ed25519.SeedSize {
		return nil, "", errors.New("update: bad signing key")
	}
	if payload, err = json.MarshalIndent(m, "", "  "); err != nil {
		return nil, "", err
	}
	s := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte(sigDomain), payload...))
	return payload, base64.StdEncoding.EncodeToString(s), nil
}

// Verify checks the signature with the built-in key and parses the manifest.
func Verify(payload []byte, sig string) (*Manifest, error) {
	pub, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("update: bad built-in key")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || !ed25519.Verify(pub, append([]byte(sigDomain), payload...), s) {
		return nil, errors.New("подпись релиза не сходится: обновление отклонено")
	}
	var m Manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	if _, ok := parseVersion(m.Version); !ok || len(m.Assets) == 0 {
		return nil, errors.New("update: bad manifest")
	}
	return &m, nil
}

type version struct {
	n   [3]int
	pre string
}

func parseVersion(s string) (version, bool) {
	var v version
	s = strings.TrimPrefix(s, "v")
	s, v.pre, _ = strings.Cut(s, "-")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v.n[i] = n
	}
	return v, true
}

// Newer reports whether version a is newer than b ("0.6.2" > "0.6.2-rc.1"
// > "0.6.1"). An unparsable b (a "dev" build) is older than anything.
func Newer(a, b string) bool {
	va, ok := parseVersion(a)
	if !ok {
		return false
	}
	vb, ok := parseVersion(b)
	if !ok {
		return true
	}
	for i := range 3 {
		if va.n[i] != vb.n[i] {
			return va.n[i] > vb.n[i]
		}
	}
	switch {
	case va.pre == vb.pre:
		return false
	case va.pre == "":
		return true
	case vb.pre == "":
		return false
	}
	return va.pre > vb.pre
}

// Release is a found and verified release newer than the running one.
type Release struct {
	Version  string
	Manifest *Manifest
	urls     map[string]string
}

type ghRelease struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: слишком большой ответ", url)
	}
	return b, err
}

// Check looks for the newest signed release of the channel ("stable" or
// "beta") newer than current; nil if there is none.
func Check(ctx context.Context, current, channel string) (*Release, error) {
	b, err := get(ctx, API+"/releases?per_page=30", 4<<20)
	if err != nil {
		return nil, err
	}
	var list []ghRelease
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	var best *ghRelease
	for i := range list {
		r := &list[i]
		if r.Draft || (r.Prerelease && channel != "beta") {
			continue
		}
		if !Newer(r.Tag, current) || (best != nil && !Newer(r.Tag, best.Tag)) {
			continue
		}
		urls := assetURLs(r)
		if urls[ManifestName] == "" || urls[SigName] == "" {
			continue // unsigned (before 0.6.2)
		}
		best = r
	}
	if best == nil {
		return nil, nil
	}
	urls := assetURLs(best)
	payload, err := get(ctx, urls[ManifestName], maxManifest)
	if err != nil {
		return nil, err
	}
	sig, err := get(ctx, urls[SigName], 1024)
	if err != nil {
		return nil, err
	}
	m, err := Verify(payload, string(sig))
	if err != nil {
		return nil, err
	}
	if v := strings.TrimPrefix(best.Tag, "v"); m.Version != v {
		return nil, fmt.Errorf("манифест подписан для %s, а релиз — %s: обновление отклонено", m.Version, v)
	}
	if !Newer(m.Version, current) {
		return nil, nil
	}
	return &Release{Version: m.Version, Manifest: m, urls: urls}, nil
}

func assetURLs(r *ghRelease) map[string]string {
	out := map[string]string{}
	for _, a := range r.Assets {
		out[a.Name] = a.URL
	}
	return out
}

// Download saves a file of the release into dir and checks its hash
// against the signed manifest.
func (r *Release) Download(ctx context.Context, name, dir string) (string, error) {
	want, ok := r.Manifest.Assets[name]
	if !ok || r.urls[name] == "" {
		return "", fmt.Errorf("в релизе %s нет файла %s", r.Version, name)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", r.urls[name], nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", name, resp.Status)
	}
	path := filepath.Join(dir, filepath.Base(name))
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAsset+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxAsset {
		err = errors.New("слишком большой файл")
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		err = fmt.Errorf("%s: контрольная сумма не совпадает с подписанной — файл отклонён", name)
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// HashFile is the SHA-256 (hex) of a file, as in the manifest.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
