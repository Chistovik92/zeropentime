// SPDX-License-Identifier: MPL-2.0

// Package licensecheck guards the licensing split described in LICENSING.md:
// the node is MPL-2.0 and must never link AGPL-3.0 code; every source file
// carries the right SPDX header.
package licensecheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/Chistovik92/zeropentime"

// agplDirs are licensed AGPL-3.0-only; everything else is MPL-2.0.
var agplDirs = []string{"internal/controller", "internal/store", "cmd/zpt-controller", "internal/e2e"}

var sourceExt = map[string]bool{".go": true, ".html": true, ".css": true, ".js": true, ".sql": true}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root not found at %s", root)
	}
	return root
}

// mitDirs are third-party code kept under its own MIT license.
var mitDirs = []string{"internal/wgfirewall"}

func wantLicense(rel string) string {
	for _, d := range mitDirs {
		if strings.HasPrefix(rel, d+"/") {
			return "MIT"
		}
	}
	for _, d := range agplDirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return "AGPL-3.0-only"
		}
	}
	return "MPL-2.0"
}

func TestSPDXHeaders(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".claude") {
			return filepath.SkipDir
		}
		if d.IsDir() || !sourceExt[filepath.Ext(path)] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		first, _, _ := strings.Cut(string(data), "\n")
		want := "SPDX-License-Identifier: " + wantLicense(rel)
		if !strings.Contains(first, want) {
			t.Errorf("%s: first line must contain %q, got %q", rel, want, first)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The MPL-2.0 node binary must not link AGPL-3.0 packages, or the whole
// binary would effectively fall under the AGPL.
func TestNodeDoesNotLinkAGPL(t *testing.T) {
	root := repoRoot(t)
	for _, target := range []string{"./cmd/zpt"} {
		cmd := exec.Command("go", "list", "-deps", target)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %s: %v", target, err)
		}
		for _, pkg := range strings.Fields(string(out)) {
			rel, ok := strings.CutPrefix(pkg, module+"/")
			if ok && wantLicense(rel) == "AGPL-3.0-only" {
				t.Errorf("%s depends on AGPL package %s", target, pkg)
			}
		}
	}
}
