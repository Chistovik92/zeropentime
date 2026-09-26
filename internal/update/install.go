// SPDX-License-Identifier: MPL-2.0

package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Kind is how the node was installed; an update is installed the same way.
type Kind int

const (
	KindArchive Kind = iota // a binary unpacked by hand
	KindMSI                 // Windows installer
	KindDeb
	KindRPM
)

func (k Kind) String() string {
	return [...]string{"архив", "MSI", "deb", "rpm"}[k]
}

// AssetName is the release file for this kind of install.
func AssetName(k Kind, version, goos, goarch string) string {
	switch k {
	case KindMSI:
		return fmt.Sprintf("zpt_%s_windows_%s.msi", version, goarch)
	case KindDeb:
		return fmt.Sprintf("zeropentime_%s_linux_%s.deb", version, goarch)
	case KindRPM:
		return fmt.Sprintf("zeropentime_%s_linux_%s.rpm", version, goarch)
	}
	if goos == "windows" {
		return fmt.Sprintf("zpt_%s_windows_%s.zip", version, goarch)
	}
	return fmt.Sprintf("zpt_%s_%s_%s.tar.gz", version, goos, goarch)
}

// Install downloads the release file for this install and installs it.
// For an archive install it replaces the binaries next to exe and
// returns restart == true: the caller restarts the service; installers
// restart it themselves.
func Install(ctx context.Context, r *Release, exe string) (kind Kind, restart bool, err error) {
	kind = Detect(exe)
	dir, err := os.MkdirTemp("", "zpt-update-")
	if err != nil {
		return kind, false, err
	}
	defer os.RemoveAll(dir)
	file, err := r.Download(ctx, AssetName(kind, r.Version, runtime.GOOS, runtime.GOARCH), dir)
	if err != nil {
		return kind, false, err
	}
	if kind != KindArchive {
		return kind, false, runInstaller(ctx, kind, file, dir)
	}
	return kind, true, replaceFromArchive(file, filepath.Dir(exe))
}

// binaries that an archive update replaces (if present in the archive).
var binaries = map[string]bool{"zpt": true, "zpt.exe": true, "zpt-tray": true, "zpt-tray.exe": true}

func replaceFromArchive(archive, dir string) error {
	found := 0
	put := func(name string, rd io.Reader) error {
		name = filepath.Base(name)
		if !binaries[name] {
			return nil
		}
		dst := filepath.Join(dir, name)
		if _, err := os.Stat(dst); err != nil && name != "zpt" && name != "zpt.exe" {
			return nil // the tray was not installed here
		}
		found++
		return replaceFile(dst, rd)
	}
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.OpenReader(archive)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			err = put(f.Name, io.LimitReader(rc, maxAsset))
			rc.Close()
			if err != nil {
				return err
			}
		}
	} else {
		f, err := os.Open(archive)
		if err != nil {
			return err
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if h.Typeflag == tar.TypeReg {
				if err := put(h.Name, io.LimitReader(tr, maxAsset)); err != nil {
					return err
				}
			}
		}
	}
	if found == 0 {
		return errors.New("в архиве нет zpt")
	}
	return nil
}

// replaceFile swaps in a new binary. A running program cannot be
// overwritten on Windows, but it can be renamed: the old one is kept as
// NAME.old until the next update.
func replaceFile(dst string, rd io.Reader) error {
	tmp := dst + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, rd)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	old := dst + ".old"
	os.Remove(old)
	if runtime.GOOS == "windows" {
		if err := os.Rename(dst, old); err != nil && !os.IsNotExist(err) {
			os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		if runtime.GOOS == "windows" {
			os.Rename(old, dst)
		}
		os.Remove(tmp)
		return err
	}
	return nil
}
