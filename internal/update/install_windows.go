// SPDX-License-Identifier: MPL-2.0

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// upgradeCode is the UpgradeCode of the MSI (deploy/packaging/windows/zpt.wxs).
const upgradeCode = "{32D8D5F8-EFCE-4749-AADF-EAC473371C93}"

var procEnumRelated = windows.NewLazySystemDLL("msi.dll").NewProc("MsiEnumRelatedProductsW")

// Detect tells an MSI install (the product is registered) from an archive.
func Detect(string) Kind {
	code, _ := windows.UTF16PtrFromString(upgradeCode)
	buf := make([]uint16, 39)
	if procEnumRelated.Find() != nil {
		return KindArchive
	}
	r, _, _ := procEnumRelated.Call(uintptr(unsafePtr(code)), 0, 0, uintptr(unsafePtr(&buf[0])))
	if r == 0 {
		return KindMSI
	}
	return KindArchive
}

func runInstaller(ctx context.Context, kind Kind, file, dir string) error {
	if kind != KindMSI {
		return fmt.Errorf("установщик %s на Windows не поддерживается", kind)
	}
	log := filepath.Join(os.TempDir(), "zpt-update-msi.log")
	cmd := exec.CommandContext(ctx, "msiexec", "/i", file, "/qn", "/norestart", "/l*v", log)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("msiexec: %v %s (журнал: %s)", err, out, log)
	}
	return nil
}
