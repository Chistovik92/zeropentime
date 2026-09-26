// SPDX-License-Identifier: MPL-2.0

package update

import (
	"context"
	"fmt"
	"os/exec"
)

// Detect tells a deb or rpm install (the package manager owns the binary)
// from an archive.
func Detect(exe string) Kind {
	if _, err := exec.LookPath("dpkg"); err == nil && exec.Command("dpkg", "-S", exe).Run() == nil {
		return KindDeb
	}
	if _, err := exec.LookPath("rpm"); err == nil && exec.Command("rpm", "-qf", exe).Run() == nil {
		return KindRPM
	}
	return KindArchive
}

func runInstaller(ctx context.Context, kind Kind, file, _ string) error {
	var cmd *exec.Cmd
	switch kind {
	case KindDeb:
		cmd = exec.CommandContext(ctx, "apt-get", "install", "-y", file)
		if _, err := exec.LookPath("apt-get"); err != nil {
			cmd = exec.CommandContext(ctx, "dpkg", "-i", file)
		}
	case KindRPM:
		cmd = exec.CommandContext(ctx, "rpm", "-U", file)
	default:
		return fmt.Errorf("установщик %s на Linux не поддерживается", kind)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v\n%s", cmd.Path, err, out)
	}
	return nil
}
