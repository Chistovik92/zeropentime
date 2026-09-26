// SPDX-License-Identifier: MPL-2.0

package control

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func useTempChannel(t *testing.T) {
	old := PipePath
	PipePath = fmt.Sprintf(`\\.\pipe\zeropentime-test-%d`, time.Now().UnixNano())
	oldSD, oldStatus := pipeSDDL, statusSDDL
	pipeSDDL = "D:P(A;;GA;;;WD)" // tests may run without administrator rights
	statusSDDL = pipeSDDL
	t.Cleanup(func() { PipePath, pipeSDDL, statusSDDL = old, oldSD, oldStatus })
}

// The real ACL (owner: administrators) must work for an elevated node.
func TestProductionPipeACL(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator rights")
	}
	old := PipePath
	PipePath = fmt.Sprintf(`\\.\pipe\zeropentime-acl-%d`, time.Now().UnixNano())
	defer func() { PipePath = old }()
	ln, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestStatusPipeSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(statusSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if s := sd.String(); !strings.Contains(s, ";;;IU)") || strings.Contains(s, ";;;WD)") {
		t.Fatalf("status pipe must be open to interactive users only: %s", s)
	}
}
