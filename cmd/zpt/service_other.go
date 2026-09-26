// SPDX-License-Identifier: MPL-2.0

//go:build !linux && !windows

package main

import "errors"

const defaultConfigPath = "zpt.yaml"

var errNoService = errors.New("служба пока поддерживается только на Linux (systemd) и Windows")

func runningAsService() bool                                { return false }
func serveAsService(func(stop <-chan struct{}) error) error { return nil }
func serviceInstall(string, string) error                   { return errNoService }
func serviceUninstall() error                               { return errNoService }
func serviceControl(string) error                           { return errNoService }
func showLogs(bool, int) error                              { return errNoService }
func logFile() string                                       { return "" }
func ensureConfigDir(string) error                          { return nil }
