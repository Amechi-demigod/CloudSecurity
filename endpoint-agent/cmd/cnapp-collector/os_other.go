//go:build !windows

package main

import (
	"errors"
	"os"
	"strings"
)

// The collector is Windows-only; these let it build (and its tests run) elsewhere.
func setServiceAccountSID() {}

func accountSID(string) (string, error) {
	return "", errors.New("running as a gMSA is only supported on Windows")
}

func machineGUID() string {
	b, _ := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(b))
}
