package service

import (
	"strings"
	"testing"
)

func TestSystemdUnit(t *testing.T) {
	u := SystemdUnit(PackageBinaryPath, []string{"run", "--home", "/srv/x"})
	for _, want := range []string{
		"ExecStart=/usr/bin/cnapp-agent run --home /srv/x\n", "User=root\n", "Restart=always\n", "StateDirectoryMode=0700\n",
		"NoNewPrivileges=yes\n", "WantedBy=multi-user.target\n", "Environment=LC_ALL=C LANG=C\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// Hardening that would break the read-only checks must stay off.
	for _, bad := range []string{"ProtectSystem=strict", "ProtectProc=", "PrivateUsers", "CapabilityBoundingSet", "PrivateNetwork", "RestrictAddressFamilies"} {
		if strings.Contains(u, bad) {
			t.Errorf("unit must not set %s", bad)
		}
	}
}
