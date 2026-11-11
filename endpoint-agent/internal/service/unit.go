package service

import (
	"fmt"
	"strings"
)

// Linux (systemd) service names and paths. unit.go has no build tag so the
// unit file text is tested on every platform; service_linux.go installs it.
const (
	SystemdUnitName = "cnapp-agent.service"
	// SystemdUnitPath is where `cnapp-agent install` writes the unit. The
	// .deb / .rpm packages ship their own copy under /usr/lib/systemd/system
	// instead (see packaging/linux).
	SystemdUnitPath = "/etc/systemd/system/" + SystemdUnitName
	// PackageBinaryPath is where the .deb / .rpm packages put the binary.
	PackageBinaryPath = "/usr/bin/cnapp-agent"
	// LocalBinaryPath is where `cnapp-agent install` copies a standalone binary.
	LocalBinaryPath = "/usr/local/bin/cnapp-agent"
)

// SystemdUnit renders the unit file: runs as root (sshd -T, the sudoers
// files, /etc/shadow's empty-password check and the firewall rule sets are
// root-only), restarts on failure and is hardened as far as the read-only
// checks allow. Deliberately NOT set: ProtectProc / PrivateUsers / a capability
// bounding set (the listening-port owners come from /proc/<pid>/fd and the
// firewall commands need CAP_NET_ADMIN) and ProtectSystem=strict (the agent
// replaces its own binary during a signed self-update, and dnf / apt write
// their usual logs).
func SystemdUnit(binary string, args []string) string {
	exec := strings.Join(append([]string{binary}, args...), " ")
	rw := "ReadWritePaths=-/usr/bin -/usr/local/bin -/var/lib/cnapp-agent -/var/log/cnapp-agent"
	return fmt.Sprintf(`[Unit]
Description=CNAPP endpoint agent (inventory, security posture, signed updates)
Documentation=https://github.com/Amechi-demigod/CloudSecurity/blob/main/docs/DEVICE_MANAGEMENT.md
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30
User=root
Environment=LC_ALL=C LANG=C
UMask=0077
StateDirectory=cnapp-agent
StateDirectoryMode=0700
LogsDirectory=cnapp-agent
LogsDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
%s
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
`, exec, rw)
}
