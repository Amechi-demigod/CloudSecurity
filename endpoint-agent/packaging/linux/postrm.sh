#!/bin/sh
# Post-remove of the cnapp-agent .deb / .rpm. deb: "remove" | "purge" | "upgrade" ...; rpm: 0 on final erase.
#
#   apt remove   keeps the device credential (a re-install re-uses the same device record)
#   apt purge    deletes credential, logs and any leftover enrolment file
#   dnf remove   (rpm has no purge) deletes them: a live device credential must not outlive the agent
#
# Also delete the device in the console (Devices > the device > Revoke / Delete): the server keeps its record.
set -e

purge() {
  rm -rf /var/lib/cnapp-agent /var/log/cnapp-agent /etc/cnapp-agent
}

case "${1:-}" in
  purge | 0) purge ;;
esac
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
