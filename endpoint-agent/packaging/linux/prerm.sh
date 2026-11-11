#!/bin/sh
# Pre-remove of the cnapp-agent .deb / .rpm. deb: "remove" | "upgrade" | "deconfigure"; rpm: 0 on final erase,
# 1 on upgrade. Only a real removal stops and disables the service; an upgrade is restarted by the new post-install.
set -e

case "${1:-}" in
  remove | deconfigure | 0)
    if [ -d /run/systemd/system ]; then
      systemctl stop cnapp-agent.service >/dev/null 2>&1 || true
      systemctl disable cnapp-agent.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
