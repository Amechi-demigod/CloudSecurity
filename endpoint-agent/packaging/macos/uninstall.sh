#!/bin/bash
# Remove the CNAPP agent from a Mac (installed to /usr/local/cnapp-agent/bin by the .pkg):
#   sudo /usr/local/cnapp-agent/bin/cnapp-uninstall.sh [--keep-state]
# Stops and removes the LaunchDaemon, deletes the binary, and (unless
# --keep-state) the device credential, any pending enrollment and the logs.
# Revoke or delete the device in the CNAPP console as well.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
bin=/usr/local/cnapp-agent/bin/cnapp-agent
purge=(--purge)
[[ "${1:-}" == "--keep-state" ]] && purge=()
if [[ -x "$bin" ]]; then
  "$bin" uninstall ${purge[@]+"${purge[@]}"}
else
  /bin/launchctl bootout system/com.cloudsecurity.cnapp-agent 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.cloudsecurity.cnapp-agent.plist
fi
rm -rf /usr/local/cnapp-agent
pkgutil --forget com.cloudsecurity.cnapp-agent >/dev/null 2>&1 || true
echo "CNAPP agent removed."
