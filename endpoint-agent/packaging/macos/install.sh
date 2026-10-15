#!/bin/bash
# Install the CNAPP agent on a Mac from a downloaded binary (no .pkg):
#   sudo ./install.sh --server https://cnapp.example.com --binary ./cnapp-agent-darwin-arm64
# The enrollment token is read from stdin (or CNAPP_ENROLL_TOKEN) so it never
# appears in the process list or shell history.
set -euo pipefail
server="" binary="" extra=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) server="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --insecure-dev) extra+=(--insecure-dev); shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -n "$server" && -n "$binary" ]] || { echo "usage: sudo $0 --server URL --binary PATH" >&2; exit 2; }
token="${CNAPP_ENROLL_TOKEN:-}"
if [[ -z "$token" ]]; then
  read -r -s -p "Enrollment token: " token; echo
fi
# Downloaded binaries carry the quarantine attribute; Gatekeeper would block an unsigned one.
xattr -d com.apple.quarantine "$binary" 2>/dev/null || true
chmod 0755 "$binary"
printf '%s\n' "$token" | "$binary" enroll --server "$server" --token-stdin ${extra[@]+"${extra[@]}"}
"$binary" install
echo "CNAPP agent installed: $(/usr/local/cnapp-agent/bin/cnapp-agent version)"
