#!/bin/bash
# Build a macOS installer package (.pkg) for the CNAPP endpoint agent.
#
#   packaging/macos/build-pkg.sh <version> <cnapp-agent binary> [output.pkg]
#
# The binary is normally a universal binary made with
#   lipo -create -output cnapp-agent cnapp-agent-darwin-amd64 cnapp-agent-darwin-arm64
#
# Signing (optional, needs your Apple Developer ID certificates in the keychain):
#   CODESIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)"  signs the binary (hardened runtime)
#   PKG_SIGN_IDENTITY="Developer ID Installer: Example Corp (TEAMID)"     signs the .pkg
# Notarization is a separate manual step (see docs/DEVICE_MANAGEMENT.md).
set -euo pipefail

version="${1:?usage: build-pkg.sh <version> <binary> [output.pkg]}"
binary="${2:?usage: build-pkg.sh <version> <binary> [output.pkg]}"
out="${3:-cnapp-agent-${version}.pkg}"
here="$(cd "$(dirname "$0")" && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"
install -d -m 0755 "$root/usr/local/cnapp-agent/bin"
install -m 0755 "$binary" "$root/usr/local/cnapp-agent/bin/cnapp-agent"

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$root/usr/local/cnapp-agent/bin/cnapp-agent"
fi

sign_args=()
if [[ -n "${PKG_SIGN_IDENTITY:-}" ]]; then
  sign_args=(--sign "$PKG_SIGN_IDENTITY" --timestamp)
fi

pkgbuild --root "$root" \
  --identifier com.cloudsecurity.cnapp-agent \
  --version "$version" \
  --install-location / \
  --scripts "$here/scripts" \
  --ownership recommended \
  ${sign_args[@]+"${sign_args[@]}"} \
  "$out"
echo "built $out"
