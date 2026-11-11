#!/usr/bin/env bash
# Build the Linux agent packages (.deb and .rpm, amd64 and arm64) with nfpm.
#
#   packaging/linux/build-packages.sh VERSION DIST_DIR
#
# DIST_DIR must already hold cnapp-agent-linux-amd64 and cnapp-agent-linux-arm64 (the CI / release builds). The
# packages are written next to them:
#   cnapp-agent_<version>_amd64.deb   cnapp-agent_<version>_arm64.deb
#   cnapp-agent-<version>-1.x86_64.rpm   cnapp-agent-<version>-1.aarch64.rpm
# nfpm must be on PATH (CI installs a pinned version). The systemd unit is generated from the Go source so the
# packaged unit and `cnapp-agent install` can never drift apart.
set -euo pipefail

version="${1:?usage: build-packages.sh VERSION DIST_DIR}"
dist="${2:?usage: build-packages.sh VERSION DIST_DIR}"
here="$(cd "$(dirname "$0")" && pwd)"
agent_dir="$(cd "$here/../.." && pwd)"
dist="$(cd "$dist" && pwd)"

command -v nfpm >/dev/null || { echo "nfpm is not installed" >&2; exit 1; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+~-][0-9A-Za-z.+~-]+)?$ ]] || { echo "bad version: $version" >&2; exit 1; }

unit="$dist/cnapp-agent.service"
(cd "$agent_dir" && go run ./cmd/cnapp-agent systemd-unit) > "$unit"
grep -q '^ExecStart=/usr/bin/cnapp-agent run$' "$unit" || { echo "unexpected unit file" >&2; exit 1; }

cd "$agent_dir"
for arch in amd64 arm64; do
  bin="$dist/cnapp-agent-linux-$arch"
  [ -x "$bin" ] || { echo "missing $bin" >&2; exit 1; }
  for fmt in deb rpm; do
    # nfpm expands ${VERSION} and ${ARCH} from the environment but not the file sources: render those here.
    cfg="$(mktemp)"
    sed -e "s|\${BINARY}|$bin|g" -e "s|\${UNIT}|$unit|g" packaging/linux/nfpm.yaml > "$cfg"
    VERSION="$version" ARCH="$arch" nfpm package --config "$cfg" --packager "$fmt" --target "$dist/"
    rm -f "$cfg"
  done
done
rm -f "$unit"
ls -l "$dist"/cnapp-agent_*.deb "$dist"/cnapp-agent-*.rpm
