#!/usr/bin/env bash
# Refuse endpoint-agent binaries built with a test-only build tag: remote_fake
# (the synthetic remote-session backend of scripts/agent_e2e.py,
# endpoint-agent/internal/remote/fake_e2e.go). It reads the build information
# Go embeds in every binary (`go version -m`), which `-ldflags "-s -w"` keeps,
# so it also works on the stripped release and installer builds.
#
#   scripts/agent_build_check.sh FILE...                fail if any FILE has a test tag
#   scripts/agent_build_check.sh --expect-fake FILE...  fail unless every FILE has it
#                                                       (proves the check sees the tag)
set -euo pipefail

TEST_TAGS=(remote_fake)
expect=no
if [[ ${1:-} == --expect-fake ]]; then
  expect=yes
  shift
fi
[[ $# -gt 0 ]] || { echo "usage: $0 [--expect-fake] FILE..." >&2; exit 2; }

status=0
for f in "$@"; do
  info="$(go version -m "$f")" || { echo "::error::$f: no Go build information" >&2; exit 1; }
  tags="$(awk '$1 == "build" && $2 ~ /^-tags=/ { sub(/^-tags=/, "", $2); print $2 }' <<<"$info")"
  found=""
  for t in "${TEST_TAGS[@]}"; do
    if [[ ",$tags," == *",$t,"* ]]; then found="$t"; fi
  done
  if [[ $expect == yes && -z $found ]]; then
    echo "::error::$f was expected to be a remote_fake build (tags: ${tags:-none})" >&2
    status=1
  elif [[ $expect == no && -n $found ]]; then
    echo "::error::$f is built with the test-only tag '$found': never ship it" >&2
    status=1
  else
    echo "ok: $f (tags: ${tags:-none})"
  fi
done
exit $status
