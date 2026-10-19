#!/usr/bin/env bash
# Tests for `cnapp-ctl tls import-pfx` PFX handling (no root, no Docker needed):
#   deploy/onprem/tests/test_pfx.sh
# Fixtures (throwaway test PKI, password in pfx-password.txt):
#   legacy-rc2.pfx  certificates RC2-40-CBC, key 3DES (old Windows / AD CS exports;
#                   OpenSSL 3 rejects it without the legacy provider)
#   modern-aes.pfx  OpenSSL 3 defaults (AES-256, PBKDF2)
# Both hold leaf (cnapp2.test) + issuing CA + root, deliberately in the wrong order.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fx="$here/fixtures"
# shellcheck source=../cnapp-ctl
source "$here/../cnapp-ctl"
PATH="${OPENSSL_BIN_DIR:+$OPENSSL_BIN_DIR:}$PATH"
openssl version
fail() { echo "FAIL: $*" >&2; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pw=$(head -n1 "$fx/pfx-password.txt")

for f in legacy-rc2 modern-aes; do
  d="$work/$f"; mkdir -p "$d"
  PFX_PASS=$pw
  out=$(pfx_extract "$fx/$f.pfx" "$d" 2>&1) || fail "$f: extraction failed: $out"
  echo "$out"
  if [[ $f == legacy-rc2 ]]; then [[ $out == *"legacy"* ]] || fail "$f: legacy retry not reported"
  else [[ $out != *"legacy"* ]] || fail "$f: needlessly used the legacy provider"; fi
  [[ "$(openssl x509 -noout -subject -in "$d/leaf.pem")" == *"CN=cnapp2.test"* ]] || fail "$f: wrong leaf"
  [[ "$(openssl x509 -noout -pubkey -in "$d/leaf.pem" | openssl sha256)" == "$(openssl pkey -pubout -in "$d/key.pem" | openssl sha256)" ]] \
    || fail "$f: key does not match the leaf"
  grep -q ENCRYPTED "$d/key.pem" && fail "$f: key still encrypted"
  [[ $(grep -c 'BEGIN CERTIFICATE' "$d/chain.pem") -eq 1 ]] || fail "$f: chain must hold exactly the intermediate"
  [[ "$(openssl x509 -noout -subject -in "$d/chain.pem")" == *"Issuing CA 1"* ]] || fail "$f: chain order"
  [[ "$(openssl x509 -noout -subject -in "$d/root.pem")" == *"Enterprise Root CA"* ]] || fail "$f: root not found"
  openssl verify -CAfile "$d/root.pem" -untrusted "$d/chain.pem" "$d/leaf.pem" >/dev/null || fail "$f: chain does not verify"
  cmp -s "$d/root.pem" <(openssl x509 -in "$fx/test-root-ca.crt") || fail "$f: unexpected root"
  cert_covers "$d/leaf.pem" cnapp2.test || fail "$f: cert_covers"
  ! cert_covers "$d/leaf.pem" cnapp.wakanow.com || fail "$f: cert_covers accepted a wrong name"
  echo "ok: $f"
done

# Wrong password: a clear message, for both formats.
for f in legacy-rc2 modern-aes; do
  d="$work/bad-$f"; mkdir -p "$d"
  PFX_PASS="not-the-password"
  if out=$( (pfx_extract "$fx/$f.pfx" "$d") 2>&1); then fail "$f: accepted a wrong password"; fi
  [[ $out == *"wrong password"* ]] || fail "$f: unclear error for a wrong password: $out"
  echo "ok: wrong password ($f)"
done

# Legacy provider missing (simulated): explain what to do instead of OpenSSL's error.
d="$work/noprov"; mkdir -p "$d"
PFX_PASS=$pw
if out=$( (export OPENSSL_MODULES="$work/no-modules"; pfx_extract "$fx/legacy-rc2.pfx" "$d") 2>&1); then
  echo "note: this OpenSSL reads RC2 without the legacy provider module (e.g. LibreSSL); skipping"
else
  [[ $out == *"legacy provider"* ]] || fail "missing legacy provider not explained: $out"
  echo "ok: missing legacy provider explained"
fi
echo "all PFX tests passed"
