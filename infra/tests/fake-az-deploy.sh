#!/usr/bin/env bash
# Stand-in for `az` (and `docker`) in the infra/deploy.sh tests. Records calls
# in $FAKE_LOG and simulates either a first deployment (FAKE_STATE=first: no
# registry, vault or apps yet) or a later one (FAKE_STATE=existing).
# FAKE_DEPLOY_FAIL_ONCE=1 fails the first `deployment group create`;
# FAKE_GHCR_MISSING=1 makes `acr import` fail. Never talks to Azure.
set -euo pipefail
tool="$(basename "$0")"
echo "$tool $*" >> "${FAKE_LOG:?}"
args=" $* "
state="${FAKE_STATE:-first}"
[[ "$tool" == az ]] || exit 0

case "$args" in
  *" keyvault list "*) [[ "$state" == existing ]] && echo "kv-cnapp-abc" || echo "" ;;
  *" keyvault secret list "*)
    printf '%s\n' postgres-admin-password ingest-api-token admin-password session-secret database-url notifications-encryption-key
    # FAKE_NO_MFA_KEY=1: a vault from before MFA (the key is generated on upgrade)
    [[ "${FAKE_NO_MFA_KEY:-0}" == 1 ]] || echo mfa-encryption-key ;;
  *" keyvault secret show "*)
    name="$(sed -E 's/.*--name ([^ ]+).*/\1/' <<<"$args")"
    echo "kv-value-of-${name}" ;;
  *" deployment group create "*)
    echo "  env: apps=${CNAPP_DEPLOY_APPS:-} backend=${CNAPP_BACKEND_IMAGE:-} frontend=${CNAPP_FRONTEND_IMAGE:-} pg=${CNAPP_POSTGRES_PASSWORD:-} token=${CNAPP_INGEST_API_TOKEN:-} admin=${CNAPP_ADMIN_PASSWORD:-} session=${CNAPP_SESSION_SECRET:-} notify=${CNAPP_NOTIFICATIONS_ENCRYPTION_KEY:-} baseurl=${CNAPP_PUBLIC_BASE_URL:-} mfa=${CNAPP_MFA_ENCRYPTION_KEY:-}" >> "$FAKE_LOG"
    if [[ "${FAKE_DEPLOY_FAIL_ONCE:-0}" == 1 && ! -e "$FAKE_LOG.failed" ]]; then
      touch "$FAKE_LOG.failed"; echo "RoleAssignmentNotFound (simulated)" >&2; exit 1
    fi ;;
  *" deployment group show "*)
    case "$args" in
      *outputs.registryName*) echo "crcnappabc" ;;
      *outputs.frontendUrl*) echo "https://cnapp-web.example.azurecontainerapps.io" ;;
      *outputs.backendAppName*) echo "cnapp-api" ;;
      *outputs.frontendAppName*) echo "cnapp-web" ;;
      *outputs.keyVaultName*) echo "kv-cnapp-abc" ;;
    esac ;;
  *" acr list "*) [[ "$state" == existing ]] && echo "crcnappabc" || echo "" ;;
  *" acr show "*) echo "crcnappabc.azurecr.io" ;;
  *" acr repository show "*) exit 1 ;;
  *" acr import "*) if [[ "${FAKE_GHCR_MISSING:-0}" == 1 ]]; then exit 1; fi ;;
  *" containerapp show "*)
    if [[ "$state" == existing ]]; then
      [[ "$args" == *cnapp-api* ]] && echo "crcnappabc.azurecr.io/cnapp-backend:old" || echo "crcnappabc.azurecr.io/cnapp-frontend:old"
    else
      echo "ResourceNotFound" >&2; exit 3
    fi ;;
  *) : ;;
esac
