#!/usr/bin/env bash
# Deploys infra/main.bicep and gets the app images into the registry.
# Called by .github/workflows/deploy.yml after `azure/login` (OIDC); see
# docs/DEPLOY_AZURE.md. Not meant to be run by hand, but it only needs an
# authenticated `az` and these environment variables:
#
#   RG                  resource group (created by infra/setup.sh)
#   SHA                 commit whose images to deploy
#   OWNER               GitHub owner of the ghcr.io images
#   GHCR_USER/GHCR_TOKEN  credentials to import the images from ghcr.io (the job's GITHUB_TOKEN)
#   CNAPP_NAME_PREFIX, AZURE_LOCATION, CNAPP_ADMIN_EMAIL, CNAPP_SIMULATION_MODE,
#   CNAPP_SCAN_SUBSCRIPTION_IDS, CNAPP_MFA_REQUIRED_ROLES, CNAPP_ENTRA_*  read by infra/main.bicepparam
#
# Writes url, backend_app, frontend_app, login_server and key_vault to $GITHUB_OUTPUT.
set -euo pipefail
: "${RG:?}" "${SHA:?}" "${OWNER:?}" "${GHCR_USER:?}" "${GHCR_TOKEN:?}"
export CNAPP_NAME_PREFIX="${CNAPP_NAME_PREFIX:-cnapp}"
owner_lc="$(echo "$OWNER" | tr '[:upper:]' '[:lower:]')"
deployment="cnapp-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
RETRY_DELAY="${DEPLOY_RETRY_DELAY:-90}"

# --- app secrets: read back from Key Vault, generated on the first run ----
# Never regenerate a secret that exists: a failed read aborts the run
# (it would otherwise rotate the database password / sign everyone out).
kv="$(az keyvault list -g "$RG" --query "[0].name" -o tsv)"
existing=""
if [ -n "$kv" ]; then
  existing="$(az keyvault secret list --vault-name "$kv" --query "[].name" -o tsv)"
fi
secret() { # <env var> <key vault secret name> <generator>
  local value=""
  if grep -qx "$2" <<<"$existing"; then
    value="$(az keyvault secret show --vault-name "$kv" --name "$2" --query value -o tsv)"
    [ -n "$value" ] || { echo "::error::Key Vault secret $2 is empty"; exit 1; }
  else
    value="$($3)"
    echo "generated a new value for $2"
  fi
  echo "::add-mask::$value"
  printf -v "$1" '%s' "$value"
  export "${1?}"
}
hex32() { openssl rand -hex 32; }
hex24() { openssl rand -hex 24; }
password() { openssl rand -base64 24 | tr -d '/+=' | cut -c1-24; }
secret CNAPP_POSTGRES_PASSWORD postgres-admin-password hex24
secret CNAPP_INGEST_API_TOKEN ingest-api-token hex32
secret CNAPP_ADMIN_PASSWORD admin-password password
secret CNAPP_SESSION_SECRET session-secret hex32
secret CNAPP_MFA_ENCRYPTION_KEY mfa-encryption-key hex32

deploy() { # <deployApps>; retried once (new role assignments can take a minute to propagate)
  export CNAPP_DEPLOY_APPS="$1"
  for attempt in 1 2; do
    if az deployment group create -g "$RG" -n "${deployment}-$1-${attempt}" \
        --template-file infra/main.bicep --parameters infra/main.bicepparam -o none --only-show-errors; then
      last_deployment="${deployment}-$1-${attempt}"
      return 0
    fi
    [ "$attempt" = 2 ] && return 1
    echo "::warning::deployment attempt $attempt failed; retrying in ${RETRY_DELAY}s"
    sleep "$RETRY_DELAY"
  done
}
output() { az deployment group show -g "$RG" -n "$last_deployment" --query "properties.outputs.$1.value" -o tsv; }

# --- first run: create everything except the apps (registry for the images) ---
acr="$(az acr list -g "$RG" --query "[0].name" -o tsv)"
if [ -z "$acr" ]; then
  echo "First deployment: creating the infrastructure (PostgreSQL takes ~10 minutes)"
  export CNAPP_BACKEND_IMAGE="cnapp-backend:${SHA}" CNAPP_FRONTEND_IMAGE="cnapp-frontend:${SHA}"
  deploy false
  acr="$(output registryName)"
fi
login_server="$(az acr show -n "$acr" --query loginServer -o tsv)"

# --- images: import from ghcr.io (built + smoke-tested by CI), else build here ---
for app in backend frontend; do
  if az acr repository show -n "$acr" --image "cnapp-${app}:${SHA}" -o none 2>/dev/null; then
    echo "cnapp-${app}:${SHA} already in $acr"
  elif az acr import -n "$acr" --source "ghcr.io/${owner_lc}/cloudsecurity-${app}:${SHA}" \
      --image "cnapp-${app}:${SHA}" --username "$GHCR_USER" --password "$GHCR_TOKEN" --only-show-errors; then
    echo "imported ghcr.io/${owner_lc}/cloudsecurity-${app}:${SHA}"
  else
    echo "::warning::ghcr.io/${owner_lc}/cloudsecurity-${app}:${SHA} not found; building it here"
    az acr login -n "$acr"
    docker build --platform linux/amd64 -t "${login_server}/cnapp-${app}:${SHA}" "${app}"
    docker push "${login_server}/cnapp-${app}:${SHA}"
  fi
done

# --- infrastructure + app configuration (keeps the running images) ---------
current() { # image currently running in a container app, without the registry ("" if none yet)
  local image
  image="$(az containerapp show -g "$RG" -n "$1" --query "properties.template.containers[0].image" -o tsv 2>/dev/null || true)"
  printf '%s' "${image#*/}"
}
CNAPP_BACKEND_IMAGE="$(current "${CNAPP_NAME_PREFIX}-api")"
CNAPP_FRONTEND_IMAGE="$(current "${CNAPP_NAME_PREFIX}-web")"
export CNAPP_BACKEND_IMAGE="${CNAPP_BACKEND_IMAGE:-cnapp-backend:${SHA}}"
export CNAPP_FRONTEND_IMAGE="${CNAPP_FRONTEND_IMAGE:-cnapp-frontend:${SHA}}"
deploy true

{
  echo "url=$(output frontendUrl)"
  echo "backend_app=$(output backendAppName)"
  echo "frontend_app=$(output frontendAppName)"
  echo "login_server=${login_server}"
  echo "key_vault=$(output keyVaultName)"
} >> "$GITHUB_OUTPUT"
