#!/usr/bin/env bash
# One-time setup for deploying CloudSecurity CNAPP to Azure from GitHub Actions.
#
# Run it yourself, once, signed in with your own accounts:
#   az login                    # an account that can create Entra apps and assign roles (e.g. Owner)
#   gh auth login               # an account with admin rights on the GitHub repository
#   infra/setup.sh --admin-email you@example.com --dry-run    # review the plan
#   infra/setup.sh --admin-email you@example.com
#
# What it does (idempotent: re-running only creates what is missing):
#   1. registers the Azure resource providers the deployment uses
#   2. creates the resource group
#   3. creates an Entra application + service principal for GitHub Actions and a
#      federated credential trusting ONLY this repository's "production"
#      environment (OIDC: no client secret is ever created)
#   4. assigns it least-privilege roles on the resource group only:
#        Contributor                            create/update the resources
#        Key Vault Secrets Officer              generate/read the app secrets in the vault
#        Role Based Access Control Administrator, constrained by an ABAC condition
#                                               to granting only AcrPull and Key Vault
#                                               Secrets User to service principals
#      and gives YOU Key Vault Secrets User on the resource group, so you can
#      read the generated first-admin password
#   5. creates the GitHub "production" environment (required reviewer: you,
#      deployments from main only) and sets the repository variables the
#      deploy workflow reads (no secrets are stored in GitHub)
#
# After the first deployment, optionally let the Azure scanner read a subscription:
#   infra/setup.sh --grant-scanner <subscription-id> [--grant-scanner <id> ...]
# which grants the backend's managed identity the built-in Reader role there.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

DRY_RUN=false
SUBSCRIPTION=""
RESOURCE_GROUP="rg-cnapp"
LOCATION="eastus"
REPO=""
ADMIN_EMAIL=""
NAME_PREFIX="cnapp"
APP_NAME=""
GH_ENVIRONMENT="production"
REVIEWER=""
DEPLOY_ON_PUSH=false
SCAN_SUBSCRIPTIONS=()
PUBLIC_BASE_URL=""

# Built-in role definition IDs.
ROLE_ACR_PULL="7f951dda-4ed3-4680-a7ca-43fe172d538d"
ROLE_KV_SECRETS_USER="4633458b-17de-408a-b874-0445c86b69e6"
PROVIDERS=(Microsoft.App Microsoft.OperationalInsights Microsoft.DBforPostgreSQL Microsoft.KeyVault
  Microsoft.ContainerRegistry Microsoft.Network Microsoft.ManagedIdentity)

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

  --admin-email EMAIL        first admin user of the app (default: your Entra sign-in name)
  --subscription ID          Azure subscription (default: az account show)
  --resource-group NAME      resource group to create/deploy into (default: $RESOURCE_GROUP)
  --location REGION          Azure region (default: $LOCATION)
  --repo OWNER/NAME          GitHub repository (default: the current gh repository)
  --name-prefix PREFIX       3-10 lowercase letters/digits for resource names (default: $NAME_PREFIX)
  --app-name NAME            Entra application display name (default: github-<repo>-deploy)
  --environment NAME         GitHub environment trusted by the federated credential (default: $GH_ENVIRONMENT)
  --reviewer LOGIN           GitHub user who must approve deployments (default: you)
  --deploy-on-push           also deploy automatically after CI passes on main
  --public-base-url URL      https URL users open the app at (custom domain), used for links in
                             notifications; default: the Container Apps URL of the web app
  --grant-scanner SUB_ID     (after the first deployment) grant the backend identity Reader on
                             SUB_ID and add it to the scanned subscriptions; repeatable.
                             Only this step runs when given.
  --dry-run                  print what would be done; change nothing
  -h, --help                 show this help
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }
note() { echo "    $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-email) ADMIN_EMAIL="${2:?}"; shift 2 ;;
    --subscription) SUBSCRIPTION="${2:?}"; shift 2 ;;
    --resource-group) RESOURCE_GROUP="${2:?}"; shift 2 ;;
    --location) LOCATION="${2:?}"; shift 2 ;;
    --repo) REPO="${2:?}"; shift 2 ;;
    --name-prefix) NAME_PREFIX="${2:?}"; shift 2 ;;
    --app-name) APP_NAME="${2:?}"; shift 2 ;;
    --environment) GH_ENVIRONMENT="${2:?}"; shift 2 ;;
    --reviewer) REVIEWER="${2:?}"; shift 2 ;;
    --deploy-on-push) DEPLOY_ON_PUSH=true; shift ;;
    --public-base-url) PUBLIC_BASE_URL="${2:?}"; shift 2 ;;
    --grant-scanner) SCAN_SUBSCRIPTIONS+=("${2:?}"); shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

[[ "$NAME_PREFIX" =~ ^[a-z0-9]{3,10}$ ]] || die "--name-prefix must be 3-10 lowercase letters/digits"
[[ "$RESOURCE_GROUP" =~ ^[-A-Za-z0-9_.()]{1,90}$ ]] || die "invalid --resource-group"
[[ "$LOCATION" =~ ^[a-z0-9]+$ ]] || die "invalid --location (use the short name, e.g. eastus)"
if [[ -n "$PUBLIC_BASE_URL" && ! "$PUBLIC_BASE_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[^[:space:]]*)?$ ]]; then
  die "--public-base-url must be an https:// URL"
fi

command -v az >/dev/null 2>&1 || die "Azure CLI (az) not found: https://aka.ms/azcli"
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) not found: https://cli.github.com"

# --- helpers --------------------------------------------------------------------

# Print a command the way it would be typed (on stderr, so it is shown even
# when the command's own output is captured or discarded).
show() {
  local out="" a
  for a in "$@"; do out+="$(printf '%q' "$a") "; done
  echo "    + ${out% }" >&2
}

# Mutating command: printed, and executed unless --dry-run.
run() {
  show "$@"
  if [[ "$DRY_RUN" == true ]]; then return 0; fi
  "$@"
}

# Like run, but captures stdout (for create commands that return an id).
# In dry-run mode prints the command and echoes the placeholder instead.
run_capture() {
  local placeholder="$1"; shift
  show "$@"
  if [[ "$DRY_RUN" == true ]]; then echo "$placeholder"; return 0; fi
  "$@"
}

# Read-only query. Never changes anything, so it also runs in dry-run mode;
# there it falls back to "" if the CLI is not signed in.
query() {
  if [[ "$DRY_RUN" == true ]]; then "$@" 2>/dev/null || true; else "$@"; fi
}

AZ_READY=true
GH_READY=true
if ! az account show --only-show-errors -o none >/dev/null 2>&1; then
  [[ "$DRY_RUN" == true ]] || die "not signed in to Azure: run 'az login' first"
  AZ_READY=false
  echo "(dry run: az is not signed in; using placeholders for Azure lookups)"
fi
if ! gh auth status >/dev/null 2>&1; then
  [[ "$DRY_RUN" == true ]] || die "not signed in to GitHub: run 'gh auth login' first"
  GH_READY=false
  echo "(dry run: gh is not signed in; using placeholders for GitHub lookups)"
fi

if [[ -z "$SUBSCRIPTION" ]]; then
  SUBSCRIPTION="$(query az account show --query id -o tsv)"
  SUBSCRIPTION="${SUBSCRIPTION:-<subscription-id>}"
fi
TENANT_ID="$(query az account show --subscription "$SUBSCRIPTION" --query tenantId -o tsv)"
TENANT_ID="${TENANT_ID:-<tenant-id>}"
if [[ -z "$REPO" ]]; then
  REPO="$(query gh repo view --json nameWithOwner --jq .nameWithOwner)"
  [[ -n "$REPO" ]] || die "could not detect the GitHub repository; pass --repo OWNER/NAME"
fi
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid --repo '$REPO' (expected OWNER/NAME)"
APP_NAME="${APP_NAME:-github-${REPO#*/}-deploy}"
RG_SCOPE="/subscriptions/${SUBSCRIPTION}/resourceGroups/${RESOURCE_GROUP}"

# ensure_role <assignee object id> <role name or id> <scope> [ABAC condition] [principal type]
ensure_role() {
  local oid="$1" role="$2" scope="$3" condition="${4:-}" ptype="${5:-ServicePrincipal}" count
  count="$(query az role assignment list --assignee "$oid" --role "$role" --scope "$scope" --query "length(@)" -o tsv)"
  if [[ "${count:-0}" != "0" ]]; then
    note "role '$role' already assigned on $scope"
    return 0
  fi
  local args=(az role assignment create --assignee-object-id "$oid" --assignee-principal-type "$ptype"
    --role "$role" --scope "$scope")
  if [[ -n "$condition" ]]; then
    args+=(--condition "$condition" --condition-version "2.0")
  fi
  run "${args[@]}" --only-show-errors -o none
}

set_gh_var() {
  run gh variable set "$1" --body "$2" --repo "$REPO"
}

# --- post-deployment: grant the scanner Reader on subscriptions -------------------
if [[ ${#SCAN_SUBSCRIPTIONS[@]} -gt 0 ]]; then
  identity="id-${NAME_PREFIX}-api"
  log "Granting the backend managed identity '$identity' Reader on ${#SCAN_SUBSCRIPTIONS[@]} subscription(s)"
  principal="$(query az identity show -g "$RESOURCE_GROUP" -n "$identity" --subscription "$SUBSCRIPTION" --query principalId -o tsv)"
  if [[ -z "$principal" ]]; then
    [[ "$DRY_RUN" == true ]] || die "managed identity $identity not found in $RESOURCE_GROUP: deploy first"
    principal="<backend-identity-principal-id>"
  fi
  for sub in "${SCAN_SUBSCRIPTIONS[@]}"; do
    [[ "$sub" =~ ^[0-9a-fA-F-]{36}$ ]] || die "invalid subscription id: $sub"
    ensure_role "$principal" "Reader" "/subscriptions/${sub}"
  done
  existing="$(query gh variable get CNAPP_SCAN_SUBSCRIPTION_IDS --repo "$REPO" 2>/dev/null || true)"
  all="$(printf '%s\n' "${existing//,/$'\n'}" "${SCAN_SUBSCRIPTIONS[@]}" | sed '/^$/d' | sort -u | paste -sd, -)"
  set_gh_var CNAPP_SCAN_SUBSCRIPTION_IDS "$all"
  cat <<EOF

Done. Re-run the "Deploy to Azure" workflow so the backend picks up
AZURE_SUBSCRIPTION_IDS=$all, then start a scan from Connectors -> Azure.
(Role assignments can take a few minutes to propagate.)
EOF
  exit 0
fi

# --- 1-2. providers and resource group --------------------------------------------
if [[ "$DRY_RUN" == true ]]; then echo "DRY RUN: nothing will be changed."; fi
log "Subscription $SUBSCRIPTION (tenant $TENANT_ID), resource group $RESOURCE_GROUP in $LOCATION"

log "Resource providers"
for p in "${PROVIDERS[@]}"; do
  state="$(query az provider show -n "$p" --subscription "$SUBSCRIPTION" --query registrationState -o tsv)"
  if [[ "$state" == "Registered" ]]; then
    note "$p registered"
  else
    run az provider register -n "$p" --subscription "$SUBSCRIPTION" -o none
  fi
done

log "Resource group"
if [[ "$(query az group exists -n "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION")" == "true" ]]; then
  note "$RESOURCE_GROUP exists"
else
  run az group create -n "$RESOURCE_GROUP" -l "$LOCATION" --subscription "$SUBSCRIPTION" \
    --tags app=cloudsecurity-cnapp managed-by=github-actions -o none
fi

# --- 3. Entra application, service principal, federated credential ---------------
log "Entra application '$APP_NAME' for GitHub Actions (OIDC, no secret)"
APP_ID="$(query az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)"
if [[ -n "$APP_ID" ]]; then
  note "application exists: $APP_ID"
else
  APP_ID="$(run_capture "<new-app-id>" az ad app create --display-name "$APP_NAME" \
    --sign-in-audience AzureADMyOrg --query appId -o tsv)"
fi

SP_OID="$(query az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || true)"
if [[ -n "$SP_OID" ]]; then
  note "service principal exists: $SP_OID"
else
  SP_OID="$(run_capture "<new-sp-object-id>" az ad sp create --id "$APP_ID" --query id -o tsv)"
fi

SUBJECT="repo:${REPO}:environment:${GH_ENVIRONMENT}"
existing_fc="$(query az ad app federated-credential list --id "$APP_ID" --query "[?subject=='${SUBJECT}'].name" -o tsv)"
if [[ -n "$existing_fc" ]]; then
  note "federated credential for $SUBJECT exists"
else
  fc_json="$(printf '{"name":"github-%s","issuer":"https://token.actions.githubusercontent.com","subject":"%s","audiences":["api://AzureADTokenExchange"],"description":"GitHub Actions deployments from %s (environment %s)"}' \
    "$GH_ENVIRONMENT" "$SUBJECT" "$REPO" "$GH_ENVIRONMENT")"
  run az ad app federated-credential create --id "$APP_ID" --parameters "$fc_json" -o none
fi

# --- 4. least-privilege role assignments (resource group scope only) ---------------
log "Role assignments for the deployment identity on $RG_SCOPE"
# The RBAC administrator role may only grant AcrPull / Key Vault Secrets User,
# only to service principals (the app's managed identities), and only remove those.
ABAC_CONDITION="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${ROLE_ACR_PULL}, ${ROLE_KV_SECRETS_USER}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'ServicePrincipal'})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${ROLE_ACR_PULL}, ${ROLE_KV_SECRETS_USER}}))"
ensure_role "$SP_OID" "Contributor" "$RG_SCOPE"
ensure_role "$SP_OID" "Key Vault Secrets Officer" "$RG_SCOPE"
ensure_role "$SP_OID" "Role Based Access Control Administrator" "$RG_SCOPE" "$ABAC_CONDITION"

log "Letting you (the signed-in user) read the generated app secrets, e.g. the first admin password"
ME_OID="$(query az ad signed-in-user show --query id -o tsv)"
ensure_role "${ME_OID:-<your-object-id>}" "Key Vault Secrets User" "$RG_SCOPE" "" User

# --- 5. GitHub environment and variables ------------------------------------------
log "GitHub environment '$GH_ENVIRONMENT' on $REPO"
if [[ -z "$REVIEWER" ]]; then
  REVIEWER="$(query gh api user --jq .login)"
fi
if [[ -z "$ADMIN_EMAIL" ]]; then
  ADMIN_EMAIL="$(query az ad signed-in-user show --query userPrincipalName -o tsv)"
  [[ -n "$ADMIN_EMAIL" ]] || die "pass --admin-email"
fi
REVIEWER_ID="$(query gh api "users/${REVIEWER:-unknown}" --jq .id)"
REVIEWER_ID="${REVIEWER_ID:-0}"
env_body="$(printf '{"wait_timer":0,"reviewers":[{"type":"User","id":%s}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' "$REVIEWER_ID")"
env_body_no_reviewers='{"wait_timer":0,"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
if ! run gh api -X PUT "repos/${REPO}/environments/${GH_ENVIRONMENT}" --input - <<<"$env_body" >/dev/null; then
  echo "warning: could not add a required reviewer (private repositories need GitHub Pro/Team for" >&2
  echo "         environment protection rules); creating the environment without one." >&2
  run gh api -X PUT "repos/${REPO}/environments/${GH_ENVIRONMENT}" --input - <<<"$env_body_no_reviewers" >/dev/null
fi
policies="$(query gh api "repos/${REPO}/environments/${GH_ENVIRONMENT}/deployment-branch-policies" --jq '.branch_policies[].name')"
if grep -qx main <<<"$policies"; then
  note "deployments restricted to main"
else
  run gh api -X POST "repos/${REPO}/environments/${GH_ENVIRONMENT}/deployment-branch-policies" \
    -f name=main -f type=branch >/dev/null
fi

log "GitHub repository variables (identifiers only; there are no secrets to store)"
set_gh_var AZURE_CLIENT_ID "$APP_ID"
set_gh_var AZURE_TENANT_ID "$TENANT_ID"
set_gh_var AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION"
set_gh_var AZURE_RESOURCE_GROUP "$RESOURCE_GROUP"
set_gh_var AZURE_LOCATION "$LOCATION"
set_gh_var CNAPP_NAME_PREFIX "$NAME_PREFIX"
set_gh_var CNAPP_ADMIN_EMAIL "$ADMIN_EMAIL"
set_gh_var AZURE_DEPLOY_ON_PUSH "$DEPLOY_ON_PUSH"
if [[ -n "$PUBLIC_BASE_URL" ]]; then
  set_gh_var CNAPP_PUBLIC_BASE_URL "${PUBLIC_BASE_URL%/}"
fi

cat <<EOF

Setup $([[ "$DRY_RUN" == true ]] && echo "plan (dry run)" || echo "complete").

Next steps:
  1. Merge the deployment PR (CI pushes the images to ghcr.io on main).
  2. GitHub -> Actions -> "Deploy to Azure" -> Run workflow (branch: main).
     Approve the "$GH_ENVIRONMENT" deployment when asked. The first run takes ~15-20 minutes.
  3. Open the URL printed in the run summary and sign in as $ADMIN_EMAIL with the
     initial password from Key Vault:
       az keyvault secret show --vault-name \$(az keyvault list -g $RESOURCE_GROUP --query "[0].name" -o tsv) \\
         --name admin-password --query value -o tsv
     Change it right away (user menu -> Change password).
  4. Optional: let the Azure scanner read a subscription:
       $SCRIPT_NAME --resource-group $RESOURCE_GROUP --grant-scanner <subscription-id>
  5. Optional: alert notifications (Teams, Slack, email, webhooks): sign in as an admin ->
     Notifications. The encryption key for channel secrets is generated into Key Vault
     (notifications-encryption-key) by the deploy workflow. See docs/NOTIFICATIONS.md.

Tear everything down later with:  az group delete -n $RESOURCE_GROUP --yes
EOF
if [[ "$AZ_READY" != true || "$GH_READY" != true ]]; then
  echo "(dry run used placeholders because a CLI was not signed in)"
fi
