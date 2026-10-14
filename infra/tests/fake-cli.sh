#!/usr/bin/env bash
# Stand-in for `az` and `gh` in the setup.sh tests: records every invocation in
# $FAKE_LOG and answers lookups. FAKE_EXISTING=1 simulates a fully set-up
# environment (everything already exists), FAKE_LOGGED_OUT=1 a CLI that is
# not signed in. Never talks to Azure or GitHub.
set -euo pipefail
tool="$(basename "$0")"
echo "$tool $*" >> "${FAKE_LOG:?}"
args=" $* "
existing="${FAKE_EXISTING:-0}"

if [[ "${FAKE_LOGGED_OUT:-0}" == 1 ]]; then
  exit 1
fi

if [[ "$tool" == az ]]; then
  case "$args" in
    *" account show "*"--query tenantId"*) echo "00000000-0000-0000-0000-00000000aaaa" ;;
    *" account show "*"--query id"*) echo "00000000-0000-0000-0000-00000000bbbb" ;;
    *" account show "*) : ;;
    *" provider show "*) [[ "$existing" == 1 ]] && echo Registered || echo NotRegistered ;;
    *" group exists "*) [[ "$existing" == 1 ]] && echo true || echo false ;;
    *" ad app list "*) [[ "$existing" == 1 ]] && echo "11111111-1111-1111-1111-111111111111" || echo "" ;;
    *" ad app create "*) echo "22222222-2222-2222-2222-222222222222" ;;
    *" ad sp show "*) if [[ "$existing" == 1 ]]; then echo "sp-object-id"; else echo "not found" >&2; exit 3; fi ;;
    *" ad sp create "*) echo "sp-object-id-new" ;;
    *" ad app federated-credential list "*) [[ "$existing" == 1 ]] && echo "github-production" || echo "" ;;
    *" ad signed-in-user show "*"--query id"*) echo "user-object-id" ;;
    *" ad signed-in-user show "*) echo "me@example.com" ;;
    *" role assignment list "*) [[ "$existing" == 1 ]] && echo 1 || echo 0 ;;
    *" identity show "*) [[ "$existing" == 1 ]] && echo "mi-principal-id" || echo "" ;;
    *) : ;;
  esac
elif [[ "$tool" == gh ]]; then
  case "$args" in
    *" auth status "*) : ;;
    *" repo view "*) echo "octo-org/CloudSecurity" ;;
    *" api user "*) echo "octocat" ;;
    *" api users/"*) echo "4242" ;;
    *"deployment-branch-policies --jq"*) [[ "$existing" == 1 ]] && echo main || echo "" ;;
    *" variable get "*) if [[ "$existing" == 1 ]]; then echo "aaaaaaaa-0000-0000-0000-000000000001"; else exit 1; fi ;;
    *" api -X PUT "*)
      body="$(cat)"
      echo "  body: $body" >> "$FAKE_LOG"
      # Simulate a plan without environment protection rules for private repos.
      if [[ "${FAKE_NO_REVIEWERS:-0}" == 1 && "$body" == *reviewers* ]]; then exit 1; fi
      ;;
    *) : ;;
  esac
fi
