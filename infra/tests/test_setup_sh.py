"""Tests for infra/setup.sh with `az` and `gh` replaced by tests/fake-cli.sh.

Nothing here touches Azure or GitHub: the fake CLIs only record their
arguments and answer lookups.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

INFRA = Path(__file__).resolve().parents[1]
SETUP = INFRA / "setup.sh"
FAKE = INFRA / "tests" / "fake-cli.sh"

MUTATING = (
    "az provider register", "az group create", "az ad app create", "az ad sp create",
    "az ad app federated-credential create", "az role assignment create", "az account set",
    "az ad app update", "az ad sp update",
    "gh variable set", "gh api -X PUT", "gh api -X POST",
)


@pytest.fixture()
def fake_env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("az", "gh"):
        (bindir / tool).symlink_to(FAKE)
    log = tmp_path / "calls.log"
    log.touch()
    env = {k: v for k, v in os.environ.items() if not k.startswith("FAKE_")}
    env.update(PATH=f"{bindir}{os.pathsep}{env['PATH']}", FAKE_LOG=str(log))
    return env, log


def run(env, *args, **extra_env):
    proc = subprocess.run(["bash", str(SETUP), *args], env={**env, **extra_env}, capture_output=True, text=True,
                          timeout=60, check=False)
    return proc


def calls(log: Path) -> list[str]:
    return [line for line in log.read_text().splitlines() if not line.startswith("  body:")]


def mutations(log: Path) -> list[str]:
    return [c for c in calls(log) if c.startswith(MUTATING)]


def test_help():
    proc = subprocess.run(["bash", str(SETUP), "--help"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0 and "--dry-run" in proc.stdout and "--grant-scanner" in proc.stdout


def test_dry_run_changes_nothing_but_prints_the_plan(fake_env):
    env, log = fake_env
    proc = run(env, "--dry-run", "--admin-email", "admin@example.com")
    assert proc.returncode == 0, proc.stderr
    assert mutations(log) == []
    out = proc.stdout + proc.stderr  # planned commands are echoed on stderr
    for expected in ("DRY RUN", "az group create -n rg-cnapp -l eastus", "az ad app create --display-name github-CloudSecurity-deploy",
                     "az ad app federated-credential create", "repo:octo-org/CloudSecurity:environment:production",
                     "api://AzureADTokenExchange", "--role Contributor", "Key\\ Vault\\ Secrets\\ Officer",
                     "Role\\ Based\\ Access\\ Control\\ Administrator", "--condition-version 2.0",
                     "gh variable set AZURE_CLIENT_ID --body \\<new-app-id\\>", "gh variable set CNAPP_ADMIN_EMAIL",
                     "deployment-branch-policies", "Next steps", "az group delete -n rg-cnapp"):
        assert expected in out, f"missing {expected!r} in:\n{out}"
    # OIDC only: never a client secret / password
    assert "credential reset" not in out and "--password" not in out and "client-secret" not in out


def test_dry_run_works_when_not_signed_in(fake_env):
    env, log = fake_env
    proc = run(env, "--dry-run", "--repo", "o/r", "--admin-email", "a@example.com", FAKE_LOGGED_OUT="1")
    assert proc.returncode == 0, proc.stderr
    assert "placeholders" in proc.stdout and "<subscription-id>" in proc.stdout
    assert mutations(log) == []


def test_real_run_requires_login(fake_env):
    env, _ = fake_env
    proc = run(env, "--admin-email", "a@example.com", FAKE_LOGGED_OUT="1")
    assert proc.returncode != 0 and "az login" in proc.stderr


def test_first_run_creates_everything_with_least_privilege(fake_env):
    env, log = fake_env
    proc = run(env, "--admin-email", "admin@example.com", "--location", "westeurope", "--resource-group", "rg-demo")
    assert proc.returncode == 0, proc.stderr
    made = mutations(log)
    assert any(c.startswith("az group create -n rg-demo -l westeurope") for c in made)
    assert sum(c.startswith("az provider register") for c in made) == 7
    assert any(c.startswith("az ad app create --display-name github-CloudSecurity-deploy") for c in made)
    assert any(c.startswith("az ad sp create --id 22222222-2222-2222-2222-222222222222") for c in made)
    fc = [c for c in made if "federated-credential create" in c]
    assert len(fc) == 1 and '"subject":"repo:octo-org/CloudSecurity:environment:production"' in fc[0]
    roles = [c for c in made if c.startswith("az role assignment create")]
    assert len(roles) == 4
    scope = "--scope /subscriptions/00000000-0000-0000-0000-00000000bbbb/resourceGroups/rg-demo"
    assert all(scope in r for r in roles)
    me = roles.pop()  # the signed-in user may read the generated secrets
    assert "--assignee-object-id user-object-id --assignee-principal-type User --role Key Vault Secrets User" in me
    assert all("--assignee-object-id sp-object-id-new --assignee-principal-type ServicePrincipal" in r for r in roles)
    assert all("Owner" not in r and "User Access Administrator" not in r for r in roles)
    rbac = next(r for r in roles if "Role Based Access Control Administrator" in r)
    # constrained delegation: only AcrPull + Key Vault Secrets User, only to service principals
    assert "7f951dda-4ed3-4680-a7ca-43fe172d538d" in rbac and "4633458b-17de-408a-b874-0445c86b69e6" in rbac
    assert "ServicePrincipal" in rbac and "--condition-version 2.0" in rbac
    variables = {c.split()[3]: c.split("--body ")[1].split(" --repo")[0] for c in made if c.startswith("gh variable set")}
    assert variables == {
        "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
        "AZURE_TENANT_ID": "00000000-0000-0000-0000-00000000aaaa",
        "AZURE_SUBSCRIPTION_ID": "00000000-0000-0000-0000-00000000bbbb",
        "AZURE_RESOURCE_GROUP": "rg-demo",
        "AZURE_LOCATION": "westeurope",
        "CNAPP_NAME_PREFIX": "cnapp",
        "CNAPP_ADMIN_EMAIL": "admin@example.com",
        "AZURE_DEPLOY_ON_PUSH": "false",
    }
    body = [line for line in log.read_text().splitlines() if line.startswith("  body:")]
    assert '"reviewers":[{"type":"User","id":4242}]' in body[0] and '"custom_branch_policies":true' in body[0]
    assert any("deployment-branch-policies -f name=main" in c for c in made)


def test_second_run_is_idempotent(fake_env):
    env, log = fake_env
    proc = run(env, "--admin-email", "admin@example.com", FAKE_EXISTING="1")
    assert proc.returncode == 0, proc.stderr
    made = mutations(log)
    # Only the (overwrite-safe) GitHub environment + variables are re-applied.
    assert all(c.startswith(("gh variable set", "gh api -X PUT")) for c in made), made
    assert "already assigned" in proc.stdout and "application exists" in proc.stdout


def test_environment_without_reviewers_fallback(fake_env):
    env, log = fake_env
    proc = run(env, "--admin-email", "a@example.com", FAKE_NO_REVIEWERS="1")
    assert proc.returncode == 0, proc.stderr
    assert "GitHub Pro/Team" in proc.stderr
    assert sum(c.startswith("gh api -X PUT") for c in calls(log)) == 2


def test_grant_scanner(fake_env):
    env, log = fake_env
    sub = "aaaaaaaa-0000-0000-0000-000000000002"
    proc = run(env, "--grant-scanner", sub, FAKE_EXISTING="1")
    assert proc.returncode == 0, proc.stderr
    made = mutations(log)
    # existing assignment found -> no new role; variable merges old + new subscription ids
    assert made == ["gh variable set CNAPP_SCAN_SUBSCRIPTION_IDS --body "
                    "aaaaaaaa-0000-0000-0000-000000000001,aaaaaaaa-0000-0000-0000-000000000002 "
                    "--repo octo-org/CloudSecurity"]


def test_grant_scanner_dry_run(fake_env):
    env, log = fake_env
    proc = run(env, "--grant-scanner", "aaaaaaaa-0000-0000-0000-000000000002", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert mutations(log) == []
    assert "--role Reader --scope /subscriptions/aaaaaaaa-0000-0000-0000-000000000002" in proc.stderr
    assert "backend-identity-principal-id" in proc.stderr


@pytest.mark.parametrize("args,msg", [
    (["--name-prefix", "Bad_Prefix"], "name-prefix"),
    (["--grant-scanner", "not-a-guid"], "invalid subscription id"),
    (["--bogus"], "unknown option"),
    (["--repo", "no-slash", "--dry-run"], "invalid --repo"),
])
def test_input_validation(fake_env, args, msg):
    env, log = fake_env
    proc = run(env, *args, FAKE_EXISTING="1")
    assert proc.returncode != 0 and msg in proc.stderr
    assert mutations(log) == []


def test_public_base_url_variable(fake_env):
    env, log = fake_env
    proc = run(env, "--admin-email", "a@example.com", "--public-base-url", "https://cnapp.example.com/")
    assert proc.returncode == 0, proc.stderr
    assert any(c.startswith("gh variable set CNAPP_PUBLIC_BASE_URL --body https://cnapp.example.com --repo")
               for c in mutations(log))
    bad = run(env, "--admin-email", "a@example.com", "--public-base-url", "http://insecure.example.com")
    assert bad.returncode != 0 and "https://" in bad.stderr
def test_entra_sso_updates_existing_app(fake_env):
    env, log = fake_env
    proc = run(env, "--entra-sso", "--sso-redirect-uri", "http://localhost:5173/api/auth/sso/entra/callback",
               FAKE_EXISTING="1")
    assert proc.returncode == 0, proc.stderr
    joined = "\n".join(mutations(log))
    app = "11111111-1111-1111-1111-111111111111"
    assert (f"az ad app update --id {app} --web-redirect-uris "
            "https://cnapp-web.example.azurecontainerapps.io/api/auth/sso/entra/callback "
            "http://localhost:5173/api/auth/sso/entra/callback") in joined
    assert f"az ad sp update --id {app} --set appRoleAssignmentRequired=true" in joined
    assert f"gh variable set CNAPP_ENTRA_CLIENT_ID --body {app}" in joined
    assert "gh variable set CNAPP_ENTRA_CLIENT_AUTH --body managed_identity" in joined
    assert "az ad app create" not in joined
    assert not any("credential reset" in c for c in calls(log))  # never creates a client secret
    # only the SSO step ran
    assert "az group create" not in joined and "az role assignment create" not in joined


def test_entra_sso_dry_run_plans_app_roles_and_federated_credential(fake_env):
    env, log = fake_env
    proc = run(env, "--entra-sso", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert mutations(log) == []
    plan = proc.stderr
    assert "az ad app create --display-name cloudsecurity-cnapp-cnapp-sso --sign-in-audience AzureADMyOrg" in plan
    assert "CNAPP.Admin" in plan and "appRoleAssignmentRequired=true" in plan
    assert "api://AzureADTokenExchange" in plan and "backend-identity-principal-id" in plan
    assert "login.microsoftonline.com/00000000-0000-0000-0000-00000000aaaa/v2.0" in plan


def test_entra_sso_rejects_bad_redirect_uri(fake_env):
    env, _ = fake_env
    proc = run(env, "--entra-sso", "--sso-redirect-uri", "http://evil.example/cb", FAKE_EXISTING="1")
    assert proc.returncode != 0 and "invalid --sso-redirect-uri" in proc.stderr
