"""Tests for infra/deploy.sh (the deploy workflow's main step) with a fake `az`.

Nothing here touches Azure: tests/fake-az-deploy.sh records the calls and
simulates a first or a later deployment.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

INFRA = Path(__file__).resolve().parents[1]
REPO = INFRA.parent
DEPLOY = INFRA / "deploy.sh"
FAKE = INFRA / "tests" / "fake-az-deploy.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture()
def env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("az", "docker"):
        (bindir / tool).symlink_to(FAKE)
    log = tmp_path / "calls.log"
    log.touch()
    out = tmp_path / "github_output"
    out.touch()
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "CNAPP_"))}
    base.update(PATH=f"{bindir}{os.pathsep}{base['PATH']}", FAKE_LOG=str(log), GITHUB_OUTPUT=str(out),
                RG="rg-cnapp", SHA=SHA, OWNER="Amechi-Demigod", GHCR_USER="ci-bot", GHCR_TOKEN="ghs_token",
                DEPLOY_RETRY_DELAY="0", GITHUB_RUN_ID="77", GITHUB_RUN_ATTEMPT="1")
    return base, log, out


def run(env, **extra):
    return subprocess.run(["bash", str(DEPLOY)], env={**env, **extra}, cwd=REPO, capture_output=True, text=True,
                          timeout=60, check=False)


def deployments(log: Path) -> list[dict[str, str]]:
    return [dict(kv.split("=", 1) for kv in line.removeprefix("  env: ").split())
            for line in log.read_text().splitlines() if line.startswith("  env: ")]


def test_first_deployment(env):
    base, log, out = env
    proc = run(base, FAKE_STATE="first")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    deps = deployments(log)
    # 1) everything but the apps (registry first), 2) full deployment with the new images
    assert [d["apps"] for d in deps] == ["false", "true"]
    assert deps[1]["backend"] == f"cnapp-backend:{SHA}" and deps[1]["frontend"] == f"cnapp-frontend:{SHA}"
    # secrets were generated (not read from a vault that does not exist yet), identical in both phases
    for key in ("pg", "token", "admin", "session"):
        assert deps[0][key] == deps[1][key] and not deps[0][key].startswith("kv-value")
    assert len(deps[0]["pg"]) == 48 and len(deps[0]["token"]) == 64 and len(deps[0]["session"]) == 64
    assert re.fullmatch(r"[A-Za-z0-9]{20,24}", deps[0]["admin"])
    # every generated value is masked in the logs
    for key in ("pg", "token", "admin", "session"):
        assert f"::add-mask::{deps[0][key]}" in proc.stdout
    calls = log.read_text()
    assert "secret show" not in calls  # nothing to read on the first run
    assert ("az acr import -n crcnappabc --source ghcr.io/amechi-demigod/cloudsecurity-backend:" + SHA) in calls
    assert ("az acr import -n crcnappabc --source ghcr.io/amechi-demigod/cloudsecurity-frontend:" + SHA) in calls
    assert "--template-file infra/main.bicep --parameters infra/main.bicepparam" in calls
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert outputs == {"url": "https://cnapp-web.example.azurecontainerapps.io", "backend_app": "cnapp-api",
                       "frontend_app": "cnapp-web", "login_server": "crcnappabc.azurecr.io",
                       "key_vault": "kv-cnapp-abc"}


def test_later_deployment_reuses_secrets_and_running_images(env):
    base, log, _ = env
    proc = run(base, FAKE_STATE="existing")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    deps = deployments(log)
    assert [d["apps"] for d in deps] == ["true"]  # registry exists: single deployment
    d = deps[0]
    assert d["pg"] == "kv-value-of-postgres-admin-password" and d["session"] == "kv-value-of-session-secret"
    assert d["token"] == "kv-value-of-ingest-api-token" and d["admin"] == "kv-value-of-admin-password"
    # Bicep keeps the running images; the workflow's next step rolls out the new tag
    assert d["backend"] == "cnapp-backend:old" and d["frontend"] == "cnapp-frontend:old"
    assert "generated a new value" not in proc.stdout


def test_deployment_is_retried_once(env):
    base, log, _ = env
    proc = run(base, FAKE_STATE="existing", FAKE_DEPLOY_FAIL_ONCE="1")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "retrying" in proc.stdout and len(deployments(log)) == 2


def test_builds_images_when_ghcr_has_none(env):
    base, log, _ = env
    proc = run(base, FAKE_STATE="existing", FAKE_GHCR_MISSING="1")
    assert proc.returncode == 0, proc.stderr + proc.stdout
    calls = log.read_text()
    assert "az acr login -n crcnappabc" in calls
    assert f"docker build --platform linux/amd64 -t crcnappabc.azurecr.io/cnapp-backend:{SHA} backend" in calls
    assert f"docker push crcnappabc.azurecr.io/cnapp-frontend:{SHA}" in calls


def test_requires_inputs(env):
    base, _, _ = env
    base = {k: v for k, v in base.items() if k != "RG"}
    proc = run(base)
    assert proc.returncode != 0 and "RG" in proc.stderr
