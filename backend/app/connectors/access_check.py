"""Connection test for the credentials an organisation admin enters on
Connectors & scans ("Test & save", PUT /api/organization/connectors/{provider}
with "test": true).

Each connector's `check_access()` makes one minimal READ-ONLY call per
configured subscription / account / project through its read-only client
wrapper (Azure: list resource groups; AWS: sts:GetCallerIdentity +
iam:ListAccountAliases; GCP: projects.get / projects.list). This module runs it
with an overall timeout and turns the failure into a short, actionable message.
Messages never contain the secrets (they are redacted if an SDK echoes them)
and nothing about the request is logged besides the provider and the outcome.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
from dataclasses import dataclass, field

from ..config import Settings
from . import build_registry
from .base import ScopeAccessError

log = logging.getLogger(__name__)

TIMEOUT_SECONDS = 20.0
LABEL = {"azure": "Azure", "aws": "AWS", "gcp": "Google Cloud"}


@dataclass
class AccessCheck:
    ok: bool
    message: str
    scopes: list[dict[str, str]] = field(default_factory=list)


def _redact(text: str, secrets: dict[str, str]) -> str:
    values = [v for v in secrets.values() if v and len(v) >= 4]
    for v in secrets.values():
        try:
            key = json.loads(v) if v and v.lstrip().startswith("{") else None
        except ValueError:
            key = None
        if isinstance(key, dict):
            values += [str(key[k]) for k in ("private_key", "private_key_id") if key.get(k)]
    for v in sorted(values, key=len, reverse=True):
        text = text.replace(v, "[redacted]")
    return text


def _status(exc: Exception) -> int | None:
    for attr in ("status_code", "status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int):
            return v
    return None


def _aws_code(exc: Exception) -> tuple[str, str]:
    resp = getattr(exc, "response", None)
    err = resp.get("Error", {}) if isinstance(resp, dict) else {}
    return str(err.get("Code", "")), str(getattr(exc, "operation_name", "") or "")


def _first_line(exc: Exception) -> str:
    text = str(exc).strip().splitlines()
    return text[0][:240] if text else ""


def explain(provider: str, scope: str, exc: Exception) -> str:  # noqa: C901 - one branch per known failure
    """A short message for an admin: what failed and what to change."""
    name = type(exc).__name__
    label = LABEL.get(provider, provider)
    if name in ("ConnectionError", "ConnectTimeout", "ReadTimeout", "ServiceRequestError", "EndpointConnectionError",
                "ConnectTimeoutError", "ReadTimeoutError", "TransportError"):
        return f"Could not reach {label} from the server ({name}). Check its outbound HTTPS access and try again."
    if provider == "azure":
        code = str(getattr(getattr(exc, "error", None), "code", "") or "")
        if name == "ClientAuthenticationError" or "AADSTS" in str(exc):
            return ("Azure rejected the credentials. Check the tenant ID, client ID and client secret "
                    "(a new client secret can take a minute to start working).")
        if _status(exc) == 403 or code == "AuthorizationFailed":
            return (f"The service principal cannot read subscription {scope}. Assign it the Reader role on that "
                    "subscription (new role assignments can take a few minutes).")
        if _status(exc) == 404 or code in ("SubscriptionNotFound", "InvalidSubscriptionId"):
            return f"Subscription {scope} was not found in this tenant. Check the subscription ID."
    elif provider == "aws":
        code, op = _aws_code(exc)
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException",
                    "AuthFailure", "InvalidAccessKeyId") or name in ("NoCredentialsError", "PartialCredentialsError"):
            return ("AWS rejected the access key. Check the access key ID and secret access key "
                    "(a new key can take a few seconds to start working).")
        if op == "AssumeRole" or (scope.startswith("arn:") and code == "AccessDenied" and op != "ListAccountAliases"):
            return (f"Could not assume {scope}. Check the role's trust policy (it must trust the scanner user) "
                    "and the external ID.")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return ("The access key works but cannot read the account. Attach the AWS managed policies "
                    "SecurityAudit and job-function/ViewOnlyAccess to the scanner user (or role).")
    elif provider == "gcp":
        if name == "RefreshError":
            return ("Google rejected the service-account key (deleted or disabled key, or a disabled "
                    "service account). Create a new key and paste it again.")
        if getattr(exc, "service_disabled", False):
            return ("The Cloud Resource Manager API is disabled in the service account's project. Run "
                    "`gcloud services enable cloudresourcemanager.googleapis.com` there and try again.")
        if _status(exc) == 403:
            return (f"The service account cannot read {scope}. Grant it roles/viewer and "
                    "roles/iam.securityReviewer there (IAM changes can take a minute).")
        if _status(exc) == 404:
            return f"{scope} was not found. Check the project ID."
        if name in ("ValueError", "DefaultCredentialsError", "MalformedError"):
            return "The service-account key could not be loaded. Paste the whole key.json file."
    detail = _first_line(exc)
    where = "" if scope == "credentials" else f" for {scope}"
    return f"{label} connection test failed{where}: {name}{': ' + detail if detail else ''}"


def run(provider: str, settings: Settings, secrets: dict[str, str] | None = None,
        timeout: float = TIMEOUT_SECONDS) -> AccessCheck:
    """Test `provider` with `settings` (explicit credentials only, see
    org_config.probe_settings). Never raises for a cloud-side failure."""
    secrets = secrets or {}
    label = LABEL.get(provider, provider)
    conn = build_registry(settings)[provider]
    if not conn.is_configured():
        return AccessCheck(False, f"Enter every required {label} value before testing.")
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"access-check-{provider}")
    try:
        scopes = pool.submit(conn.check_access).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        log.info("connection test %s: timed out", provider)
        return AccessCheck(False, f"No answer from {label} within {max(1, round(timeout))} seconds. Try again; if it keeps "
                                  "happening, check the server's outbound HTTPS access.")
    except Exception as exc:  # noqa: BLE001 - every failure becomes a message
        scope, cause = (exc.scope, exc.cause) if isinstance(exc, ScopeAccessError) else ("credentials", exc)
        log.info("connection test %s: failed (%s)", provider, type(cause).__name__)
        return AccessCheck(False, _redact(explain(provider, scope, cause), secrets)[:400])
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    log.info("connection test %s: ok (%d scopes)", provider, len(scopes))
    names = ", ".join(s["name"] for s in scopes[:5]) + (" …" if len(scopes) > 5 else "")
    return AccessCheck(True, f"Connected to {label}: read access to {names}." if names else f"Connected to {label}.",
                       scopes)
