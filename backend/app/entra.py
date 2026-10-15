"""Microsoft Entra ID single sign-on: OpenID Connect authorization code flow with PKCE.

* The authorization request carries a random `state` (CSRF / request binding),
  a `nonce` (ID-token replay) and a PKCE S256 challenge. All three are kept
  server-side in `oidc_auth_requests`, keyed by an HMAC of `state` and bound to
  the browser that started the flow through a random httpOnly cookie; the row
  is deleted on first use and expires after 10 minutes.
* The code is redeemed at the token endpoint (plain httpx POST) with one
  of three client credentials: a certificate (private_key_jwt with x5t#S256),
  a managed identity token as federated credential (no secret at all), or a
  client secret.
* The ID token is validated locally: RS256 signature against the tenant's JWKS
  (fetched from OIDC discovery, cached, refreshed on an unknown `kid`), `iss`
  for the configured tenant, `aud` = our client id, `tid`, `nonce`, `exp`,
  `nbf` and `iat` (60 s leeway). The access token is not used.

All HTTP goes through `httpx`; tests swap in an `httpx.MockTransport` via
`set_transport()`, so no test ever talks to Microsoft.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field

import httpx
from authlib.common.security import generate_token
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet, RSAKey

from . import config

log = logging.getLogger(__name__)

SCOPES = "openid profile email"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
FEDERATED_AUDIENCE = "api://AzureADTokenExchange/.default"
LEEWAY_SECONDS = 60
HTTP_TIMEOUT = 10.0
_CACHE_SECONDS = 3600


class SsoError(Exception):
    """Sign-in failed. `code` is a fixed identifier safe to show in the UI / audit log."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


_transport: httpx.BaseTransport | None = None


def set_transport(transport: httpx.BaseTransport | None) -> None:
    """Route all IdP HTTP calls through `transport` (tests); clears the caches."""
    global _transport
    _transport = transport
    clear_cache()


def _http() -> httpx.Client:
    return httpx.Client(transport=_transport, timeout=HTTP_TIMEOUT, follow_redirects=False)


# --- metadata (discovery + JWKS), cached --------------------------------------------

@dataclass
class _Cache:
    metadata: dict | None = None
    metadata_at: float = 0.0
    jwks: dict | None = None
    jwks_at: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)


_cache = _Cache()


def clear_cache() -> None:
    global _cache
    _cache = _Cache()


def authority() -> str:
    s = config.settings
    return f"{s.entra_authority_host}/{s.entra_tenant_id}"


def expected_issuer() -> str:
    s = config.settings
    return f"{s.entra_authority_host}/{s.entra_tenant_id}/v2.0"


def _get_json(url: str) -> dict:
    try:
        with _http() as c:
            r = c.get(url)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("Entra metadata request failed: %s", e)
        raise SsoError("idp_unavailable") from e


def metadata() -> dict:
    with _cache.lock:
        if _cache.metadata and time.monotonic() - _cache.metadata_at < _CACHE_SECONDS:
            return _cache.metadata
    md = _get_json(f"{authority()}/v2.0/.well-known/openid-configuration")
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not isinstance(md.get(k), str):
            raise SsoError("idp_unavailable", f"discovery document lacks {k}")
    # The discovery issuer must be the tenant-specific one we validate tokens against.
    if md["issuer"] != expected_issuer():
        raise SsoError("idp_misconfigured", f"unexpected issuer in discovery: {md['issuer']}")
    with _cache.lock:
        _cache.metadata, _cache.metadata_at = md, time.monotonic()
    return md


def _jwks(force: bool = False) -> KeySet:
    with _cache.lock:
        cached = _cache.jwks if not force and time.monotonic() - _cache.jwks_at < _CACHE_SECONDS else None
    if cached is None:
        cached = _get_json(metadata()["jwks_uri"])
        with _cache.lock:
            _cache.jwks, _cache.jwks_at = cached, time.monotonic()
    try:
        return KeySet.import_key_set(cached)
    except (JoseError, ValueError, KeyError, TypeError) as e:
        raise SsoError("idp_unavailable", "invalid JWKS") from e


# --- authorization request ------------------------------------------------------------

@dataclass
class AuthRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


def _redirect_uri(fallback: str) -> str:
    return config.settings.entra_redirect_uri or fallback


def build_authorization_request(redirect_uri_fallback: str, login_hint: str | None = None) -> AuthRequest:
    s = config.settings
    md = metadata()
    state, nonce, verifier = generate_token(43), generate_token(43), generate_token(64)
    params = {"nonce": nonce, "response_mode": "query", "code_challenge": create_s256_code_challenge(verifier),
              "code_challenge_method": "S256"}
    if login_hint:
        params["login_hint"] = login_hint
    url = prepare_grant_uri(md["authorization_endpoint"], client_id=s.entra_client_id, response_type="code",
                            redirect_uri=_redirect_uri(redirect_uri_fallback), scope=SCOPES, state=state, **params)
    return AuthRequest(url=url, state=state, nonce=nonce, code_verifier=verifier)


# --- client credentials -------------------------------------------------------------------

def client_auth_mode() -> str:
    s = config.settings
    mode = s.entra_client_auth
    if mode != "auto":
        return mode
    if s.entra_client_certificate:
        return "certificate"
    if s.entra_client_secret:
        return "secret"
    if s.entra_managed_identity_client_id:
        return "managed_identity"
    return "none"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def certificate_assertion(pem: str, token_endpoint: str) -> str:
    """private_key_jwt client assertion signed with the app's certificate key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    data = pem.encode()
    try:
        cert = x509.load_pem_x509_certificate(data)
        key = serialization.load_pem_private_key(data, password=None)
    except ValueError as e:
        raise SsoError("client_credential_invalid", "ENTRA_CLIENT_CERTIFICATE must be a PEM with key + cert") from e
    der = cert.public_bytes(serialization.Encoding.DER)
    s = config.settings
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(hashlib.sha1(der).digest()),  # noqa: S324 (thumbprint)
              "x5t#S256": _b64url(hashlib.sha256(der).digest())}
    claims = {"aud": token_endpoint, "iss": s.entra_client_id, "sub": s.entra_client_id, "jti": str(uuid.uuid4()),
              "iat": now, "nbf": now, "exp": now + 300}
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return jwt.encode(header, claims, RSAKey.import_key(pem_key), algorithms=["RS256"])


def managed_identity_assertion() -> str:
    """Federated credential: a managed identity token for api://AzureADTokenExchange."""
    from azure.identity import ManagedIdentityCredential

    s = config.settings
    try:
        cred = ManagedIdentityCredential(client_id=s.entra_managed_identity_client_id)
        return cred.get_token(FEDERATED_AUDIENCE).token
    except Exception as e:  # noqa: BLE001 - any credential failure means "cannot sign in"
        log.warning("managed identity token for the Entra federated credential failed: %s", e)
        raise SsoError("client_credential_invalid") from e


def _token_request_auth(token_endpoint: str) -> dict:
    """Client authentication parameters for the token request body."""
    s = config.settings
    mode = client_auth_mode()
    if mode == "secret":
        if not s.entra_client_secret:
            raise SsoError("client_credential_invalid", "ENTRA_CLIENT_SECRET is not set")
        return {"client_secret": s.entra_client_secret}
    if mode == "certificate":
        if not s.entra_client_certificate:
            raise SsoError("client_credential_invalid", "ENTRA_CLIENT_CERTIFICATE is not set")
        assertion = certificate_assertion(s.entra_client_certificate, token_endpoint)
    elif mode == "managed_identity":
        assertion = managed_identity_assertion()
    else:
        raise SsoError("client_credential_invalid", "no Entra client credential configured")
    return {"client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": assertion}


def exchange_code(code: str, code_verifier: str, redirect_uri_fallback: str) -> dict:
    """Redeem the authorization code (with the PKCE verifier); returns the token response."""
    s = config.settings
    md = metadata()
    body = {"grant_type": "authorization_code", "client_id": s.entra_client_id, "code": code,
            "redirect_uri": _redirect_uri(redirect_uri_fallback), "code_verifier": code_verifier, "scope": SCOPES,
            **_token_request_auth(md["token_endpoint"])}
    try:
        with _http() as c:
            r = c.post(md["token_endpoint"], data=body, headers={"Accept": "application/json"})
        token = r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("Entra token request failed: %s", e)
        raise SsoError("token_exchange_failed") from e
    if r.status_code != 200 or not isinstance(token, dict):
        err = token.get("error") if isinstance(token, dict) else None
        log.warning("Entra token request rejected (%s): %s", r.status_code, err)
        raise SsoError("token_exchange_failed", str(err or r.status_code))
    if not isinstance(token.get("id_token"), str):
        raise SsoError("token_exchange_failed", "no id_token in the token response")
    return token


# --- ID token validation -------------------------------------------------------------------

def validate_id_token(id_token: str, nonce: str) -> dict:
    s = config.settings
    try:
        keys = _jwks()
        try:
            tok = jwt.decode(id_token, keys, algorithms=["RS256"])
        except InvalidKeyIdError:
            # Signing keys roll over: refetch the JWKS once for an unknown kid.
            tok = jwt.decode(id_token, _jwks(force=True), algorithms=["RS256"])
    except JoseError as e:
        raise SsoError("invalid_token", f"signature: {e}") from e
    except ValueError as e:
        raise SsoError("invalid_token", f"malformed: {e}") from e

    claims = tok.claims
    registry = jwt.JWTClaimsRegistry(
        leeway=LEEWAY_SECONDS,
        iss={"essential": True, "value": expected_issuer()},
        aud={"essential": True, "value": s.entra_client_id},
        tid={"essential": True, "value": s.entra_tenant_id},
        nonce={"essential": True, "value": nonce},
        exp={"essential": True},
        iat={"essential": True},
        oid={"essential": True},
    )
    try:
        registry.validate(claims)
    except JoseError as e:
        raise SsoError("invalid_token", f"claims: {e}") from e
    # A token may list several audiences; only accept ours (and azp, if present, must be us).
    aud = claims.get("aud")
    if isinstance(aud, list) and (len(aud) != 1 or aud[0] != s.entra_client_id):
        raise SsoError("invalid_token", "unexpected audience list")
    if claims.get("azp") not in (None, s.entra_client_id):
        raise SsoError("invalid_token", "unexpected azp")
    return claims


# --- identity mapping ------------------------------------------------------------------------

def claimed_email(claims: dict) -> str | None:
    """The email to match / provision a local user by.

    `email` only when Microsoft marks its domain as verified by the tenant
    (`xms_edov`); otherwise `preferred_username`, which for a single-tenant app is
    the user's UPN in YOUR directory (assigned by your administrators)."""
    email = claims.get("email")
    if isinstance(email, str) and "@" in email and claims.get("xms_edov") in (True, "true", "1", 1):
        return email.strip().lower()
    upn = claims.get("preferred_username") or claims.get("upn")
    if isinstance(upn, str) and "@" in upn and "#ext#" not in upn.lower():
        return upn.strip().lower()
    return None


def mapped_role(claims: dict) -> str | None:
    """Highest local role granted by the token's app roles / groups via ENTRA_ROLE_MAP."""
    from .auth import ROLE_RANK

    role_map = config.settings.entra_role_map
    if not role_map:
        return None
    values: set[str] = set()
    for claim in ("roles", "groups"):
        v = claims.get(claim)
        if isinstance(v, list):
            values.update(str(x) for x in v)
    lowered = {k.lower(): r for k, r in role_map.items()}
    matches = [lowered[v.lower()] for v in values if v.lower() in lowered]
    if not matches:
        return None
    return max(matches, key=lambda r: ROLE_RANK.get(r, -1))


def new_binding() -> str:
    return secrets.token_urlsafe(32)
