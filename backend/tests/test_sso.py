"""Microsoft Entra ID SSO against a mocked identity provider (httpx.MockTransport),
plus the password-login policy and break-glass access. Nothing talks to Microsoft."""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from sqlalchemy import select

from app import config, db, entra
from app.models import AuditLog, OidcAuthRequest, User, UserIdentity
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, BASE_URL, login, make_user, reset_database

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AUTHORITY = "https://login.microsoftonline.com"
ISSUER = f"{AUTHORITY}/{TENANT}/v2.0"
TOKEN_URL = f"{AUTHORITY}/{TENANT}/oauth2/v2.0/token"
REDIRECT = "https://cnapp.example.com/api/auth/sso/entra/callback"
USER_PW = "a-long-test-password"


class FakeEntra:
    """Minimal Entra ID: discovery, JWKS and a token endpoint issuing the next ID token."""

    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "key-1"}, private=True)
        self.published = [self.key]
        self.claims: dict = {}
        self.sign_with: RSAKey | None = None
        self.token_requests: list[dict] = []
        self.jwks_fetches = 0
        self.token_status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == f"{AUTHORITY}/{TENANT}/v2.0/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": f"{AUTHORITY}/{TENANT}/oauth2/v2.0/authorize",
                "token_endpoint": TOKEN_URL, "jwks_uri": f"{AUTHORITY}/{TENANT}/discovery/v2.0/keys"})
        if url == f"{AUTHORITY}/{TENANT}/discovery/v2.0/keys":
            self.jwks_fetches += 1
            return httpx.Response(200, json=KeySet([RSAKey.import_key(k.as_dict(private=False))
                                                    for k in self.published]).as_dict())
        if url == TOKEN_URL and request.method == "POST":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"token_type": "Bearer", "access_token": "at",
                                             "id_token": self.id_token(form)})
        return httpx.Response(404)

    def id_token(self, form: dict) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT, "tid": TENANT, "oid": "oid-alice", "sub": "sub-alice",
                  "nonce": self.nonce, "iat": now, "nbf": now, "exp": now + 3600, "name": "Alice Analyst",
                  "preferred_username": "alice@example.com", "ver": "2.0"}
        claims.update(self.claims)
        claims = {k: v for k, v in claims.items() if v is not None}
        key = self.sign_with or self.key
        return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, claims, key)


@pytest.fixture()
def idp(monkeypatch):
    fake = FakeEntra()
    for k, v in {"ENTRA_TENANT_ID": TENANT, "ENTRA_CLIENT_ID": CLIENT, "ENTRA_CLIENT_SECRET": "s3cret",
                 "ENTRA_REDIRECT_URI": REDIRECT}.items():
        monkeypatch.setenv(k, v)
    entra.set_transport(httpx.MockTransport(fake.handler))
    yield fake
    entra.set_transport(None)


@pytest.fixture()
def app_client(idp):
    config.reload_settings()
    reset_database()
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        yield c
    config.reload_settings()


@pytest.fixture()
def admin(app_client):
    login(app_client)
    return app_client


def browser(c: TestClient) -> TestClient:
    return TestClient(c.app, base_url=BASE_URL)


def start(b: TestClient, idp: FakeEntra, next_path: str | None = None) -> dict:
    r = b.get("/api/auth/sso/entra/login", params={"next": next_path} if next_path else None, follow_redirects=False)
    assert r.status_code == 302, r.text
    loc = urlparse(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert loc.netloc == "login.microsoftonline.com" and loc.path == f"/{TENANT}/oauth2/v2.0/authorize"
    idp.nonce = q["nonce"]
    return q


def callback(b: TestClient, **params) -> httpx.Response:
    return b.get("/api/auth/sso/entra/callback", params=params, follow_redirects=False)


def sso_login(b: TestClient, idp: FakeEntra, next_path: str | None = None) -> httpx.Response:
    q = start(b, idp, next_path)
    return callback(b, code="auth-code", state=q["state"])


def error_of(r: httpx.Response) -> str | None:
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    return q.get("sso_error", [None])[0]


def audit_rows(action: str) -> list[AuditLog]:
    with db.get_session() as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def me(b: TestClient) -> dict:
    r = b.get("/api/auth/me")
    assert r.status_code == 200, r.text
    return r.json()


# --- providers / configuration ------------------------------------------------------------

def test_providers_without_entra(anon_client):
    assert anon_client.get("/api/auth/providers").json() == {"password": True, "entra": False,
                                                             "entra_label": "Microsoft"}
    assert anon_client.get("/api/auth/sso/entra/login", follow_redirects=False).status_code == 404
    assert anon_client.get("/api/auth/sso/entra/callback?code=x&state=y").status_code == 404


def test_providers_with_entra(app_client):
    assert app_client.get("/api/auth/providers").json()["entra"] is True


def test_multi_tenant_alias_is_rejected(monkeypatch):
    monkeypatch.setenv("ENTRA_TENANT_ID", "common")
    monkeypatch.setenv("ENTRA_CLIENT_ID", CLIENT)
    config.reload_settings()
    try:
        from app.main import create_app

        with pytest.raises(RuntimeError, match="ENTRA_TENANT_ID"):
            create_app()
    finally:
        monkeypatch.delenv("ENTRA_TENANT_ID")
        monkeypatch.delenv("ENTRA_CLIENT_ID")
        config.reload_settings()


# --- happy path --------------------------------------------------------------------------------

def test_sso_login_links_existing_user_and_issues_normal_session(admin, idp):
    make_user(admin, "analyst", "alice@example.com")
    b = browser(admin)
    q = start(b, idp, "/findings?x=1")
    assert q["response_type"] == "code" and q["client_id"] == CLIENT and q["redirect_uri"] == REDIRECT
    assert q["code_challenge_method"] == "S256" and q["response_mode"] == "query"
    assert set(q["scope"].split()) == {"openid", "profile", "email"}
    assert "cnapp_oidc" in b.cookies

    r = callback(b, code="auth-code", state=q["state"])
    assert r.status_code == 302 and r.headers["location"] == "/findings?x=1"
    cookies = r.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("cnapp_session="))
    for attr in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert attr.lower() in session_cookie.lower()

    # PKCE: the verifier sent to the token endpoint matches the challenge
    form = idp.token_requests[-1]
    digest = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert digest == q["code_challenge"]
    assert form["grant_type"] == "authorization_code" and form["code"] == "auth-code"
    assert form["client_secret"] == "s3cret" and form["redirect_uri"] == REDIRECT

    # same session + CSRF machinery as password login
    info = me(b)
    assert info["user"]["email"] == "alice@example.com" and info["user"]["role"] == "analyst"
    assert info["user"]["auth_sources"] == ["entra", "password"] or info["user"]["auth_sources"] == [
        "password", "entra"]
    assert b.post("/api/auth/logout").status_code == 403  # CSRF still enforced
    b.headers["X-CSRF-Token"] = info["csrf_token"]
    assert b.post("/api/auth/logout").status_code == 204

    with db.get_session() as s:
        ident = s.scalar(select(UserIdentity))
        assert (ident.provider, ident.tenant_id, ident.subject) == ("entra", TENANT, "oid-alice")
        assert s.scalar(select(OidcAuthRequest)) is None  # consumed
    assert audit_rows("sso_identity_linked")
    assert audit_rows("login_success")[-1].detail == {"method": "entra"}


def test_returning_user_matched_by_oid_even_if_upn_changes(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    assert error_of(sso_login(browser(admin), idp)) is None
    idp.claims = {"preferred_username": "alice.renamed@example.com"}
    b = browser(admin)
    assert error_of(sso_login(b, idp)) is None
    assert me(b)["user"]["email"] == "alice@example.com"


def test_unverified_email_claim_is_not_trusted(admin, idp):
    make_user(admin, "admin", "victim@example.com")
    idp.claims = {"email": "victim@example.com", "preferred_username": "mallory@example.com"}
    assert error_of(sso_login(browser(admin), idp)) == "not_provisioned"
    idp.claims = {"email": "victim@example.com", "xms_edov": True, "preferred_username": "x@example.com"}
    b = browser(admin)
    assert error_of(sso_login(b, idp)) is None
    assert me(b)["user"]["email"] == "victim@example.com"


def test_unsafe_next_is_ignored(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    for bad in ("https://evil.example", "//evil.example", "/\\evil", "/login", "/api/auth/me"):
        r = sso_login(browser(admin), idp, bad)
        assert r.headers["location"] == "/", bad


# --- state / nonce / token validation ---------------------------------------------------

def test_bad_state(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    b = browser(admin)
    q = start(b, idp)
    assert error_of(callback(b, code="c", state="forged")) == "invalid_state"
    assert error_of(callback(b, code="c")) == "invalid_state"
    assert error_of(callback(b, code="c", state=q["state"])) is None
    # replay of the same state
    assert error_of(callback(b, code="c", state=q["state"])) == "invalid_state"
    assert all(r.detail["reason"] == "invalid_state" for r in audit_rows("sso_login_failure"))


def test_state_is_bound_to_the_browser(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    victim, attacker = browser(admin), browser(admin)
    q = start(attacker, idp)
    # login CSRF: the attacker's callback URL opened in the victim's browser
    r = callback(victim, code="c", state=q["state"])
    assert error_of(r) == "invalid_state" and "cnapp_session" not in victim.cookies
    assert idp.token_requests == []  # the code was never redeemed


def test_expired_request(admin, idp):
    b = browser(admin)
    q = start(b, idp)
    with db.get_session() as s:
        s.scalar(select(OidcAuthRequest)).expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
        s.commit()
    assert error_of(callback(b, code="c", state=q["state"])) == "expired"


def test_idp_error_response(admin, idp):
    b = browser(admin)
    q = start(b, idp)
    r = callback(b, error="access_denied", error_description="<script>", state=q["state"])
    assert error_of(r) == "idp_error"
    assert audit_rows("sso_login_failure")[-1].detail["idp_error"] == "access_denied"


def test_token_endpoint_failure(admin, idp):
    idp.token_status = 400
    assert error_of(sso_login(browser(admin), idp)) == "token_exchange_failed"


@pytest.mark.parametrize("claims", [
    {"nonce": "wrong-nonce"},
    {"nonce": None},
    {"tid": "99999999-2222-3333-4444-555555555555"},
    {"aud": "another-client"},
    {"aud": [CLIENT, "another-client"]},
    {"azp": "another-client"},
    {"iss": f"{AUTHORITY}/99999999-2222-3333-4444-555555555555/v2.0"},
    {"iss": "https://sts.windows.net/" + TENANT + "/"},
    {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200, "nbf": int(time.time()) - 7200},
    {"nbf": int(time.time()) + 3600},
    {"oid": None},
], ids=["bad-nonce", "no-nonce", "wrong-tenant", "wrong-audience", "extra-audience", "wrong-azp",
        "wrong-issuer", "v1-issuer", "expired", "not-yet-valid", "no-oid"])
def test_invalid_id_tokens_are_rejected(admin, idp, claims):
    make_user(admin, "viewer", "alice@example.com")
    idp.claims = claims
    b = browser(admin)
    r = sso_login(b, idp)
    assert error_of(r) == "invalid_token"
    assert "cnapp_session" not in b.cookies
    assert audit_rows("sso_login_failure")[-1].detail["reason"] == "invalid_token"


def test_bad_signature_is_rejected(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    idp.sign_with = RSAKey.generate_key(2048, parameters={"kid": "key-1"}, private=True)  # same kid, other key
    assert error_of(sso_login(browser(admin), idp)) == "invalid_token"


def test_signing_key_rollover_refetches_jwks(admin, idp):
    make_user(admin, "viewer", "alice@example.com")
    assert error_of(sso_login(browser(admin), idp)) is None
    fetches = idp.jwks_fetches
    new_key = RSAKey.generate_key(2048, parameters={"kid": "key-2"}, private=True)
    idp.published = [idp.key, new_key]
    idp.sign_with = new_key
    assert error_of(sso_login(browser(admin), idp)) is None
    assert idp.jwks_fetches == fetches + 1
    # unknown kid even after refetch
    idp.sign_with = RSAKey.generate_key(2048, parameters={"kid": "key-3"}, private=True)
    assert error_of(sso_login(browser(admin), idp)) == "invalid_token"


# --- provisioning and role mapping ----------------------------------------------------------

def test_unknown_user_without_jit(admin, idp):
    r = sso_login(browser(admin), idp)
    assert error_of(r) == "not_provisioned"
    with db.get_session() as s:
        assert s.scalar(select(User).where(User.email == "alice@example.com")) is None
    assert audit_rows("sso_login_failure")[-1].actor_email == "alice@example.com"


def test_jit_provisioning(admin, idp, monkeypatch):
    monkeypatch.setattr(config.settings, "entra_jit_provisioning", True)
    b = browser(admin)
    assert error_of(sso_login(b, idp)) is None
    user = me(b)["user"]
    assert user["email"] == "alice@example.com" and user["role"] == "viewer" and user["name"] == "Alice Analyst"
    assert user["auth_sources"] == ["entra"]
    assert b.get("/api/auth/mfa").json()["has_password"] is False
    entry = audit_rows("user_provisioned")[0]
    assert entry.detail["provider"] == "entra" and entry.detail["role"] == "viewer"
    # a JIT user has no usable password
    r = browser(admin).post("/api/auth/login", json={"email": "alice@example.com", "password": "!sso"})
    assert r.status_code == 401


def test_jit_default_role(admin, idp, monkeypatch):
    monkeypatch.setattr(config.settings, "entra_jit_provisioning", True)
    monkeypatch.setattr(config.settings, "entra_default_role", "analyst")
    b = browser(admin)
    sso_login(b, idp)
    assert me(b)["user"]["role"] == "analyst"


def test_role_mapping(admin, idp, monkeypatch):
    monkeypatch.setattr(config.settings, "entra_jit_provisioning", True)
    monkeypatch.setattr(config.settings, "entra_role_map",
                        {"CNAPP.Admin": "admin", "CNAPP.Analyst": "analyst", "0f0f0f0f-group": "viewer"})
    idp.claims = {"roles": ["cnapp.analyst", "Unrelated"], "groups": ["0f0f0f0f-group"]}
    b = browser(admin)
    sso_login(b, idp)
    assert me(b)["user"]["role"] == "analyst"  # highest match, case-insensitive
    # role follows Entra at the next sign-in
    idp.claims = {"roles": ["CNAPP.Admin"]}
    b = browser(admin)
    sso_login(b, idp)
    assert me(b)["user"]["role"] == "admin"
    changes = [a.detail for a in audit_rows("user_updated") if a.detail.get("source") == "entra_role_map"]
    assert changes[-1]["changes"] == {"role": ["analyst", "admin"]}
    # no match: existing user keeps their role
    idp.claims = {"roles": []}
    b = browser(admin)
    sso_login(b, idp)
    assert me(b)["user"]["role"] == "admin"


def test_role_mapping_required(admin, idp, monkeypatch):
    make_user(admin, "viewer", "alice@example.com")
    monkeypatch.setattr(config.settings, "entra_role_map", {"CNAPP.Admin": "admin"})
    monkeypatch.setattr(config.settings, "entra_require_role", True)
    assert error_of(sso_login(browser(admin), idp)) == "no_role_assigned"


def test_role_sync_never_demotes_last_admin(admin, idp, monkeypatch):
    monkeypatch.setattr(config.settings, "entra_role_map", {"CNAPP.Viewer": "viewer"})
    idp.claims = {"preferred_username": ADMIN_EMAIL, "roles": ["CNAPP.Viewer"]}
    b = browser(admin)
    assert error_of(sso_login(b, idp)) is None
    assert me(b)["user"]["role"] == "admin"
    assert audit_rows("user_role_sync_skipped")


def test_inactive_user_is_refused(admin, idp):
    u = make_user(admin, "viewer", "alice@example.com")
    admin.patch(f"/api/users/{u['id']}", json={"is_active": False})
    assert error_of(sso_login(browser(admin), idp)) == "inactive"


# --- local MFA and SSO --------------------------------------------------------------------------

def _enable_totp(c: TestClient) -> str:
    secret = c.post("/api/auth/mfa/totp/setup").json()["secret"]
    assert c.post("/api/auth/mfa/totp/enable", json={"code": pyotp.TOTP(secret).now()}).status_code == 200
    return secret


def test_sso_skips_local_mfa_by_default(admin, idp, monkeypatch):
    make_user(admin, "analyst", "alice@example.com")
    a = browser(admin)
    login(a, "alice@example.com", USER_PW)
    _enable_totp(a)
    monkeypatch.setattr(config.settings, "mfa_required_roles", ["analyst"])
    b = browser(admin)
    r = sso_login(b, idp)
    assert r.headers["location"] == "/" and me(b)["user"]["email"] == "alice@example.com"


def test_sso_with_enforced_local_mfa(admin, idp, monkeypatch):
    make_user(admin, "analyst", "alice@example.com")
    a = browser(admin)
    login(a, "alice@example.com", USER_PW)
    secret = _enable_totp(a)
    monkeypatch.setattr(config.settings, "entra_enforce_local_mfa", True)
    b = browser(admin)
    r = sso_login(b, idp, "/threats")
    loc = urlparse(r.headers["location"])
    assert loc.path == "/login" and "cnapp_session" not in b.cookies
    frag = {k: v[0] for k, v in parse_qs(loc.fragment).items()}
    assert frag["purpose"] == "verify" and frag["next"] == "/threats"
    code = pyotp.TOTP(secret).at(time.time() + 30)
    r = b.post("/api/auth/login/mfa", json={"mfa_token": frag["mfa_token"], "code": code})
    assert r.status_code == 200
    assert audit_rows("login_success")[-1].detail == {"method": "entra", "mfa": "totp"}


# --- client credentials ------------------------------------------------------------------------

def _self_signed_pem() -> tuple[str, x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cnapp-sso")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM)
    return pem.decode(), cert, key


def test_certificate_client_assertion(admin, idp, monkeypatch):
    make_user(admin, "viewer", "alice@example.com")
    pem, cert, key = _self_signed_pem()
    monkeypatch.setattr(config.settings, "entra_client_secret", None)
    monkeypatch.setattr(config.settings, "entra_client_certificate", pem)
    assert entra.client_auth_mode() == "certificate"
    assert error_of(sso_login(browser(admin), idp)) is None
    form = idp.token_requests[-1]
    assert "client_secret" not in form
    assert form["client_assertion_type"] == entra.CLIENT_ASSERTION_TYPE
    pub = RSAKey.import_key(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
    tok = jwt.decode(form["client_assertion"], pub, algorithms=["RS256"])
    der = cert.public_bytes(serialization.Encoding.DER)
    assert tok.header["x5t#S256"] == base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
    assert tok.claims["aud"] == TOKEN_URL and tok.claims["iss"] == tok.claims["sub"] == CLIENT
    assert tok.claims["exp"] - tok.claims["iat"] <= 600
    uuid.UUID(tok.claims["jti"])


def test_managed_identity_federated_credential(admin, idp, monkeypatch):
    make_user(admin, "viewer", "alice@example.com")
    monkeypatch.setattr(config.settings, "entra_client_secret", None)
    monkeypatch.setattr(config.settings, "entra_managed_identity_client_id", "mi-client-id")
    monkeypatch.setattr(entra, "managed_identity_assertion", lambda: "mi-federated-token")
    assert entra.client_auth_mode() == "managed_identity"
    assert error_of(sso_login(browser(admin), idp)) is None
    form = idp.token_requests[-1]
    assert form["client_assertion"] == "mi-federated-token" and "client_secret" not in form


def test_no_client_credential_hides_sso(admin, idp, monkeypatch):
    monkeypatch.setattr(config.settings, "entra_client_secret", None)
    monkeypatch.setattr(config.settings, "entra_managed_identity_client_id", None)
    assert admin.get("/api/auth/providers").json()["entra"] is False
    assert admin.get("/api/auth/sso/entra/login", follow_redirects=False).status_code == 404


# --- password login policy & break-glass -------------------------------------------------------

def test_password_login_disabled_globally_keeps_break_glass(admin, monkeypatch):
    make_user(admin, "analyst", "alice@example.com")
    monkeypatch.setattr(config.settings, "auth_password_login_enabled", False)
    assert admin.get("/api/auth/providers").json()["password"] is False
    b = browser(admin)
    # wrong password: the usual generic 401 (no hint about the policy)
    assert b.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-wrong-wrong"}
                  ).status_code == 401
    r = b.post("/api/auth/login", json={"email": "alice@example.com", "password": USER_PW})
    assert r.status_code == 403 and "cnapp_session" not in b.cookies
    assert audit_rows("login_password_disabled")
    # break-glass: ADMIN_EMAIL by default
    assert config.settings.auth_break_glass_emails == [ADMIN_EMAIL]
    r = browser(admin).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200 and r.json()["csrf_token"]


def test_break_glass_list_is_configurable(admin, monkeypatch):
    make_user(admin, "admin", "breakglass@example.com")
    monkeypatch.setenv("AUTH_PASSWORD_LOGIN_ENABLED", "false")
    monkeypatch.setenv("AUTH_BREAK_GLASS_EMAILS", "BreakGlass@example.com")
    config.reload_settings()
    b = browser(admin)
    assert b.post("/api/auth/login", json={"email": "breakglass@example.com", "password": USER_PW}).status_code == 200
    assert b.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).status_code == 403


def test_break_glass_still_requires_its_mfa(admin, monkeypatch):
    secret = _enable_totp(admin)
    monkeypatch.setattr(config.settings, "auth_password_login_enabled", False)
    r = browser(admin).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200 and r.json()["mfa_required"] is True
    assert secret


def test_sso_linked_users_cannot_use_password_by_default(admin, idp, monkeypatch):
    make_user(admin, "analyst", "alice@example.com")
    sso_login(browser(admin), idp)
    r = browser(admin).post("/api/auth/login", json={"email": "alice@example.com", "password": USER_PW})
    assert r.status_code == 403
    monkeypatch.setattr(config.settings, "auth_password_login_for_sso_users", True)
    r = browser(admin).post("/api/auth/login", json={"email": "alice@example.com", "password": USER_PW})
    assert r.status_code == 200
    users = {u["email"]: u for u in admin.get("/api/users").json()}
    assert sorted(users["alice@example.com"]["auth_sources"]) == ["entra", "password"]


def test_cli_reset_mfa_break_glass(admin):
    import argparse

    from app import cli

    _enable_totp(admin)
    assert cli.reset_mfa(argparse.Namespace(email=ADMIN_EMAIL.upper())) == 0
    r = browser(admin).post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200 and "csrf_token" in r.json()
    assert audit_rows("mfa_reset")[-1].actor_email == "cli"
    with pytest.raises(SystemExit):
        cli.reset_mfa(argparse.Namespace(email="nobody@example.com"))
