"""Product modules (sold separately): a platform owner switches each one on or
off per organisation (Platform > Organisations). Turning a module off keeps its
data (it is hidden and its APIs answer 403 `module_disabled`); turning it back
on shows it again.

`Organization.modules` is a JSON list of enabled keys. NULL means "never set":
every module is on, including `external` (databases that predate modules; the Alembic migrations write
explicit lists for existing organisations: 0031 the first four, so `external` stays off for them).
New organisations are created with an explicit empty list."""
from __future__ import annotations

from collections.abc import Iterable

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from . import tenancy
from .db import get_db

CLOUD = "cloud"
ENDPOINTS = "endpoints"
VULNERABILITIES = "vulnerabilities"
ASSETS = "assets"
EXTERNAL = "external"
ALL_MODULES: tuple[str, ...] = (CLOUD, ENDPOINTS, VULNERABILITIES, ASSETS, EXTERNAL)

LABELS = {CLOUD: "Cloud security", ENDPOINTS: "Endpoints & servers", VULNERABILITIES: "Vulnerabilities",
          ASSETS: "Assets & identity", EXTERNAL: "Attack surface & pre-ASV"}


class ModuleDisabled(Exception):
    """The organisation does not have (one of) the module(s); answered with 403."""

    def __init__(self, module: str):
        super().__init__(module)
        self.module = module


async def module_disabled_handler(_: Request, exc: ModuleDisabled) -> JSONResponse:
    return JSONResponse({"detail": "module_disabled", "module": exc.module}, status_code=403)


def normalize(keys: Iterable[str]) -> list[str]:
    """Known keys only, once each, in the canonical order."""
    wanted = set(keys)
    return [m for m in ALL_MODULES if m in wanted]


def coerce(stored: Iterable[str] | None) -> list[str]:
    """Stored value to the enabled list (NULL = never set = all)."""
    return list(ALL_MODULES) if stored is None else normalize(stored)


def enabled_modules(org) -> list[str]:
    """The modules of an organisation (all of them when never set)."""
    return coerce(None if org is None else org.modules)


def check(db: Session, *keys: str, org_id: str | None = None) -> None:
    """Raise ModuleDisabled unless at least one of `keys` is on for `org_id`
    (default: the session's organisation)."""
    org = tenancy.get_org(db, org_id or tenancy.require_org(db))
    on = enabled_modules(org)
    if not any(k in on for k in keys):
        raise ModuleDisabled(keys[0])


def has_module(db: Session, key: str, org_id: str | None = None) -> bool:
    try:
        check(db, key, org_id=org_id)
    except ModuleDisabled:
        return False
    return True


def require_module(*keys: str):
    """Route / router dependency: 403 `module_disabled` unless the session's
    organisation has the module (with several keys: any one of them). Platform
    owners get no bypass: they see the customer's view."""
    from .auth import current_session

    def dep(_=Depends(current_session), db: Session = Depends(get_db)) -> None:
        check(db, *keys)

    dep.__name__ = "require_module_" + "_or_".join(keys)
    return dep


def ensure(db: Session, key: str, org_id: str) -> None:
    """Machine-credential variant (agents, sensors): same check, as an HTTP error."""
    if not has_module(db, key, org_id):
        raise HTTPException(403, "module_disabled")
