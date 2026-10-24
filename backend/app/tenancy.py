"""Multi-tenancy: every tenant-owned row belongs to exactly one organisation,
and the ORM enforces it centrally (docs/MULTI_TENANCY.md).

How isolation is enforced
-------------------------
* Tenant-owned models inherit `TenantMixin` (an `organization_id` column with
  a foreign key to `organizations`). Global reference data (CVE / KEV / EPSS
  caches, agent releases, signed script bundles, user accounts and their MFA
  state, login sessions) does not.
* Every SQLAlchemy `Session` is in one of three modes, kept in `session.info`:

  - organisation mode (`set_org(session, org_id)`): every ORM SELECT, UPDATE
    and DELETE touching a tenant model gets `organization_id = :org` added
    (`with_loader_criteria`, also inside joins, eager loads, relationship
    loads, `Session.get` and subqueries); new tenant rows get the organisation
    stamped on flush, and flushing a row of another organisation (insert,
    update or delete) raises `TenancyError`.
  - unscoped mode (`set_unscoped(session)` / `with unscoped(session):`): no
    filtering, for platform-owner and system code that works across
    organisations on purpose (login lookups, machine-credential resolution,
    the platform console). New tenant rows must then name their organisation.
  - unset (a fresh session): any statement touching a tenant table raises
    `TenancyError`. Code that forgets to choose a context fails closed instead
    of silently reading or writing another organisation's data.

* Requests get their organisation from the authenticated principal: the user's
  session (`auth.current_session`), the device credential / enrollment token
  (endpoint agents) or the ingest token (runtime sensors). Background jobs
  iterate over active organisations and open one session per organisation.

The filter covers ORM statements; raw SQL (`text()`) and Core statements on
`Table` objects bypass it, so application code does not use them on tenant
tables (the cross-tenant test-suite checks the main paths).
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, event, inspect, select
from sqlalchemy.orm import Mapped, ORMExecuteState, Session, declared_attr, mapped_column, with_loader_criteria
from sqlalchemy.sql.util import find_tables

if TYPE_CHECKING:  # pragma: no cover
    from .models import Organization

log = logging.getLogger(__name__)

#: Primary key of the organisation that existing (pre multi-tenancy) data is
#: migrated into: the installation operator's organisation. Environment-only
#: settings (cloud connector credentials, INGEST_API_TOKEN, Entra ID SSO, the
#: simulated data source) apply to it.
DEFAULT_ORG_ID = "default"
DEFAULT_ORG_SLUG = "default"

ORG_KEY = "tenant_org_id"
MODE_KEY = "tenant_mode"
ORG_MODE = "org"
UNSCOPED_MODE = "unscoped"


class TenancyError(RuntimeError):
    """A statement or flush would cross an organisation boundary, or ran without
    an organisation context."""


class TenantMixin:
    """Adds the owning organisation to a model (indexed, required, FK)."""

    @declared_attr
    def organization_id(cls) -> Mapped[str]:  # noqa: N805 - declared_attr receives the class
        # (also evaluated on the mixin itself by with_loader_criteria's lambda analysis)
        table = getattr(cls, "__tablename__", "tenant")
        return mapped_column(String(32), ForeignKey("organizations.id", name=f"fk_{table}_organization_id"),
                             index=True, nullable=False)


_tenant_tables: set[str] | None = None


def tenant_tables() -> set[str]:
    """Names of all tables owned by an organisation."""
    global _tenant_tables
    if _tenant_tables is None:
        from .db import Base

        _tenant_tables = {m.local_table.name for m in Base.registry.mappers if issubclass(m.class_, TenantMixin)}
    return _tenant_tables


# --------------------------------------------------------------------------- session context
def set_org(session: Session, org_id: str) -> Session:
    """Scope `session` to one organisation. Switching an already scoped session
    to another organisation is only allowed with nothing pending, and empties
    the identity map so no object of the previous organisation is reused."""
    if not org_id:
        raise TenancyError("organisation id required")
    current = session.info.get(ORG_KEY)
    if current is not None and current != org_id:
        if session.new or session.dirty or session.deleted:
            raise TenancyError("cannot switch organisation with pending changes")
        session.expunge_all()
    session.info[ORG_KEY] = org_id
    session.info[MODE_KEY] = ORG_MODE
    return session


def set_unscoped(session: Session) -> Session:
    """Cross-organisation (platform / system) access for this session."""
    session.info[ORG_KEY] = None
    session.info[MODE_KEY] = UNSCOPED_MODE
    return session


def clear(session: Session) -> None:
    session.info.pop(ORG_KEY, None)
    session.info.pop(MODE_KEY, None)


def org_id(session: Session) -> str | None:
    """The organisation `session` is scoped to (None when unscoped / unset)."""
    return session.info.get(ORG_KEY)


def require_org(session: Session) -> str:
    oid = org_id(session)
    if not oid:
        raise TenancyError("no organisation context on this session")
    return oid


def is_unscoped(session: Session) -> bool:
    return session.info.get(MODE_KEY) == UNSCOPED_MODE


@contextmanager
def unscoped(session: Session) -> Iterator[Session]:
    """Temporarily lift scoping, e.g. to resolve a credential to its organisation."""
    saved = (session.info.get(ORG_KEY), session.info.get(MODE_KEY))
    set_unscoped(session)
    try:
        yield session
    finally:
        session.info[ORG_KEY], session.info[MODE_KEY] = saved
        if saved[1] is None:
            clear(session)


# --------------------------------------------------------------------------- enforcement
@event.listens_for(Session, "do_orm_execute")
def _scope_statement(state: ORMExecuteState) -> None:
    if not (state.is_select or state.is_update or state.is_delete) or state.is_column_load:
        return
    info = state.session.info
    mode = info.get(MODE_KEY)
    if mode == UNSCOPED_MODE or state.execution_options.get("tenant_unscoped"):
        return
    if mode == ORG_MODE:
        oid = info[ORG_KEY]
        state.statement = state.statement.options(
            with_loader_criteria(TenantMixin, lambda cls: cls.organization_id == oid, include_aliases=True))
        return
    touched = {t.name for t in find_tables(state.statement, include_crud=True, include_joins=True)} & tenant_tables()
    if touched:
        raise TenancyError(f"query on {', '.join(sorted(touched))} without an organisation context "
                           "(use tenancy.set_org / db.get_session(org_id))")


@event.listens_for(Session, "before_flush")
def _stamp_and_check(session: Session, _ctx, _instances) -> None:
    oid = session.info.get(ORG_KEY)
    for obj in session.new:
        if not isinstance(obj, TenantMixin):
            continue
        if obj.organization_id is None:
            if oid is not None:
                obj.organization_id = oid
            elif not _nullable(obj):  # audit_log: platform-level events
                raise TenancyError(f"cannot insert {type(obj).__name__} without an organisation "
                                   "(no organisation context on the session)")
        elif oid is not None and obj.organization_id != oid:
            raise TenancyError(f"cannot insert {type(obj).__name__} of another organisation")
    for obj in list(session.dirty) + list(session.deleted):
        if not isinstance(obj, TenantMixin):
            continue
        hist = inspect(obj).attrs.organization_id.history
        if hist.deleted and hist.deleted[0] is not None and hist.deleted[0] != obj.organization_id:
            raise TenancyError(f"the organisation of a {type(obj).__name__} cannot change")
        if oid is not None and obj.organization_id is not None and obj.organization_id != oid:
            raise TenancyError(f"cannot modify {type(obj).__name__} of another organisation")


def _nullable(obj: object) -> bool:
    return bool(obj.__table__.c.organization_id.nullable)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- organisations
def get_org(session: Session, oid: str) -> Organization | None:
    from .models import Organization

    return session.get(Organization, oid)


def active_org_ids(session: Session) -> list[str]:
    """Organisations background jobs run for (suspended ones are skipped)."""
    from .models import Organization

    return list(session.scalars(select(Organization.id).where(Organization.status == "active")
                                .order_by(Organization.created_at, Organization.id)))


def for_each_active_org() -> Iterator[tuple[str, Session]]:
    """Yield (org id, session scoped to it) for every active organisation; each
    session is closed after its turn. Errors are left to the caller."""
    from . import db as dbmod

    with dbmod.get_session(unscoped=True) as s:
        ids = active_org_ids(s)
    for oid in ids:
        with dbmod.get_session(oid) as session:
            yield oid, session


def is_default(oid: str | None) -> bool:
    return oid == DEFAULT_ORG_ID


def ensure_default_org(session: Session) -> None:
    """Create the default organisation if missing (fresh databases; migrated ones
    get it from the 0013 migration / SQLite startup upgrade). Caller commits."""
    from . import config
    from .models import Organization

    with unscoped(session):
        if session.get(Organization, DEFAULT_ORG_ID) is None:
            s = config.settings
            session.add(Organization(id=DEFAULT_ORG_ID, name=s.default_org_name, slug=DEFAULT_ORG_SLUG,
                                     is_default=True, status="active"))
            session.flush()
            log.info("Created the default organisation %r", s.default_org_name)
