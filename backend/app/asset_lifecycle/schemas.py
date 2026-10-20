"""Request / response schemas for /api/it-assets (Pydantic v2)."""
from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .models import ASSET_STATUSES, ASSET_TYPES, DISPOSAL_METHODS

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/#-]{0,63}$")
CUSTOM_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")

Status = Literal["in_stock", "assigned", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen", "disposed"]
AssetType = Literal["laptop", "desktop", "computer", "monitor", "phone", "tablet", "dock", "peripheral", "headset",
                    "printer", "network", "server", "other"]
DisposalMethod = Literal["recycled", "destroyed", "resold", "donated", "returned_to_vendor", "other"]
assert set(Status.__args__) == set(ASSET_STATUSES)  # type: ignore[attr-defined]
assert set(AssetType.__args__) == set(ASSET_TYPES)  # type: ignore[attr-defined]
assert set(DisposalMethod.__args__) == set(DISPOSAL_METHODS)  # type: ignore[attr-defined]

Str128 = Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)]
Notes = Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000)]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]


def clean_text(v: Any) -> Any:
    """Reject control characters (CSV / log injection, broken exports)."""
    if isinstance(v, str):
        if _CONTROL.search(v):
            raise ValueError("must not contain control characters")
        return v.strip()
    return v


def clean_email(v: str) -> str:
    v = (v or "").strip().lower()
    if v and not EMAIL_RE.match(v):
        raise ValueError("is not a valid email address")
    return v


def clean_tag(v: str) -> str:
    v = (v or "").strip()
    if not TAG_RE.match(v):
        raise ValueError("asset tag must be 1-64 characters: letters, digits and . _ / # - "
                         "(starting with a letter or digit)")
    return v


def clean_currency(v: str | None) -> str | None:
    if v is None or v == "":
        return None
    v = v.strip().upper()
    if not CURRENCY_RE.match(v):
        raise ValueError("currency must be a 3-letter ISO 4217 code, e.g. NGN, USD")
    return v


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def _no_control_chars(cls, v: Any) -> Any:
        return clean_text(v)


class AssetFields(_Base):
    """Editable fields (all optional: PATCH semantics; unset = unchanged)."""

    asset_tag: str | None = None
    serial_number: Str128 | None = None
    asset_type: AssetType | None = None
    manufacturer: Str128 | None = None
    model: Str128 | None = None
    location: Str128 | None = None
    purchase_date: date | None = None
    supplier: Str128 | None = None
    purchase_cost: Decimal | None = Field(None, ge=0, le=Decimal("999999999999.99"), decimal_places=2)
    currency: str | None = None
    warranty_end: date | None = None
    refresh_date: date | None = None
    notes: Notes | None = None
    custom_fields: dict[str, Annotated[str, StringConstraints(max_length=500)]] | None = None
    assignee_department: Str128 | None = None

    @field_validator("asset_tag")
    @classmethod
    def _tag(cls, v: str | None) -> str | None:
        return None if v is None else clean_tag(v)

    @field_validator("currency")
    @classmethod
    def _cur(cls, v: str | None) -> str | None:
        return clean_currency(v)

    @field_validator("custom_fields")
    @classmethod
    def _custom(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return None
        if len(v) > 50:
            raise ValueError("at most 50 custom fields")
        out = {}
        for k, val in v.items():
            if not CUSTOM_KEY_RE.match(k):
                raise ValueError(f"invalid custom field key {k!r}")
            val = clean_text(val)
            if val:
                out[k] = val
        return out


class AssetCreate(AssetFields):
    asset_tag: str
    asset_type: AssetType = "other"
    status: Literal["in_stock", "in_repair", "assigned"] = "in_stock"
    assignee_name: Str128 = ""
    assignee_email: str = ""
    device_id: str | None = Field(None, pattern=r"^[0-9a-f]{32}$")

    @field_validator("assignee_email")
    @classmethod
    def _email(cls, v: str) -> str:
        return clean_email(v)


class AssetUpdate(AssetFields):
    # Link / unlink an agent device ("" unlinks).
    device_id: str | None = Field(None, pattern=r"^([0-9a-f]{32})?$")
    note: Reason = ""


class AssignIn(_Base):
    assignee_name: Str128 = ""
    assignee_email: str
    assignee_department: Str128 = ""
    notes: Reason = ""

    @field_validator("assignee_email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = clean_email(v)
        if not v:
            raise ValueError("assignee email is required")
        return v


class ReturnIn(_Base):
    notes: Reason = ""
    # Where the returned asset goes (default: in_stock, or retrieved for a pending retrieval).
    status: Literal["in_stock", "retrieved", "in_repair"] | None = None
    location: Str128 | None = None


class StatusIn(_Base):
    status: Literal["in_stock", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen"]
    notes: Reason = ""
    retrieval_due: date | None = None


class DisposeIn(_Base):
    method: DisposalMethod
    disposal_date: date
    vendor: Str128 = ""
    notes: Notes = ""


class OffboardingIn(_Base):
    person_email: str
    person_name: Str128 = ""
    department: Str128 = ""
    leave_date: date
    retrieval_due: date | None = None
    notes: Notes = ""

    @field_validator("person_email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = clean_email(v)
        if not v:
            raise ValueError("email is required")
        return v


class CancelIn(_Base):
    notes: Reason = ""


class CustomFieldDef(_Base):
    key: str
    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]

    @field_validator("key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not CUSTOM_KEY_RE.match(v):
            raise ValueError("key must be lower-case letters, digits and _ (max 32, starting with a letter)")
        return v


class SettingsIn(_Base):
    default_currency: str | None = None
    locations: list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]] | None = \
        Field(None, max_length=500)
    custom_fields: list[CustomFieldDef] | None = Field(None, max_length=50)
    idle_days: int | None = Field(None, ge=1, le=3650)
    warranty_warning_days: int | None = Field(None, ge=1, le=3650)
    retrieval_due_days: int | None = Field(None, ge=0, le=365)

    @field_validator("default_currency")
    @classmethod
    def _cur(cls, v: str | None) -> str | None:
        return clean_currency(v)

    @field_validator("locations")
    @classmethod
    def _locs(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        for item in v:
            clean_text(item)
        return sorted(set(v), key=str.lower)

    @field_validator("custom_fields")
    @classmethod
    def _defs(cls, v: list[CustomFieldDef] | None) -> list[CustomFieldDef] | None:
        if v is not None and len({d.key for d in v}) != len(v):
            raise ValueError("custom field keys must be unique")
        return v


# --- responses ---------------------------------------------------------------------

class AssetOut(BaseModel):
    id: str
    asset_tag: str
    serial_number: str
    asset_type: str
    manufacturer: str
    model: str
    status: str
    source: str
    device_id: str | None
    device_hostname: str | None = None
    device_last_seen_at: datetime | None = None
    idle: bool = False
    assignee_name: str
    assignee_email: str
    assignee_department: str
    assigned_at: datetime | None
    location: str
    purchase_date: date | None
    supplier: str
    purchase_cost: float | None
    currency: str
    warranty_end: date | None
    warranty_expiring: bool = False
    refresh_date: date | None
    notes: str
    custom_fields: dict[str, str]
    retrieval_due: date | None
    retrieval_overdue: bool = False
    offboarding_id: str | None
    disposal_method: str | None
    disposal_date: date | None
    disposal_vendor: str | None
    disposal_notes: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor_email: str | None
    event_type: str
    from_status: str | None
    to_status: str | None
    from_assignee: str | None
    to_assignee: str | None
    notes: str
    detail: dict[str, Any]


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    uploaded_by: str | None
    uploaded_at: datetime


class OffboardingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    person_email: str
    person_name: str
    department: str
    leave_date: date
    retrieval_due: date
    status: str
    notes: str
    created_by: str | None
    created_at: datetime
    closed_at: datetime | None
    assets_total: int = 0
    assets_outstanding: int = 0
    overdue: bool = False
