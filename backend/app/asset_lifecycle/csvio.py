"""CSV export and import for IT assets.

Export guards against CSV formula injection: any cell that starts with
`=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with a single quote
so spreadsheet applications show it as text instead of evaluating it. Import
strips that quote again, so an exported file can be re-imported unchanged.
"""
from __future__ import annotations

import csv
import io
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import ItAsset

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Column -> asset attribute (in export order). Read-only columns are exported but ignored on import.
COLUMNS = [
    "asset_tag", "serial_number", "asset_type", "manufacturer", "model", "status",
    "assignee_name", "assignee_email", "assignee_department", "location", "purchase_date", "supplier",
    "purchase_cost", "currency", "warranty_end", "refresh_date", "notes",
]
READ_ONLY_COLUMNS = ["retrieval_due", "disposal_method", "disposal_date", "disposal_vendor", "device_hostname",
                     "device_last_seen_at", "source", "id"]
CUSTOM_PREFIX = "custom."
IMPORT_STATUSES = ("in_stock", "assigned", "in_repair", "retrieved", "lost", "stolen")


def safe_cell(value: Any) -> str:
    """Stringify for CSV, neutralising spreadsheet formulas."""
    if value is None:
        return ""
    if isinstance(value, Decimal):
        text = f"{value:.2f}"
    elif isinstance(value, datetime):
        text = value.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(value, date):
        text = value.isoformat()
    else:
        text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def unescape_cell(text: str) -> str:
    """Undo `safe_cell`'s quote prefix (round trip)."""
    if len(text) >= 2 and text[0] == "'" and text[1] in "=+-@\t\r":
        return text[1:]
    return text


def export_csv(rows: list[tuple[ItAsset, Any]], custom_keys: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(COLUMNS + [CUSTOM_PREFIX + k for k in custom_keys] + READ_ONLY_COLUMNS)
    for asset, device in rows:
        values = [getattr(asset, c) for c in COLUMNS]
        values += [(asset.custom_fields or {}).get(k, "") for k in custom_keys]
        values += [asset.retrieval_due, asset.disposal_method, asset.disposal_date, asset.disposal_vendor,
                   device.hostname if device else "", device.last_seen_at if device else None, asset.source, asset.id]
        w.writerow([safe_cell(v) for v in values])
    return buf.getvalue()


class CsvError(ValueError):
    pass


def parse_csv(data: bytes, max_rows: int) -> tuple[list[str], list[dict[str, str]]]:
    """Decode (UTF-8, optional BOM) and parse; returns (headers, rows with unescaped values)."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CsvError("the file must be UTF-8 encoded CSV") from None
    if "\x00" in text:
        raise CsvError("the file contains NUL bytes; is it really a CSV file?")
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        headers = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        raise CsvError("the file is empty") from None
    except csv.Error as e:
        raise CsvError(f"invalid CSV: {e}") from None
    if "asset_tag" not in headers:
        raise CsvError("the header row must contain an asset_tag column")
    if len(set(headers)) != len(headers):
        raise CsvError("duplicate column names in the header row")
    known = set(COLUMNS) | set(READ_ONLY_COLUMNS)
    unknown = [h for h in headers if h and h not in known and not h.startswith(CUSTOM_PREFIX)]
    if unknown:
        raise CsvError(f"unknown column(s): {', '.join(unknown[:10])}")
    rows: list[dict[str, str]] = []
    try:
        for raw in reader:
            if not any(c.strip() for c in raw):
                continue
            if len(rows) >= max_rows:
                raise CsvError(f"too many rows (maximum {max_rows})")
            if len(raw) > len(headers):
                raise CsvError(f"row {len(rows) + 2} has more cells than the header row")
            rows.append({h: unescape_cell(v.strip()) for h, v in zip(headers, raw, strict=False) if h})
    except csv.Error as e:
        raise CsvError(f"invalid CSV: {e}") from None
    return headers, rows


def parse_date(v: str) -> date | None:
    if not v:
        return None
    try:
        return date.fromisoformat(v[:10])
    except ValueError:
        raise ValueError(f"invalid date {v!r} (use YYYY-MM-DD)") from None


def parse_cost(v: str) -> Decimal | None:
    if not v:
        return None
    try:
        d = Decimal(v.replace(",", "").strip())
    except InvalidOperation:
        raise ValueError(f"invalid purchase_cost {v!r}") from None
    if not d.is_finite() or d < 0 or d > Decimal("999999999999.99"):
        raise ValueError("purchase_cost must be between 0 and 999999999999.99")
    return d.quantize(Decimal("0.01"))
