"""CSV / JSON exports of list pages (Computers & servers, Cloud resources).

Rows are plain dicts built by the caller. They are encoded in chunks and streamed, so the response is never
one big string. CSV is UTF-8 with a BOM (Excel) and neutralises spreadsheet formulas in every text cell.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

MAX_EXPORT_ROWS = 50_000
_CHUNK_ROWS = 500
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def iso(value: datetime | None) -> str | None:
    """Stored timestamps are naive UTC: ISO 8601 with an explicit +00:00 offset."""
    return value.replace(tzinfo=UTC).isoformat() if value is not None else None


def check_row_limit(n: int) -> None:
    if n > MAX_EXPORT_ROWS:
        raise HTTPException(413, f"Too many rows to export at once (more than {MAX_EXPORT_ROWS:,}). "
                                 "Narrow the search or filters and try again.")


def safe_cell(value: Any) -> Any:
    """CSV/formula injection: a text cell starting with = + - @ tab or CR gets a leading apostrophe."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | tuple):
        value = "; ".join(str(v) for v in value)
    return safe_cell(value)


def _csv_stream(columns: Sequence[str], rows: Sequence[dict[str, Any]]) -> Iterator[bytes]:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(columns)
    yield b"\xef\xbb\xbf" + buf.getvalue().encode()
    for start in range(0, len(rows), _CHUNK_ROWS):
        buf.seek(0)
        buf.truncate()
        for r in rows[start:start + _CHUNK_ROWS]:
            w.writerow([_csv_value(r.get(c)) for c in columns])
        yield buf.getvalue().encode()


def _json_stream(rows: Sequence[dict[str, Any]]) -> Iterator[bytes]:
    yield (f'{{"exported_at": {json.dumps(iso(datetime.now(UTC).replace(tzinfo=None)))}, '
           f'"count": {len(rows)}, "items": [').encode()
    for i, r in enumerate(rows):
        yield (("," if i else "") + json.dumps(r, ensure_ascii=False)).encode()
    yield b"]}"


def export_response(fmt: str, rows: list[dict[str, Any]], columns: Sequence[str], basename: str) -> StreamingResponse:
    name = f"{basename}-{datetime.now(UTC):%Y-%m-%d}.{fmt}"
    if fmt == "csv":
        body, media = _csv_stream(columns, rows), "text/csv; charset=utf-8"
    else:
        body, media = _json_stream(rows), "application/json"
    return StreamingResponse(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
        "Access-Control-Expose-Headers": "Content-Disposition"})
