"""Whitelisted server-side sorting for list endpoints (`?sort=<key>&dir=asc|desc`).

A key is a name from the endpoint's own table of getters: user input only ever selects one of those entries, it is
never put into SQL or evaluated. Text sorts case-insensitively, numbers numerically, missing values come last in
both directions; ties keep the endpoint's default order (the sort is stable)."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Literal, TypeVar

from fastapi import HTTPException

T = TypeVar("T")
SortDir = Literal["asc", "desc"]


def _norm(v: Any) -> Any:
    if isinstance(v, str):
        return v.casefold()
    if isinstance(v, bool):
        return int(v)
    return v


def sort_rows(rows: Iterable[T], getters: dict[str, Callable[[T], Any]], sort: str | None, direction: str = "asc") -> list[T]:
    """`rows` ordered by getters[sort] (422 for a key that is not in the table). No `sort`: the rows unchanged."""
    out = list(rows)
    if not sort:
        return out
    get = getters.get(sort)
    if get is None:
        raise HTTPException(422, f"sort must be one of {', '.join(sorted(getters))}")
    if direction not in ("asc", "desc"):
        raise HTTPException(422, "dir must be asc or desc")
    present = [(r, _norm(get(r))) for r in out]
    have = [p for p in present if p[1] is not None and p[1] != ""]
    missing = [p[0] for p in present if p[1] is None or p[1] == ""]
    have.sort(key=lambda p: p[1], reverse=direction == "desc")
    return [p[0] for p in have] + missing
