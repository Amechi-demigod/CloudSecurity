"""The Overview dashboard layout of an organisation: which widgets show, in what order and how wide.

Stored as {"order": [...], "hidden": [...], "widths": {id: 6|12}}:
  * `order`   widget ids in display order (hidden widgets keep their place, so turning one back on restores it);
  * `hidden`  ids switched off;
  * `widths`  12 = full width, 6 = half width.
A widget id the layout does not mention (added to the product later) keeps its default state; ids the
product no longer knows are dropped when reading. The frontend holds the matching defaults and titles.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# Fixed whitelist (keep in sync with frontend/src/components/overview/widgets.ts).
WIDGET_IDS: tuple[str, ...] = ("summary", "cloudSev", "vulnSev", "extSev", "attention", "trend", "compliance",
                               "kpis", "risk", "top", "age", "category")
WIDTHS = (6, 12)

WidgetId = Literal["summary", "cloudSev", "vulnSev", "extSev", "attention", "trend", "compliance",
                   "kpis", "risk", "top", "age", "category"]


class LayoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: Annotated[list[WidgetId], Field(max_length=len(WIDGET_IDS))] = []
    hidden: Annotated[list[WidgetId], Field(max_length=len(WIDGET_IDS))] = []
    widths: dict[WidgetId, Literal[6, 12]] = {}


def validate(body: LayoutIn) -> dict:
    """Canonical dict, or ValueError (answered 422): no widget twice in `order` or `hidden`."""
    if len(set(body.order)) != len(body.order):
        raise ValueError("order lists a widget twice")
    if len(set(body.hidden)) != len(body.hidden):
        raise ValueError("hidden lists a widget twice")
    return {"order": list(body.order), "hidden": list(body.hidden), "widths": dict(body.widths)}


def clean(stored: dict | None) -> dict | None:
    """A stored layout without ids or widths the product no longer knows."""
    if not isinstance(stored, dict):
        return None
    known = set(WIDGET_IDS)
    def ids(v: object) -> list[str]:
        return [i for i in v if i in known] if isinstance(v, list) else []

    order, hidden = ids(stored.get("order")), ids(stored.get("hidden"))
    w = stored.get("widths")
    widths = {k: v for k, v in w.items() if k in known and v in WIDTHS} if isinstance(w, dict) else {}
    return {"order": list(dict.fromkeys(order)), "hidden": list(dict.fromkeys(hidden)), "widths": widths}
