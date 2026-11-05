"""Control status and framework score (pure, unit-tested; docs/COMPLIANCE.md#scoring).

Per control, from its mapping coverage and the status of its checks:

* ``manual``  - no automated check is mapped: not assessed automatically.
* ``fail``    - at least one mapped check fails in scope.
* ``pass``    - the mapping fully covers the control and every mapped check passes.
* ``partial`` - nothing fails and at least one check passes, but the mapping
  covers only part of the control, or some mapped checks have no data: the
  automated evidence is fine and the rest needs manual evidence.
* ``no_data`` - checks are mapped but none has anything to evaluate in scope
  (for example AWS rules in an organisation without an AWS account).

Score = controls without failing evidence (pass + partial) / controls assessed
automatically (pass + partial + fail). Coverage = controls assessed
automatically / all controls. Neither is a certification or audit result.
"""
from __future__ import annotations

from collections.abc import Iterable

STATUSES = ("pass", "fail", "partial", "no_data", "manual")
EVALUATED = ("pass", "fail")


def control_status(coverage: str | None, check_statuses: Iterable[str]) -> str:
    statuses = list(check_statuses)
    if not statuses:
        return "manual"
    if "fail" in statuses:
        return "fail"
    if "pass" not in statuses:
        return "no_data"
    if coverage == "full" and all(s == "pass" for s in statuses):
        return "pass"
    return "partial"


def summarize(control_statuses: Iterable[str]) -> dict[str, int | float | None]:
    counts = {s: 0 for s in STATUSES}
    total = 0
    for s in control_statuses:
        counts[s] += 1
        total += 1
    assessed = counts["pass"] + counts["partial"] + counts["fail"]
    ok = counts["pass"] + counts["partial"]
    return {**counts, "total": total, "assessed": assessed,
            "score": round(100.0 * ok / assessed, 1) if assessed else None,
            "coverage": round(100.0 * assessed / total, 1) if total else 0.0,
            "mapped": total - counts["manual"]}
