"""Structured, per-rule remediation guidance for posture findings.

The rule decorators in `engine/posture*.py` carry the short description / remediation / compliance
text; everything an engineer needs to *act* on a finding (business impact, weakness class,
ATT&CK mapping, verification, fix as console / CLI / Terraform, prevention, references) lives in
this package, keyed by rule id: `azure.py`, `aws.py`, `gcp.py`. `tests/test_guidance.py` fails if a
registered rule has no complete entry or a reference is not https.

Commands use `<name>`, `<rg>`, `<region>`, `<subscription>` placeholders; `render()` substitutes
the values of the affected asset where known. Everything here is read-only to verify and is guidance
only: the platform never executes any of it.
"""
from __future__ import annotations

import re
from typing import Any

from . import aws, azure, gcp

GUIDANCE: dict[str, dict[str, Any]] = {**azure.GUIDANCE, **aws.GUIDANCE, **gcp.GUIDANCE}

REQUIRED_KEYS = ("impact", "cwe", "attack", "risk_score", "verify_steps", "verify_cli", "fix_console", "fix_cli",
                 "fix_terraform", "prevent", "references")
#: CVSS-style qualitative bands the rule's severity must agree with
SCORE_BANDS = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (0.1, 3.9), "info": (0.0, 0.0)}


_SAFE = re.compile(r"[A-Za-z0-9._-]{1,128}")


def _lookup(rule_id: str) -> dict[str, Any] | None:
    """Posture guidance, else the network discovery rules' (NET-*, kept apart: they are not posture rules)."""
    entry = GUIDANCE.get(rule_id)
    if entry is None and rule_id.startswith("NET-"):
        from ...network import rules as net_rules

        entry = net_rules.GUIDANCE.get(rule_id)
    return entry


def get(rule_id: str) -> dict[str, Any] | None:
    return _lookup(rule_id)


def _sub(value: Any, subs: dict[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in subs.items():
            value = value.replace(k, v)
        return value
    if isinstance(value, list):
        return [_sub(x, subs) for x in value]
    if isinstance(value, dict):
        return {k: (v if k == "url" else _sub(v, subs)) for k, v in value.items()}
    return value


def render(rule_id: str, *, name: str | None, resource_group: str | None, region: str | None,
           account: str | None) -> dict[str, Any] | None:
    """The guidance for `rule_id` with the asset's own name / group / region / account substituted for the
    placeholders (a value we do not know keeps its placeholder)."""
    entry = _lookup(rule_id)
    if entry is None:
        return None
    subs = {"<name>": name, "<rg>": resource_group, "<region>": region, "<subscription>": account,
            "<account>": account, "<project>": account}
    # only plain identifiers are substituted: a name with shell metacharacters must never end up in a command
    return _sub(entry, {k: v for k, v in subs.items() if v and _SAFE.fullmatch(v)})
