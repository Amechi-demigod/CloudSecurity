"""Built-in event sources and the helpers the platform calls to emit them.

Push sources (called from the code that creates the object, same transaction):
runtime alerts, posture findings, vulnerabilities, scans. Pull source: attack
paths, which are computed on demand, so the dispatcher polls them and notifies
about paths it has not seen before.
"""
from __future__ import annotations

import logging
from datetime import datetime
from urllib.parse import quote

from sqlalchemy.orm import Session

from . import settings as nsettings
from .events import STATUS_CHANGED, Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

RUNTIME_ALERT = "runtime_alert"
POSTURE_FINDING = "posture_finding"
VULNERABILITY = "vulnerability"
ATTACK_PATH = "attack_path"
SCAN = "scan"


def _q(v: str) -> str:
    return quote(str(v), safe="")


# --- runtime alerts ---------------------------------------------------------------

def alert_created(db: Session, alert) -> None:
    emit(db, Event(
        source=RUNTIME_ALERT, event_type="created", severity=alert.severity, title=alert.title,
        summary=alert.description, entity_id=alert.id, group_key=f"{RUNTIME_ALERT}:{alert.rule_id}:{alert.asset_id}",
        asset_id=alert.asset_id, rule_id=alert.rule_id, mitre_technique_id=alert.mitre_technique_id,
        link_path=f"/threats?alert={_q(alert.id)}",
        attributes={"mitre_tactic": alert.mitre_tactic, "mitre_technique_name": alert.mitre_technique_name,
                    "status": alert.status},
    ))


def alert_status_changed(db: Session, alert, old: str, new: str, actor: str | None = None) -> None:
    emit(db, Event(
        source=RUNTIME_ALERT, event_type=STATUS_CHANGED, severity=alert.severity,
        title=f"Alert {new}: {alert.title}", summary=f"Status changed from {old} to {new}"
        + (f" by {actor}" if actor else "") + ".",
        entity_id=alert.id, group_key=f"{RUNTIME_ALERT}:{alert.id}:status:{new}", asset_id=alert.asset_id,
        rule_id=alert.rule_id, mitre_technique_id=alert.mitre_technique_id,
        link_path=f"/threats?alert={_q(alert.id)}",
        attributes={"old_status": old, "new_status": new, "actor": actor,
                    "mitre_technique_name": alert.mitre_technique_name},
    ))


# --- posture findings ---------------------------------------------------------------

def finding_opened(db: Session, finding, regression: bool = False) -> None:
    emit(db, Event(
        source=POSTURE_FINDING, event_type="created", severity=finding.severity,
        title=("Regressed: " if regression else "") + finding.title, summary=finding.description,
        entity_id=finding.id, group_key=f"{POSTURE_FINDING}:{finding.rule_id}:{finding.asset_id}",
        asset_id=finding.asset_id, rule_id=finding.rule_id, link_path=f"/findings?finding={_q(finding.id)}",
        attributes={"regression": regression, "remediation": (finding.remediation or "")[:500],
                    "compliance": list(finding.compliance or [])[:10]},
    ))


def finding_status_changed(db: Session, finding, old: str, new: str, actor: str | None = None) -> None:
    emit(db, Event(
        source=POSTURE_FINDING, event_type=STATUS_CHANGED, severity=finding.severity,
        title=f"Finding {new}: {finding.title}",
        summary=f"Status changed from {old} to {new}" + (f" by {actor}" if actor else "") + ".",
        entity_id=finding.id, group_key=f"{POSTURE_FINDING}:{finding.id}:status:{new}", asset_id=finding.asset_id,
        rule_id=finding.rule_id, link_path=f"/findings?finding={_q(finding.id)}",
        attributes={"old_status": old, "new_status": new, "actor": actor},
    ))


# --- vulnerabilities --------------------------------------------------------------

def vulnerability_found(db: Session, v) -> None:
    title = f"{v.cve_id} in {v.package} {v.version}"
    emit(db, Event(
        source=VULNERABILITY, event_type="created", severity=v.severity, title=title,
        summary=(v.title or "") + (f" Fixed in {v.fixed_version}." if v.fixed_version else ""),
        entity_id=v.id, group_key=f"{VULNERABILITY}:{v.cve_id}:{v.asset_id}", asset_id=v.asset_id,
        rule_id=v.cve_id, link_path=f"/vulnerabilities?asset={_q(v.asset_id)}",
        attributes={"cvss": v.cvss, "exploit_available": bool(v.exploit_available), "in_use": bool(v.in_use),
                    "package": v.package, "fixed_version": v.fixed_version},
    ))


# --- scans ------------------------------------------------------------------------

def scan_finished(db: Session, run) -> None:
    failed = run.status == "failed"
    trigger = run.trigger or "manual"
    emit(db, Event(
        source=SCAN, event_type="failed" if failed else "completed", severity="high" if failed else "low",
        title=f"{'Scheduled ' if trigger == 'scheduled' else ''}{run.connector} scan "
              f"{'failed' if failed else 'completed'}", summary=run.message or "",
        entity_id=run.id, group_key=f"{SCAN}:{run.connector}:{run.status}", rule_id=run.connector,
        link_path=f"/connectors?scan={_q(run.id)}",
        attributes={"connector": run.connector, "trigger": trigger, "assets_found": run.assets_found,
                    "findings_open": run.findings_open, "errors": list(run.errors or [])[:5]},
    ))


# --- attack paths (pull) ----------------------------------------------------------

MAX_SEEN_PATHS = 5000


def poll_attack_paths(db: Session, state: dict, now: datetime) -> tuple[list[Event], dict]:
    """Notify about attack paths that were not present at the previous poll.

    The very first poll only records a baseline, so enabling notifications does
    not flood channels with every existing path.
    """
    from ..services import analytics

    # Only confirmed (exploitable) paths notify; exposure paths would be noise.
    paths = analytics.attack_paths(db, limit=100, include_unconfirmed=False)
    current = {p.id: p for p in paths}
    seen = set(state.get("seen") or [])
    events: list[Event] = []
    if state.get("initialized"):
        for pid, p in current.items():
            if pid in seen:
                continue
            entry = p.steps[0] if p.steps else None
            target = p.steps[-1] if p.steps else None
            events.append(Event(
                source=ATTACK_PATH, event_type="created", severity=p.severity, title=p.title,
                summary=" -> ".join(s.name for s in p.steps)[:1000], entity_id=pid,
                group_key=f"{ATTACK_PATH}:{pid}", asset_id=entry.asset_id if entry else None,
                link_path=f"/attack-paths?path={_q(pid)}",
                attributes={"score": p.score, "entry": entry.name if entry else None,
                            "target": target.name if target else None, "hops": len(p.steps)},
            ))
    # Paths that disappeared are forgotten, so they notify again if they come back.
    return events, {"initialized": True, "seen": sorted(current)[:MAX_SEEN_PATHS]}


register_source(EventSource(RUNTIME_ALERT, "Runtime alert (CDR)", ("created", STATUS_CHANGED),
                            "A detection rule fired on runtime events."))
register_source(EventSource(POSTURE_FINDING, "Posture finding (CSPM)", ("created", STATUS_CHANGED),
                            "A misconfiguration was found (or regressed) on a resource."))
register_source(EventSource(VULNERABILITY, "Vulnerability", ("created",),
                            "A vulnerable package was found in a workload."))
register_source(EventSource(ATTACK_PATH, "Attack path", ("created",),
                            "A new exploitable path from the internet to sensitive data.",
                            poll=poll_attack_paths,
                            poll_interval=lambda: nsettings.get().attack_path_poll_minutes * 60))
register_source(EventSource(SCAN, "Cloud scans", ("completed", "failed"),
                            "A cloud connector scan (manual or scheduled) finished or failed."))
