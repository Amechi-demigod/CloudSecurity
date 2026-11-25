"""Assembles the executive report of the session's organisation (docs/EXECUTIVE_REPORT.md).

Plain sentences only: every number is explained. Sections exist only for the modules the organisation has
(app/modules.py). Trends reuse the daily dashboard snapshots (services/dashboard_snapshots.py): the comparison
point is the snapshot taken one period earlier (a day, a week, 30 or 90 days), unknown when none exists.
Everything is read through the tenant-scoped session, so one organisation's report never contains another's data.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, modules, tenancy
from ..compliance import checks as compliance_checks
from ..compliance import service as compliance_service
from ..models import (
    ExternalFinding,
    ExternalTarget,
    Finding,
    Organization,
    ReputationDomain,
    ReputationFinding,
    Vulnerability,
    utcnow,
)
from ..services import dashboards, vuln_sla
from .models import FREQUENCIES

# period key -> (days covered, what the comparison is called in a sentence)
PERIODS: dict[str, tuple[int, str]] = {"daily": (1, "yesterday"), "weekly": (7, "last week"),
                                       "monthly": (30, "last month"), "quarterly": (90, "last quarter")}
PERIOD_NAME = {"daily": "Daily", "weekly": "Weekly", "monthly": "Monthly", "quarterly": "Quarterly"}
assert tuple(PERIODS) == FREQUENCIES
SEV_WEIGHT = {"critical": 100, "high": 80, "medium": 50, "low": 20}
RISK_WORD = (("very high", 75), ("high", 50), ("moderate", 25), ("low", 0))
GRADE_WORD = {"A": "excellent", "B": "good", "C": "fair", "D": "weak", "F": "poor"}
WHO = {"cloud": "Your cloud / infrastructure team", "endpoints": "Your IT support team",
       "vulnerabilities": "Your IT operations team", "external": "Your network and web team",
       "reputation": "Whoever manages your email and domain names", "paths": "Your cloud / infrastructure team"}
DISCLAIMER = compliance_service.DISCLAIMER


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _clip(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "..."


def _sentence(s: str) -> str:
    s = _clip(s, 400)
    return s if not s or s[-1] in ".!?" else s + "."


def _make_window(days: int, now: datetime) -> dashboards.Window:
    start = now - timedelta(days=days)
    return dashboards.Window("custom", days, now, now.date(), start, start - timedelta(days=days), None)


def _risk_word(score: float) -> str:
    return next(word for word, floor in RISK_WORD if score >= floor)


def _change_phrase(delta: float | int | None, better_is_lower: bool, compare: str) -> str | None:
    if delta is None:
        return None
    d = abs(round(delta))
    if d == 0:
        return f"unchanged from {compare}"
    good = (delta < 0) == better_is_lower
    return f"{_plural(d, 'point')} {'better' if good else 'worse'} than {compare}"


# ----------------------------------------------------------------------------- sections
def _headline(score: float | None, delta: float | None, compare: str, serious: int, has_cloud: bool) -> dict[str, Any]:
    if has_cloud and score is not None:
        score_i = round(score)
        text = f"Your overall risk is {score_i} out of 100 ({_risk_word(score)}; lower is better)"
        phrase = _change_phrase(delta, True, compare)
        text += f", {phrase}." if phrase else f". A comparison with {compare} is not available yet."
        direction = "unknown" if delta is None else ("same" if round(delta) == 0 else ("better" if delta < 0 else "worse"))
        return {"text": text, "score": score_i, "delta": None if delta is None else round(delta, 1),
                "direction": direction, "level": _risk_word(score),
                "explain": "The risk score combines open security issues, known software flaws, alerts and the "
                           "routes an attacker could use. 0 is the best result and 100 the worst."}
    text = (f"{_plural(serious, 'serious problem')} need attention across your environment."
            if serious else "No serious problems are open across your environment.")
    return {"text": text, "score": None, "delta": None, "direction": "unknown", "level": None,
            "explain": "A serious problem is anything rated critical or high that is still open."}


def _candidates(db: Session, on: list[str], metrics: dict[str, Any], ep: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if modules.VULNERABILITIES in on:
        kev = int(metrics.get("vulns_kev") or 0)
        if kev:
            out.append({"area": "vulnerabilities", "severity": "critical", "rank": 150,
                        "title": f"{_plural(kev, 'software flaw')} that attackers are already using",
                        "why": "Criminals are actively exploiting these flaws in the real world, so unpatched systems "
                               "are the most likely way in.",
                        "who": WHO["vulnerabilities"] + " should install the vendor updates, starting with systems "
                                                         "reachable from the internet."})
        crit = int(metrics.get("vulns_critical") or 0)
        if crit and crit > kev:
            out.append({"area": "vulnerabilities", "severity": "critical", "rank": 120,
                        "title": f"{_plural(crit, 'critical software flaw')} still waiting to be fixed",
                        "why": "Critical flaws let an attacker take control of a system, often without a password.",
                        "who": WHO["vulnerabilities"] + " should schedule the updates."})
    if modules.CLOUD in on:
        paths = int(metrics.get("attack_paths") or 0)
        if paths:
            out.append({"area": "paths", "severity": "critical", "rank": 140,
                        "title": f"{_plural(paths, 'route')} an attacker could follow to reach your important systems",
                        "why": "Several smaller weaknesses line up so that a break-in from the internet could reach "
                               "sensitive data or powerful accounts.",
                        "who": WHO["paths"] + " should close the weaknesses along each route."})
        for r in dashboards._top_issues(db, dashboards.window(), 5):
            if r["severity"] not in ("critical", "high"):
                continue
            f = db.scalar(select(Finding).where(Finding.rule_id == r["rule_id"], Finding.status == "open").limit(1))
            out.append({"area": "cloud", "severity": r["severity"],
                        "rank": SEV_WEIGHT[r["severity"]] + min(r["assets"], 10),
                        "title": _clip(r["title"], 110),
                        "why": _sentence(f"{_plural(r['assets'], 'cloud resource')} affected. "
                                         + (f.description if f is not None else "")),
                        "who": WHO["cloud"] + " should fix it" + (f": {_clip(f.remediation, 150)}" if f is not None
                                                                   and f.remediation else ".")})
    if modules.ENDPOINTS in on:
        for i in (ep or {}).get("issues", []):
            if i["severity"] in ("critical", "high"):
                out.append({"area": "endpoints", "severity": i["severity"],
                            "rank": SEV_WEIGHT[i["severity"]] + min(i["devices"], 10) - 5,
                            "title": f"{_plural(i['devices'], 'computer')}: {i['title'].lower()}",
                            "why": "Laptops and servers without basic protection are the easiest targets for "
                                   "malware and theft of data.",
                            "who": WHO["endpoints"] + " should switch the protection back on."})
    if modules.EXTERNAL in on:
        # min(id), not min(detail): Postgres has no min() for JSON, so the detail of one row is loaded separately.
        rows = db.execute(select(ExternalFinding.title, ExternalFinding.severity, func.count(),
                                 func.min(ExternalFinding.id))
                          .where(ExternalFinding.status == "open", ExternalFinding.severity.in_(("critical", "high")))
                          .group_by(ExternalFinding.title, ExternalFinding.severity)).all()
        for title, sev, n, first_id in rows:
            detail = db.scalar(select(ExternalFinding.detail).where(ExternalFinding.id == first_id))
            impact = (detail or {}).get("impact") if isinstance(detail, dict) else None
            out.append({"area": "external", "severity": sev, "rank": SEV_WEIGHT[sev] + 5 + min(n, 5),
                        "title": _clip(f"{title} ({_plural(n, 'place')} on the internet)", 110),
                        "why": _sentence(impact or "This is visible to anyone on the internet, including attackers."),
                        "who": WHO["external"] + " should fix it."})
        rrows = db.execute(select(ReputationFinding.title, ReputationFinding.severity, func.count(),
                                  func.min(ReputationFinding.id))
                           .where(ReputationFinding.status == "open",
                                  ReputationFinding.severity.in_(("critical", "high")))
                           .group_by(ReputationFinding.title, ReputationFinding.severity)).all()
        for title, sev, n, first_id in rrows:
            detail = db.scalar(select(ReputationFinding.detail).where(ReputationFinding.id == first_id))
            desc = (detail or {}).get("description") if isinstance(detail, dict) else None
            out.append({"area": "reputation", "severity": sev, "rank": SEV_WEIGHT[sev] + min(n, 5) - 10,
                        "title": _clip(title if n == 1 else f"{title} ({n} domains or addresses)", 110),
                        "why": _sentence(desc or "This makes it easier to impersonate your company or send fake email "
                                                 "in your name."),
                        "who": WHO["reputation"] + " should correct it."})
    return out


def _top_risks(db: Session, on: list[str], metrics: dict[str, Any], ep: dict[str, Any] | None) -> list[dict[str, Any]]:
    per_area: Counter = Counter()
    out = []
    for c in sorted(_candidates(db, on, metrics, ep), key=lambda c: (-c["rank"], c["title"])):
        if per_area[c["area"]] >= 2:  # keep the list varied: at most two per area
            continue
        per_area[c["area"]] += 1
        out.append({k: c[k] for k in ("title", "why", "who", "severity")})
        if len(out) == 5:
            break
    return out


def _lines(items: list[tuple[str, float | int, float | int | None, bool]]) -> list[dict[str, Any]]:
    """(label, value, previous, lower_is_better) to {label, value, change, direction}."""
    out = []
    for label, value, change, lower_better in items:
        direction = "same" if not change else ("better" if (change < 0) == lower_better else "worse")
        out.append({"label": label, "value": value, "change": change, "direction": direction})
    return out


def _changes(db: Session, on: list[str], w: dashboards.Window, metrics: dict[str, Any],
             base: dict[str, Any] | None, compare: str) -> dict[str, Any]:
    improved: list[str] = []
    worse: list[str] = []
    notes: list[str] = []
    since = f"since {compare}" if compare != "yesterday" else "since yesterday"
    if modules.CLOUD in on:
        fixed = db.scalar(select(func.count()).select_from(Finding).where(
            Finding.status == "resolved", Finding.close_reason.is_(None), Finding.resolved_at >= w.start,
            Finding.resolved_at < w.now)) or 0
        new = db.scalar(select(func.count()).select_from(Finding).where(Finding.first_seen >= w.start,
                                                                       Finding.first_seen < w.now)) or 0
        if fixed:
            improved.append(f"{_plural(fixed, 'cloud security issue')} {'was' if fixed == 1 else 'were'} fixed.")
        if new:
            worse.append(f"{_plural(new, 'new cloud security issue')} appeared.")
        crit_d = dashboards.delta(metrics["open_critical"], base, "open_critical")
        notes.append(f"{_plural(int(metrics['open_critical']), 'critical cloud issue')} "
                     f"{'is' if metrics['open_critical'] == 1 else 'are'} open now"
                     + (f" ({_signed(crit_d)} {since})." if crit_d else "."))
        if crit_d:
            (improved if crit_d < 0 else worse).append(
                f"Open critical cloud issues {'fell' if crit_d < 0 else 'rose'} by {abs(int(crit_d))}.")
    if modules.VULNERABILITIES in on:
        fixed = db.scalar(select(func.count()).select_from(Vulnerability).where(
            Vulnerability.status == "resolved", Vulnerability.resolved_at >= w.start,
            Vulnerability.resolved_at < w.now)) or 0
        new = db.scalar(select(func.count()).select_from(Vulnerability).where(
            Vulnerability.first_seen >= w.start, Vulnerability.first_seen < w.now)) or 0
        if fixed:
            improved.append(f"{_plural(fixed, 'software flaw')} {'was' if fixed == 1 else 'were'} fixed.")
        if new:
            worse.append(f"{_plural(new, 'new software flaw')} {'was' if new == 1 else 'were'} found.")
        vc = int(metrics.get("vulns_critical") or 0)
        d = dashboards.delta(vc, base, "vulns_critical")
        notes.append(f"{_plural(vc, 'critical software flaw')} {'is' if vc == 1 else 'are'} open now"
                     + (f" ({_signed(d)} {since})." if d else "."))
        if d:
            (improved if d < 0 else worse).append(
                f"Open critical software flaws {'fell' if d < 0 else 'rose'} by {abs(int(d))}.")
    if modules.ENDPOINTS in on and base is not None:
        d = dashboards.delta(metrics.get("devices_failing"), base, "devices_failing")
        if d:
            (improved if d < 0 else worse).append(
                f"Computers with a protection problem {'fell' if d < 0 else 'rose'} by {abs(int(d))}.")
    if not improved and not worse:
        improved_text = ("Nothing changed in a way that needs your attention." if base is not None or notes
                         else "There is not enough history yet to show what changed.")
        notes.insert(0, improved_text)
    return {"compared_with": compare, "comparison_available": base is not None, "improved": improved,
            "worse": worse, "notes": notes,
            "explain": "Compared with the same measures " + compare + ". A fixed item was closed during the period; "
                       "a new one was first found during it."}


def _signed(d: float | int) -> str:
    return f"{'+' if d > 0 else '-'}{abs(int(d))}"


def _coverage(db: Session, on: list[str], ep: dict[str, Any] | None) -> dict[str, Any]:
    lines: list[str] = []
    data: dict[str, Any] = {}
    if modules.CLOUD in on:
        accts = dashboards.accounts(db)
        data["cloud_accounts"] = len(accts)
        lines.append(f"{_plural(len(accts), 'cloud account')} {'is' if len(accts) == 1 else 'are'} connected and "
                     "checked." if accts else "No cloud accounts are connected yet, so cloud systems are not checked.")
    if modules.ENDPOINTS in on and ep is not None:
        conn = ep["connectivity"]
        reporting = conn["active"]
        missing = conn["stale"] + conn["inactive"] + conn["never"]
        data["devices_reporting"], data["devices_not_seen"] = reporting, missing
        if ep["managed"]:
            lines.append(f"{reporting} of {ep['managed']} managed computers and servers reported in recently"
                         + (f"; {_plural(missing, 'device')} {'has' if missing == 1 else 'have'} not been seen for over "
                            "a day, so we cannot vouch for it." if missing else "."))
        else:
            lines.append("No computers or servers are enrolled yet.")
    if modules.EXTERNAL in on:
        total = db.scalar(select(func.count()).select_from(ExternalTarget).where(ExternalTarget.kind == "domain")) or 0
        verified = db.scalar(select(func.count()).select_from(ExternalTarget).where(
            ExternalTarget.kind == "domain", ExternalTarget.verified_at.is_not(None))) or 0
        data["domains_monitored"] = verified
        lines.append(f"{_plural(verified, 'internet domain')} {'is' if verified == 1 else 'are'} monitored"
                     + (f" ({total - verified} more waiting to be verified as yours)." if total > verified else ".")
                     if total else "No internet domains are monitored yet.")
    return {"lines": lines, "data": data,
            "explain": "Coverage shows how much of your environment the checks can actually see. "
                       "Anything not covered is a blind spot."}


def _compliance(db: Session, now: datetime) -> dict[str, Any]:
    rows = compliance_service.overview(db, compliance_checks.Scope(), now)
    fws = []
    for r in rows:
        s = r["summary"]
        fws.append({"name": r["name"], "score": s.get("score"), "coverage": s.get("coverage"),
                    "failing": s.get("fail", 0)})
    return {"frameworks": fws, "disclaimer": DISCLAIMER,
            "explain": "The score is the share of automatically checked requirements that pass. Coverage is the "
                       "share of the standard's requirements the platform can check automatically; the rest need "
                       "manual evidence."}


def _exposure(db: Session) -> dict[str, Any]:
    sev = Counter(dict(db.execute(select(ExternalFinding.severity, func.count())
                                  .where(ExternalFinding.status == "open").group_by(ExternalFinding.severity)).all()))
    domains = [{"domain": d.domain, "grade": d.grade, "score": d.score,
                "meaning": GRADE_WORD.get(d.grade or "", "not yet graded"),
                "open_issues": sum((d.counts or {}).values()) if isinstance(d.counts, dict) else 0}
               for d in db.scalars(select(ReputationDomain).order_by(ReputationDomain.domain))]
    by = {s: int(sev.get(s, 0)) for s in dashboards.SEVERITIES}
    total = sum(by.values())
    lines = [(f"{_plural(total, 'weakness')} visible from the internet {'is' if total == 1 else 'are'} open: "
              + ", ".join(f"{by[s]} {s}" for s in dashboards.SEVERITIES if by[s]) + ".") if total
             else "No weaknesses visible from the internet are open."]
    return {"findings": by, "total": total, "domains": domains, "lines": lines,
            "explain": "These are things anyone on the internet can see. The grade per domain (A best, F worst) "
                       "rates how hard it is to fake email from your domain or mimic it, and how healthy its "
                       "security certificates are."}


def _overdue(db: Session, now: datetime) -> dict[str, Any]:
    rows = db.execute(select(Vulnerability.severity, Vulnerability.kev, Vulnerability.first_seen)
                      .where(Vulnerability.status == "open")).all()
    by: Counter = Counter()
    oldest = 0
    for sev, kev, first_seen in rows:
        d = vuln_sla.fix_due(first_seen, sev, kev=bool(kev), now=now)
        if d["overdue_days"]:
            by[sev] += 1
            oldest = max(oldest, d["overdue_days"])
    total = sum(by.values())
    parts = {s: by.get(s, 0) for s in dashboards.SEVERITIES}
    if total:
        lines = [f"{total} of {len(rows)} open software flaws are past their fix-by date"
                 + " (" + ", ".join(f"{parts[s]} {s}" for s in dashboards.SEVERITIES if parts[s]) + ")."
                 f" The longest overdue has waited {_plural(oldest, 'day')} too long."]
    else:
        lines = ["No open software flaw is past its fix-by date." if rows else "No software flaws are open."]
    return {"total": total, "open": len(rows), "by_severity": parts, "oldest_days": oldest, "lines": lines,
            "explain": "Every flaw has a fix-by date: 7 days for critical, 14 for high, 30 for medium and 90 for low "
                       "after it was found, and 14 days if criminals are already using it."}


# ----------------------------------------------------------------------------- next steps
def _next_steps(r: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    ov = r.get("overdue")
    if ov and ov["total"]:
        steps.append(f"Ask your IT team to clear the {_plural(ov['total'], 'overdue software fix', 'overdue software fixes')}"
                     " first, starting with the critical ones.")
    top = r["top_risks"][0] if r["top_risks"] else None
    if top and top["severity"] == "critical":
        steps.append(f"Agree an owner and a date for the biggest risk: {top['title'][:1].lower() + top['title'][1:]}.")
    ex = r.get("exposure")
    if ex:
        bad = [d for d in ex["domains"] if d["grade"] in ("D", "F")]
        if ex["findings"]["critical"] or ex["findings"]["high"]:
            steps.append("Have your network or web team fix the serious weaknesses that are visible from the internet.")
        if bad:
            steps.append(f"Improve the email and certificate protection of {bad[0]['domain']}"
                         + (f" and {len(bad) - 1} more" if len(bad) > 1 else "") + ", which grade poorly.")
    cov = r.get("coverage", {}).get("data", {})
    if cov.get("devices_not_seen"):
        steps.append(f"Reconnect or retire the {_plural(cov['devices_not_seen'], 'device')} that "
                     f"{'has' if cov['devices_not_seen'] == 1 else 'have'} stopped reporting.")
    if "cloud_accounts" in cov and not cov["cloud_accounts"]:
        steps.append("Connect your cloud accounts so they can be checked.")
    comp = r.get("compliance")
    if comp:
        scored = [f for f in comp["frameworks"] if f["score"] is not None and f["failing"]]
        if scored:
            worst = min(scored, key=lambda f: f["score"])
            steps.append(f"Review the failing requirements for {worst['name']} (score {worst['score']:g}%) with your "
                         "compliance lead.")
    steps += ["Review this report with your IT or security lead and give each action an owner and a date.",
              "Check the next report to confirm the numbers are moving in the right direction.",
              "Keep new computers, cloud accounts and domains connected as the business grows."]
    return list(dict.fromkeys(steps))[:3]


# ----------------------------------------------------------------------------- entry point
def build(db: Session, period: str = "monthly", now: datetime | None = None) -> dict[str, Any]:
    """The report of the session's organisation for `period` (daily|weekly|monthly|quarterly)."""
    if period not in PERIODS:
        raise ValueError("unknown period")
    now = now or utcnow()
    days, compare = PERIODS[period]
    org = db.get(Organization, tenancy.require_org(db))
    on = modules.enabled_modules(org)
    w = _make_window(days, now)
    metrics = dashboards.current_metrics(db)
    dashboards.ensure_today(db, w, metrics)
    base = dashboards.baseline(db, w)
    ep = dashboards.endpoint_stats(db) if modules.ENDPOINTS in on else None
    serious = int(metrics.get("critical_high") or 0) + int(metrics.get("vulns_critical") or 0) \
        if modules.CLOUD in on or modules.VULNERABILITIES in on else 0
    score = float(metrics["risk_score"]) if modules.CLOUD in on else None
    r: dict[str, Any] = {
        "organization": org.name if org else "",
        "period": {"key": period, "name": PERIOD_NAME[period], "days": days, "start": w.start.date().isoformat(),
                   "end": now.date().isoformat(), "compared_with": compare,
                   "label": f"{w.start:%d %b %Y} to {now:%d %b %Y}"},
        "generated_at": now, "modules": on, "brand": config.settings.brand_name,
        "headline": _headline(score, dashboards.delta(score, base, "risk_score") if score is not None else None,
                              compare, serious, modules.CLOUD in on),
        "top_risks": _top_risks(db, on, metrics, ep),
        "changes": _changes(db, on, w, metrics, base, compare),
        "coverage": _coverage(db, on, ep),
    }
    if {modules.CLOUD, modules.ENDPOINTS, modules.VULNERABILITIES} & set(on):
        r["compliance"] = _compliance(db, now)
    if modules.EXTERNAL in on:
        r["exposure"] = _exposure(db)
    if modules.VULNERABILITIES in on:
        r["overdue"] = _overdue(db, now)
    r["next_steps"] = _next_steps(r)
    return r
