"""Email security: SPF, DMARC, DKIM (common selectors), MX, MTA-STS and TLS-RPT. DNS only."""
from __future__ import annotations

import re

from .hits import Hit
from .lookup import Dns

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim")
SPF_LOOKUP_LIMIT = 10
_MAX_SPF_QUERIES = 25  # never follow more than this many include / redirect records


def _txt(dns: Dns, name: str, prefix: str) -> list[str]:
    return [v.strip() for v in dns.q(name, "TXT") if v.strip().lower().startswith(prefix)]


def spf_lookups(record: str, dns: Dns, budget: list[int] | None = None, depth: int = 0) -> int:
    """DNS-lookup terms of an SPF record (include, a, mx, ptr, exists, redirect), following include / redirect."""
    budget = budget if budget is not None else [_MAX_SPF_QUERIES]
    total = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech, _, arg = t.partition(":")
        if t.startswith("redirect="):
            mech, arg = "redirect", t.split("=", 1)[1]
        if mech in ("a", "mx", "ptr", "exists") or mech.startswith(("a/", "mx/")):
            total += 1
        elif mech in ("include", "redirect"):
            total += 1
            if arg and depth < 5 and budget[0] > 0:
                budget[0] -= 1
                inner = _txt(dns, arg, "v=spf1")
                if inner:
                    total += spf_lookups(inner[0], dns, budget, depth + 1)
    return total


def _check_spf(domain: str, dns: Dns, has_mail: bool, snap: dict) -> list[Hit]:
    recs = _txt(dns, domain, "v=spf1")
    snap["spf"] = recs[0] if recs else None
    if not recs:
        if not has_mail:
            return []
        return [Hit("rep.spf_missing", "email", domain, "medium", "No SPF record",
                    "The domain has no SPF record, so receiving mail servers cannot tell which servers may send email "
                    "for it. Anyone can more easily send mail that appears to come from your domain.",
                    "Publish a TXT record on the domain that lists your sending services and ends in -all (or ~all while "
                    'testing), for example "v=spf1 include:_spf.your-mail-provider.com -all".')]
    hits: list[Hit] = []
    if len(recs) > 1:
        hits.append(Hit("rep.spf_multiple", "email", domain, "medium", "More than one SPF record",
                        "The domain publishes several SPF records. The standard says this is an error and receivers "
                        "may ignore SPF completely.",
                        "Merge them into a single TXT record that starts with v=spf1.", evidence={"records": recs[:5]}))
    rec = recs[0]
    terms = rec.lower().split()
    allm = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    if allm is not None and (allm == "all" or allm.startswith("+")):
        hits.append(Hit("rep.spf_allow_all", "email", domain, "high", "SPF allows any server to send (+all)",
                        "The SPF record ends in +all, which authorises every server on the internet to send mail as "
                        "your domain. It gives no protection.",
                        "Change the ending to -all (reject) or ~all (soft fail) after listing your real senders.",
                        evidence={"record": rec}))
    elif allm is not None and allm.startswith("?"):
        hits.append(Hit("rep.spf_neutral", "email", domain, "medium", "SPF is neutral (?all)",
                        "The SPF record ends in ?all, which says nothing about unlisted servers, so it does not "
                        "help receivers reject forged mail.",
                        "Change the ending to -all (reject) or ~all (soft fail).", evidence={"record": rec}))
    elif allm is None and not any(t.startswith("redirect=") for t in terms):
        hits.append(Hit("rep.spf_no_all", "email", domain, "low", "SPF record has no ending policy",
                        "The SPF record has no all mechanism or redirect, so unlisted servers get a neutral result.",
                        "End the record with -all (or ~all while testing).", evidence={"record": rec}))
    n = spf_lookups(rec, dns)
    snap["spf_lookups"] = n
    if n > SPF_LOOKUP_LIMIT:
        hits.append(Hit("rep.spf_too_many_lookups", "email", domain, "medium",
                        f"SPF needs {n} DNS look-ups (the limit is {SPF_LOOKUP_LIMIT})",
                        "SPF allows at most 10 DNS look-ups. Above that receivers return a permanent error and treat "
                        "your SPF as broken, so legitimate mail may fail checks.",
                        "Remove services you no longer use, replace include: entries with ip4: / ip6: ranges, or use "
                        "an SPF flattening service.", evidence={"lookups": n, "record": rec}))
    return hits


def _check_dmarc(domain: str, dns: Dns, has_mail: bool, snap: dict) -> list[Hit]:
    recs = _txt(dns, f"_dmarc.{domain}", "v=dmarc1")
    snap["dmarc"] = recs[0] if recs else None
    if not recs:
        sev = "high" if has_mail else "medium"
        return [Hit("rep.dmarc_missing", "email", domain, sev, "No DMARC record",
                    "Without DMARC, receivers have no instruction on what to do with mail that fails SPF and DKIM, and "
                    "you get no reports about who is sending as your domain. Spoofing and phishing in your name are "
                    "easier.",
                    f'Publish a TXT record on _dmarc.{domain} such as "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}". '
                    "Start with p=none if you need to monitor first, then move to quarantine and reject.")]
    hits: list[Hit] = []
    if len(recs) > 1:
        hits.append(Hit("rep.dmarc_multiple", "email", domain, "medium", "More than one DMARC record",
                        "Several DMARC records are published; receivers ignore DMARC when there is more than one.",
                        "Keep a single v=DMARC1 TXT record on _dmarc." + domain, evidence={"records": recs[:5]}))
    tags = {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in recs[0].split(";")) if k.strip()}
    policy = tags.get("p", "").lower()
    snap["dmarc_policy"] = policy or None
    if policy not in ("none", "quarantine", "reject"):
        hits.append(Hit("rep.dmarc_invalid", "email", domain, "medium", "DMARC record has no valid policy",
                        "The DMARC record has no p= tag with none, quarantine or reject, so receivers ignore it.",
                        "Add p=quarantine (or p=reject) to the record.", evidence={"record": recs[0]}))
    elif policy == "none":
        hits.append(Hit("rep.dmarc_policy_none", "email", domain, "medium", "DMARC policy is monitor-only (p=none)",
                        "DMARC is published but p=none tells receivers to deliver mail that fails the checks. It "
                        "gives visibility but does not stop spoofing.",
                        "Review the reports, fix legitimate senders, then raise the policy to p=quarantine and finally "
                        "p=reject.", evidence={"record": recs[0]}))
    if "rua" not in tags or not tags["rua"].lower().startswith("mailto:"):
        hits.append(Hit("rep.dmarc_no_rua", "email", domain, "low", "DMARC has no aggregate report address (rua)",
                        "Without rua= you receive no DMARC reports, so you cannot see who sends mail as your domain "
                        "or whether legitimate mail is failing.",
                        f"Add rua=mailto:dmarc@{domain} (a mailbox or a DMARC reporting service) to the record.",
                        evidence={"record": recs[0]}))
    return hits


def _check_dkim(domain: str, dns: Dns, has_mail: bool, snap: dict) -> list[Hit]:
    found = []
    for sel in DKIM_SELECTORS:
        if any(re.search(r"\bp=", v) or "v=dkim1" in v.lower() for v in dns.q(f"{sel}._domainkey.{domain}", "TXT")):
            found.append(sel)
    snap["dkim_selectors"] = found
    if found or not has_mail:
        return []
    return [Hit("rep.dkim_not_found", "email", domain, "info", "No DKIM key found on common selectors",
                "None of the common DKIM selectors (" + ", ".join(DKIM_SELECTORS) + ") has a key. Your mail provider "
                "may use a different selector name, so this is not necessarily a problem, but it cannot be confirmed "
                "from outside.",
                "Check your mail provider's setup guide for the DKIM selector and make sure signing is enabled.",
                evidence={"selectors_checked": list(DKIM_SELECTORS)})]


def check(domain: str, dns: Dns) -> tuple[list[Hit], dict]:
    """(hits, snapshot) of the email security of `domain`."""
    snap: dict = {}
    mx = dns.q(domain, "MX")
    snap["mx"] = sorted(set(m.lower().rstrip(".") for m in mx))[:20]
    null_mx = snap["mx"] == [""] or snap["mx"] == []
    has_mail = bool(snap["mx"]) and not null_mx
    hits: list[Hit] = []
    if not mx:
        hits.append(Hit("rep.mx_missing", "email", domain, "info", "No mail servers (MX records)",
                        "The domain has no MX records, so it cannot receive email. This is fine if the domain is not "
                        "used for mail.",
                        "If the domain is not used for mail, publish a null MX (0 .) and an SPF record of v=spf1 -all "
                        "and a DMARC policy of reject so nobody can send as it."))
    hits += _check_spf(domain, dns, has_mail, snap)
    hits += _check_dmarc(domain, dns, has_mail, snap)
    hits += _check_dkim(domain, dns, has_mail, snap)
    if has_mail:
        snap["mta_sts"] = bool(_txt(dns, f"_mta-sts.{domain}", "v=stsv1"))
        snap["tls_rpt"] = bool(_txt(dns, f"_smtp._tls.{domain}", "v=tlsrptv1"))
        if not snap["mta_sts"]:
            hits.append(Hit("rep.mta_sts_missing", "email", domain, "info", "MTA-STS is not set up",
                            "MTA-STS tells other mail servers to use encrypted connections when sending to you and "
                            "to refuse to downgrade.",
                            f"Publish a TXT record on _mta-sts.{domain} (v=STSv1; id=...) and host the policy file."))
        if not snap["tls_rpt"]:
            hits.append(Hit("rep.tls_rpt_missing", "email", domain, "info", "TLS reporting (TLS-RPT) is not set up",
                            "TLS-RPT sends you reports when other servers fail to deliver mail to you securely.",
                            f"Publish a TXT record on _smtp._tls.{domain} such as v=TLSRPTv1; rua=mailto:tls@{domain}."))
    return hits, snap
