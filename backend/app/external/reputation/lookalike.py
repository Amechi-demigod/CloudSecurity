"""Look-alike domains: deterministic permutations of a domain name and a DNS-only check of which ones resolve.
Nothing is fetched and no port is opened: only A / MX / AAAA look-ups, rate limited by `Dns`."""
from __future__ import annotations

import re

from .hits import Hit
from .lookup import Dns

LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
TLD_SWAPS = ("com", "net", "org", "co", "io", "biz", "info", "online", "xyz", "app", "shop", "site", "ng", "com.ng",
             "co.uk", "us", "cc")
SECOND_LEVEL = {"com", "co", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "ol", "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
    "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13w", "3": "24e", "4": "35r", "5": "46t", "6": "57y", "7": "68u", "8": "79i", "9": "80o",
    "0": "9p"}
HOMOGLYPHS = (("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("i", "1"), ("i", "l"), ("l", "i"), ("rn", "m"),
              ("m", "rn"), ("w", "vv"), ("vv", "w"), ("d", "cl"), ("cl", "d"), ("s", "5"), ("e", "3"), ("a", "4"))
TECHNIQUES = ("omission", "repetition", "swap", "keyboard", "homoglyph", "hyphenation", "tld")
TECHNIQUE_LABELS = {"omission": "a missing letter", "repetition": "a repeated letter", "swap": "swapped letters",
                    "keyboard": "a neighbouring key", "homoglyph": "a look-alike character",
                    "hyphenation": "an added hyphen", "tld": "a different ending (TLD)"}


def split(domain: str) -> tuple[str, str] | None:
    """(label, suffix) when `domain` is a registrable domain (label + suffix such as com or co.uk), else None."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    n = 2 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL else 1
    if len(parts) != n + 1:
        return None  # a subdomain: look-alikes of a subdomain are not meaningful
    return parts[0], ".".join(parts[1:])


def _by_technique(label: str, suffix: str) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {t: set() for t in TECHNIQUES}
    for i in range(len(label)):
        out["omission"].add(label[:i] + label[i + 1:])
        out["repetition"].add(label[:i] + label[i] + label[i:])
        for k in KEYBOARD.get(label[i], ""):
            out["keyboard"].add(label[:i] + k + label[i + 1:])
        if i + 1 < len(label) and label[i] != label[i + 1]:
            out["swap"].add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
        if i > 0:
            out["hyphenation"].add(label[:i] + "-" + label[i:])
    for a, b in HOMOGLYPHS:
        start = 0
        while (j := label.find(a, start)) != -1:
            out["homoglyph"].add(label[:j] + b + label[j + len(a):])
            start = j + 1
    res: dict[str, list[str]] = {}
    for t, labels in out.items():
        res[t] = sorted(f"{lab}.{suffix}" for lab in labels if lab != label and LABEL_RE.match(lab) and len(lab) <= 63)
    res["tld"] = sorted(f"{label}.{tld}" for tld in TLD_SWAPS if tld != suffix)
    return res


def generate(domain: str, cap: int = 300) -> list[tuple[str, str]]:
    """Up to `cap` (candidate, technique) pairs, deterministic: the techniques are interleaved so each is represented
    when the cap bites. The domain itself is never included."""
    sp = split(domain)
    if sp is None or not LABEL_RE.match(sp[0]):
        return []
    by_t = _by_technique(*sp)
    seen = {domain.lower()}
    out: list[tuple[str, str]] = []
    i = 0
    while len(out) < cap and any(i < len(v) for v in by_t.values()):
        for t in TECHNIQUES:
            lst = by_t[t]
            if i < len(lst) and lst[i] not in seen and len(out) < cap:
                seen.add(lst[i])
                out.append((lst[i], t))
        i += 1
    return out


def resolve(candidates: list[tuple[str, str]], dns: Dns, skip: set[str] | None = None) -> list[dict]:
    """The candidates that resolve: [{domain, technique, a, aaaa, mx}], with MX records first. `skip` = domains the
    organisation itself owns."""
    found: list[dict] = []
    for cand, tech in candidates:
        if skip and cand in skip:
            continue
        a = dns.q(cand, "A")
        mx = dns.q(cand, "MX")
        aaaa = [] if (a or mx) else dns.q(cand, "AAAA")
        mx = [m for m in mx if m]
        if a or mx or aaaa:
            found.append({"domain": cand, "technique": tech, "a": sorted(set(a))[:5], "aaaa": sorted(set(aaaa))[:3],
                          "mx": sorted({m.lower() for m in mx})[:5]})
    found.sort(key=lambda r: (not r["mx"], r["domain"]))
    return found


MAX_MX_FINDINGS = 25


def hits_for(domain: str, found: list[dict]) -> list[Hit]:
    hits: list[Hit] = []
    with_mx = [r for r in found if r["mx"]]
    for r in with_mx[:MAX_MX_FINDINGS]:
        hits.append(Hit(
            "rep.lookalike_mail", "lookalike", domain, "medium",
            f"Look-alike domain {r['domain']} can send and receive email",
            f"{r['domain']} is registered by someone else, looks like {domain} ({TECHNIQUE_LABELS[r['technique']]}) "
            "and has mail servers set up. Look-alike domains with mail are commonly used for phishing and invoice "
            "fraud against your staff, customers and suppliers.",
            "Check who owns it (WHOIS / RDAP). If it is not yours, consider a takedown request through the registrar, "
            "warn staff and finance teams, and add mail filtering rules. Register the most dangerous variants "
            "yourself.", subject=r["domain"], evidence=r))
    rest = [r for r in found if r not in with_mx[:MAX_MX_FINDINGS]]
    if rest:
        n = len(rest)
        plural = n != 1
        hits.append(Hit(
            "rep.lookalike_registered", "lookalike", domain, "low",
            f"{n} look-alike domain{'s' if plural else ''} of {domain} {'are' if plural else 'is'} registered",
            "These names differ from your domain by a typo, look-alike character or different ending and they resolve "
            "in DNS. Most are parked or unrelated, but they can be used for phishing or to catch mistyped addresses.",
            "Review the list. Register the variants you care about most (your common typos and your own TLDs) and watch "
            "the rest; act if one starts sending mail or hosting a copy of your site.",
            evidence={"domains": [r["domain"] for r in rest][:100], "count": n}))
    return hits
