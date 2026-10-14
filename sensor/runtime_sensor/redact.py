"""Redaction of secrets from command lines before anything leaves the host."""
from __future__ import annotations

import re
from typing import List, Sequence

REDACTED = "[REDACTED]"
MAX_CMDLINE_LEN = 1024

_SECRET_KEY = (
    r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization)?|credentials?|session[_-]?id)"
)

# key=value / key:value inside a single argument (e.g. --password=hunter2, DB_PASSWORD=x)
_KV_RE = re.compile(r"(?i)((?:^|[\s,;&?])[\w.-]*" + _SECRET_KEY + r"[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)")
# a flag whose *next* argument is the secret (e.g. --password hunter2, -token x)
_FLAG_RE = re.compile(r"(?i)^--?[\w.-]*" + _SECRET_KEY + r"[\w.-]*$")
# URL user-info: scheme://user:password@host
_URL_CRED_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)")
# Authorization: Bearer xxx / Basic xxx
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
# Well-known token shapes
_TOKEN_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # GitHub tokens
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
# mysql/mariadb style -pSECRET (only for db clients, -p is ambiguous elsewhere)
_DB_CLIENTS = {"mysql", "mysqldump", "mariadb", "mysqladmin"}


def redact_text(text: str) -> str:
    if not text:
        return text
    text = _URL_CRED_RE.sub(lambda m: m.group(1) + REDACTED + m.group(3), text)
    text = _BEARER_RE.sub(lambda m: m.group(1) + " " + REDACTED, text)
    text = _KV_RE.sub(lambda m: m.group(1) + REDACTED, text)
    for pat in _TOKEN_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


def redact_argv(argv: Sequence[str]) -> List[str]:
    out: List[str] = []
    redact_next = False
    prog = argv[0].rsplit("/", 1)[-1] if argv else ""
    for i, arg in enumerate(argv):
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        if prog in _DB_CLIENTS and arg.startswith("-p") and len(arg) > 2 and not arg.startswith("--"):
            out.append("-p" + REDACTED)
            continue
        if i > 0 and _FLAG_RE.match(arg):
            out.append(arg)
            redact_next = True
            continue
        out.append(redact_text(arg))
    return out


def safe_cmdline(argv: Sequence[str], max_len: int = MAX_CMDLINE_LEN) -> str:
    """Redact secrets and truncate. Returns a single space-joined string."""
    joined = " ".join(redact_argv(argv))
    if len(joined) > max_len:
        joined = joined[: max_len - 3] + "..."
    return joined
