"""What a check reports: one `Hit` becomes one reputation finding."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = ("email", "lookalike", "blocklist", "certificate")


@dataclass
class Hit:
    check_id: str
    category: str
    domain: str
    severity: str
    title: str
    description: str
    fix: str
    subject: str = ""  # makes the key unique when a check can fire several times for a domain
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.check_id}|{self.domain}|{self.subject}"[:400]
