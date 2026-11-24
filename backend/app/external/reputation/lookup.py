"""DNS access for the reputation checks: one polite (rate limited) query function that tests replace.

`Dns(query, rate)` wraps a `query(name, rtype) -> list[str]` callable (default: the external module's `dnsclient`,
which returns [] on NXDOMAIN, no data and failure) and spaces queries at most `rate` per second (0 = unlimited)."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable

from .. import dnsclient

Query = Callable[[str, str], list[str]]


def default_query(name: str, rtype: str) -> list[str]:
    return dnsclient.query(name, rtype, timeout=3.0)


class Dns:
    def __init__(self, query: Query | None = None, rate: float = 0.0, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self._query = query or default_query
        self.rate = rate
        self._sleep, self._clock = sleep, clock
        self._next = 0.0
        self._lock = threading.Lock()
        self.queries = 0

    def q(self, name: str, rtype: str) -> list[str]:
        if self.rate > 0:
            with self._lock:
                now = self._clock()
                wait = self._next - now
                self._next = max(now, self._next) + 1.0 / self.rate
            if wait > 0:
                self._sleep(wait)
        self.queries += 1
        try:
            return list(self._query(name.rstrip("."), rtype))
        except Exception:
            return []
