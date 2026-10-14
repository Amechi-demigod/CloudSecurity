"""Pluggable collector interface."""
from __future__ import annotations

import abc
from typing import List

from ..schema import RuntimeEvent


class Collector(abc.ABC):
    """A collector produces RuntimeEvents.

    The agent calls ``setup()`` once, ``poll()`` every poll interval from a
    single thread, and ``close()`` on shutdown. ``poll`` must be non-blocking
    (or block only briefly) and must never raise for per-process races
    (processes exiting mid-read are normal).
    """

    name: str = "base"

    def setup(self) -> None:  # pragma: no cover - default no-op
        pass

    @abc.abstractmethod
    def poll(self) -> List[RuntimeEvent]:
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - default no-op
        pass
