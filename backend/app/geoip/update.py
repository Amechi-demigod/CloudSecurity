"""Download and install the DB-IP Lite city and ASN databases (CC BY 4.0, https://db-ip.com).

Manual run:  python -m app.geoip.update
Automatic:   `GeoipUpdater` (leader-elected background thread, monthly; GEOIP_AUTO_UPDATE=false switches it off).

Each file is fetched for the current month, falling back to the previous one (DB-IP publishes early in the month),
checked by opening it, then swapped in atomically (os.replace). A failed download leaves the old file alone.
"""
from __future__ import annotations

import gzip
import logging
import os
import tempfile
import threading
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .. import config, geoip
from ..locks import LeaderLock

log = logging.getLogger(__name__)

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
MAX_BYTES = 400 * 1024 * 1024
Fetch = Callable[[str], bytes]


def _months(now: datetime) -> list[str]:
    prev = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    return [f"{now.year}-{now.month:02d}", f"{prev[0]}-{prev[1]:02d}"]


def _http_fetch(url: str) -> bytes:  # pragma: no cover - network
    if not url.startswith("https://download.db-ip.com/"):
        raise ValueError("unexpected URL")
    req = urllib.request.Request(url, headers={"User-Agent": "sentrigis-geoip-updater"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 (fixed https URL)
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("download too large")
    return data


def _opens(path: str) -> bool:
    try:
        import maxminddb

        with maxminddb.open_database(path) as r:
            return bool(r.metadata().node_count)
    except Exception:
        return False


def install(kind: str, dest: str, fetch: Fetch = _http_fetch, now: datetime | None = None) -> bool:
    """Fetch one database ("city" or "asn") to `dest`; True when a new file was installed."""
    now = now or datetime.now(UTC)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    for ym in _months(now):
        url = URL.format(kind=kind, ym=ym)
        try:
            raw = gzip.decompress(fetch(url))
        except Exception as e:
            log.info("geoip: %s not available (%s)", url, type(e).__name__)
            continue
        fd, tmp = tempfile.mkstemp(dir=str(Path(dest).parent), suffix=".part")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            if not _opens(tmp):
                log.warning("geoip: downloaded %s is not a usable database", url)
                continue
            os.replace(tmp, dest)
            tmp = ""
            log.info("geoip: installed %s", dest)
            return True
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
    return False


def update_all(fetch: Fetch = _http_fetch, now: datetime | None = None) -> dict[str, bool]:
    s = config.settings
    out = {"city": install("city", s.geoip_city_db, fetch, now), "asn": install("asn", s.geoip_asn_db, fetch, now)}
    if any(out.values()):
        geoip.reload()
    return out


def _stale(path: str, now: datetime, days: int = 30) -> bool:
    try:
        return (now.timestamp() - os.path.getmtime(path)) > days * 86400
    except OSError:
        return True


class GeoipUpdater:
    """Leader-elected: checks daily, downloads when a file is missing or older than a month."""

    LOCK_NAME = "geoip-update"

    def __init__(self, tick_seconds: float = 86400.0, startup_delay_seconds: float = 60.0, fetch: Fetch = _http_fetch):
        self.tick_seconds, self.startup_delay, self._fetch = tick_seconds, startup_delay_seconds, fetch
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="geoip-update", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> dict[str, bool]:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return {}
        now = now or datetime.now(UTC)
        s = config.settings
        if not (_stale(s.geoip_city_db, now) or _stale(s.geoip_asn_db, now)):
            return {}
        return update_all(self._fetch, now)

    def _run(self) -> None:
        if self._stop.wait(self.startup_delay):
            return
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("geoip update failed")
            if self._stop.wait(self.tick_seconds):
                return


def main() -> int:  # pragma: no cover - manual entry point
    logging.basicConfig(level=logging.INFO)
    res = update_all()
    print(res)
    return 0 if any(res.values()) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
