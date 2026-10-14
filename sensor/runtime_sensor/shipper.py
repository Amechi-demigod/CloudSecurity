"""Batching event shipper.

* bounded in-memory queue (oldest events dropped when full, counted)
* batches by size or flush interval
* POSTs JSON to the platform with ``Authorization: Bearer <token>``
* retries 429/5xx/network errors with exponential backoff + jitter
* ``dry_run`` writes JSON lines to stdout instead of sending
"""
from __future__ import annotations

import collections
import json
import logging
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import IO, Callable, Deque, Dict, List, Optional

from . import __version__
from .compat import to_cnapp_mvp
from .schema import RuntimeEvent, utc_now_iso

log = logging.getLogger(__name__)

DEFAULT_API_URL = "http://localhost:8000/api/runtime/events"
# list      = JSON array of native v1.0 events
# envelope  = {"sensor_id", "sensor_version", "sent_at", "events": [native v1.0 events]}
# cnapp-mvp = JSON array translated to the current backend RuntimeEventIn shape (see compat.py)
PAYLOAD_FORMATS = ("cnapp-mvp", "list", "envelope")
DEFAULT_PAYLOAD_FORMAT = "cnapp-mvp"


class SendError(Exception):
    def __init__(self, message: str, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


# Honour HTTP(S)_PROXY / NO_PROXY env vars only (no OS proxy-registry lookups).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler(urllib.request.getproxies_environment()))


def http_post(url: str, body: bytes, headers: Dict[str, str], timeout: float) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        retryable = exc.code == 429 or exc.code >= 500
        raise SendError(f"HTTP {exc.code} from {url}", retryable) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise SendError(f"network error posting to {url}: {exc}", True) from exc


class Shipper:
    def __init__(self, api_url: str = DEFAULT_API_URL, token: Optional[str] = None, sensor_id: str = "",
                 batch_size: int = 100, flush_interval: float = 5.0, max_queue: int = 10_000,
                 max_retries: int = 5, backoff_base: float = 1.0, backoff_max: float = 60.0,
                 timeout: float = 10.0, dry_run: bool = False, payload_format: str = DEFAULT_PAYLOAD_FORMAT,
                 out: Optional[IO[str]] = None, post: Callable[..., int] = http_post,
                 sleep: Callable[[float], None] = time.sleep):
        if payload_format not in PAYLOAD_FORMATS:
            raise ValueError(f"payload_format must be one of {PAYLOAD_FORMATS}")
        self.api_url = api_url
        self.token = token
        self.sensor_id = sensor_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_queue = max_queue
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.timeout = timeout
        self.dry_run = dry_run
        self.payload_format = payload_format
        self.out = out or sys.stdout
        self._post = post
        self._sleep = sleep
        self._queue: Deque[Dict] = collections.deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {"enqueued": 0, "sent": 0, "dropped_queue_full": 0, "dropped_send_failed": 0,
                      "batches_sent": 0, "send_errors": 0, "skipped_unsupported": 0}

    # -- producer side ------------------------------------------------------
    def enqueue(self, event: RuntimeEvent) -> None:
        with self._lock:
            if len(self._queue) >= self.max_queue:
                self._queue.popleft()
                self.stats["dropped_queue_full"] += 1
            self._queue.append(event.to_dict())
            self.stats["enqueued"] += 1
            if len(self._queue) >= self.batch_size:
                self._wake.set()

    def queue_len(self) -> int:
        with self._lock:
            return len(self._queue)

    # -- consumer side --------------------------------------------------------
    def _take_batch(self) -> List[Dict]:
        with self._lock:
            n = min(self.batch_size, len(self._queue))
            return [self._queue.popleft() for _ in range(n)]

    def build_payload(self, batch: List[Dict]):
        if self.payload_format == "cnapp-mvp":
            return [t for t in (to_cnapp_mvp(e) for e in batch) if t is not None]
        if self.payload_format == "list":
            return batch
        return {"sensor_id": self.sensor_id, "sensor_version": __version__, "sent_at": utc_now_iso(),
                "events": batch}

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "User-Agent": f"cnapp-runtime-sensor/{__version__}",
                   "X-Sensor-Id": self.sensor_id}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def send_batch(self, batch: List[Dict]) -> bool:
        if not batch:
            return True
        if self.dry_run:
            for ev in batch:
                self.out.write(json.dumps(ev, separators=(",", ":")) + "\n")
            self.out.flush()
            self.stats["sent"] += len(batch)
            self.stats["batches_sent"] += 1
            return True
        payload = self.build_payload(batch)
        if not payload:  # e.g. only library events in cnapp-mvp mode
            self.stats["skipped_unsupported"] += len(batch)
            return True
        body = json.dumps(payload, separators=(",", ":")).encode()
        attempt = 0
        while True:
            try:
                self._post(self.api_url, body, self._headers(), self.timeout)
                self.stats["sent"] += len(batch)
                self.stats["batches_sent"] += 1
                return True
            except SendError as exc:
                self.stats["send_errors"] += 1
                if not exc.retryable or attempt >= self.max_retries:
                    log.warning("dropping batch of %d events: %s", len(batch), exc)
                    self.stats["dropped_send_failed"] += len(batch)
                    return False
                delay = min(self.backoff_max, self.backoff_base * (2 ** attempt))
                delay = delay * (0.5 + random.random() / 2)  # jitter
                log.info("send failed (%s); retry %d/%d in %.1fs", exc, attempt + 1, self.max_retries, delay)
                attempt += 1
                if self._stop.is_set():
                    delay = min(delay, 0.5)
                self._sleep(delay)

    def flush(self) -> None:
        while True:
            batch = self._take_batch()
            if not batch:
                return
            self.send_batch(batch)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            self.flush()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="shipper", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)
        self.flush()
