"""Connections of the scanner: every connection goes through `Net.open`, which enforces the address guard (name
resolved and re-checked right before connecting, then the checked IP literal is dialled), the scan deadline, a
per-host parallelism cap and a per-host connection rate, and the connect timeout. Includes a tiny HTTP/1.1 client
that never reads more than a few KB of a response and never follows redirects."""
from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field

from .. import config
from . import guard

USER_AGENT = "Sentrigis-AttackSurface/1.0 (+https://sentrigis.com/scanner)"
MAX_HEADER_BYTES = 16 * 1024


class ScanDeadline(Exception):
    """The maximum scan duration was reached."""


@dataclass
class HostLimiter:
    parallel: int
    rate: float  # connection attempts per second
    _sem: asyncio.Semaphore = field(init=False)
    _next: float = field(default=0.0, init=False)
    _lock: asyncio.Lock = field(init=False)

    def __post_init__(self) -> None:
        self._sem = asyncio.Semaphore(self.parallel)
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        await self._sem.acquire()
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + (1.0 / self.rate if self.rate > 0 else 0)
        if wait > 0:
            await asyncio.sleep(wait)

    def release(self) -> None:
        self._sem.release()


def unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


class Net:
    def __init__(self, *, deadline: float | None = None, connect_timeout: float | None = None,
                 read_timeout: float | None = None, rate: float | None = None, parallel: int | None = None):
        s = config.settings
        self.deadline = deadline  # time.monotonic() value
        self.connect_timeout = connect_timeout or s.external_connect_timeout
        self.read_timeout = read_timeout or s.external_read_timeout
        self.rate = rate or s.external_host_rate
        self.parallel = parallel or s.external_host_parallel
        self._limiters: dict[str, HostLimiter] = {}
        self.refused: list[str] = []
        self.connections = 0

    def check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ScanDeadline()

    def limiter(self, ip: str) -> HostLimiter:
        if ip not in self._limiters:
            self._limiters[ip] = HostLimiter(self.parallel, self.rate)
        return self._limiters[ip]

    async def open(self, host: str, port: int, *, tls: bool = False, sni: str | None = None,
                   ctx: ssl.SSLContext | None = None):
        """(reader, writer, ip, release): `release()` must be called when the connection is finished."""
        self.check_deadline()
        try:
            ip = await guard.resolve_public(host)  # checked again for every connection
        except guard.BlockedAddress as e:
            self.refused.append(str(e))
            raise
        lim = self.limiter(ip)
        await lim.acquire()
        try:
            self.connections += 1
            server_hostname = None
            if tls:
                server_hostname = sni if sni is not None else (None if guard.is_ip_literal(host) else host)
            kw: dict = {}
            if tls:
                kw = {"ssl": ctx or unverified_ctx(), "server_hostname": server_hostname,
                      "ssl_handshake_timeout": self.connect_timeout}
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, **kw), self.connect_timeout * 2)
        except BaseException:
            lim.release()
            raise
        return r, w, ip, lim.release

    async def http(self, host: str, port: int, *, tls: bool, path: str = "/", method: str = "GET",
                   headers: dict[str, str] | None = None, max_body: int = 2048, host_header: str | None = None,
                   ) -> dict | None:
        """One HTTP/1.1 request. None when the connection or the response failed. Returns
        {status, headers (lower-case; set-cookie is a list), body (<= max_body bytes), ip}."""
        try:
            r, w, ip, release = await self.open(host, port, tls=tls)
        except (OSError, TimeoutError, ssl.SSLError, guard.BlockedAddress):
            return None
        try:
            hdrs = {"Host": host_header or host, "User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close",
                    **(headers or {})}
            req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
            w.write(req.encode("latin-1", "replace"))
            await asyncio.wait_for(w.drain(), self.read_timeout)
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), self.read_timeout)
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ", 2)
            if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
                return None
            out_h: dict = {}
            for ln in lines[1:]:
                if ":" not in ln:
                    continue
                k, v = ln.split(":", 1)
                k, v = k.strip().lower(), v.strip()
                if k == "set-cookie":
                    out_h.setdefault(k, []).append(v)
                else:
                    out_h[k] = v
            body = b""
            if method != "HEAD" and max_body:
                try:
                    body = await asyncio.wait_for(r.read(max_body), self.read_timeout)
                except (TimeoutError, OSError):
                    body = b""
            return {"status": int(parts[1]), "headers": out_h, "body": body[:max_body], "ip": ip}
        except (OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ssl.SSLError):
            return None
        finally:
            w.close()
            release()
            try:
                await asyncio.wait_for(w.wait_closed(), 1)
            except (OSError, TimeoutError, ssl.SSLError):
                pass

    async def banner(self, host: str, port: int, *, send: bytes = b"", max_bytes: int = 256, wait: float = 3.0
                     ) -> bytes | None:
        """None when the port is closed / filtered; b"" when open but silent."""
        try:
            r, w, _ip, release = await self.open(host, port)
        except (OSError, TimeoutError, guard.BlockedAddress):
            return None
        try:
            if send:
                w.write(send)
                await w.drain()
            try:
                return await asyncio.wait_for(r.read(max_bytes), min(wait, self.read_timeout))
            except (TimeoutError, OSError):
                return b""
        finally:
            w.close()
            release()
