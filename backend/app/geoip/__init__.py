"""IP geolocation for device tracking (docs/DEVICE_TRACKING.md).

Reads the free DB-IP "IP to City Lite" and "IP to ASN Lite" databases (MMDB, CC BY 4.0, https://db-ip.com) with
the `maxminddb` package. A missing or unreadable database never raises: `lookup` answers `available=False`
("Not available yet"). Private, loopback, CGNAT and documentation ranges are never looked up ("Private network").
Results are cached per IP in-process (LRU); the cache is cleared whenever the databases are (re)loaded.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol

from .. import config

log = logging.getLogger(__name__)

DEFAULT_ACCURACY_KM = 25.0  # a city-level fix: the area around the city centre
COUNTRY_ACCURACY_KM = 300.0


class MmdbReader(Protocol):
    """What the lookup needs from a database: `maxminddb.Reader` satisfies it; tests may fake it."""

    def get(self, ip: str) -> Any: ...


@dataclass(frozen=True)
class GeoResult:
    ip: str
    available: bool = False  # a database answered (False: "Not available yet", or no record for this address)
    is_private: bool = False
    country_code: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy_km: float | None = None
    asn: int | None = None
    provider: str | None = None


_DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100.64.0.0/10"))

_lock = threading.Lock()
_city: MmdbReader | None = None
_asn: MmdbReader | None = None
_loaded = False


def is_private(ip: str) -> bool:
    """Not a public internet address: private, loopback, link-local, CGNAT (100.64/10), documentation, ..."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (not addr.is_global) or any(addr in n for n in _DOC_NETS if n.version == addr.version)


def _open(path: str) -> MmdbReader | None:
    if not path or not os.path.isfile(path):
        return None
    try:
        import maxminddb

        return maxminddb.open_database(path)
    except Exception:
        log.warning("geoip: cannot open %s", path, exc_info=True)
        return None


def set_readers(city: MmdbReader | None, asn: MmdbReader | None) -> None:
    """Install readers (tests, and after an update) and clear the cache."""
    global _city, _asn, _loaded
    with _lock:
        _city, _asn, _loaded = city, asn, True
        _cached.cache_clear()


def reload() -> None:
    """(Re)open the databases from the configured paths."""
    s = config.settings
    set_readers(_open(s.geoip_city_db), _open(s.geoip_asn_db))


def reset() -> None:
    """Forget the readers: the next lookup opens the configured files again."""
    global _loaded
    with _lock:
        _loaded = False
        _cached.cache_clear()


def database_available() -> bool:
    _ensure()
    return _city is not None


def _ensure() -> None:
    if not _loaded:
        reload()


def _name(node: Any) -> str | None:
    names = node.get("names") if isinstance(node, dict) else None
    if isinstance(names, dict):
        return names.get("en") or next(iter(names.values()), None)
    return None


@lru_cache(maxsize=20000)
def _cached(ip: str) -> GeoResult:
    city_rec = asn_rec = None
    if _city is not None:
        try:
            city_rec = _city.get(ip)
        except Exception:
            log.debug("geoip city lookup failed for %s", ip, exc_info=True)
    if _asn is not None:
        try:
            asn_rec = _asn.get(ip)
        except Exception:
            log.debug("geoip asn lookup failed for %s", ip, exc_info=True)
    asn = provider = None
    if isinstance(asn_rec, dict):
        n = asn_rec.get("autonomous_system_number")
        asn = n if isinstance(n, int) else None
        provider = asn_rec.get("autonomous_system_organization") or None
    if not isinstance(city_rec, dict):
        return GeoResult(ip=ip, available=False, asn=asn, provider=provider)
    country = city_rec.get("country") or {}
    subs = city_rec.get("subdivisions") or []
    loc = city_rec.get("location") or {}
    city_name = _name(city_rec.get("city"))
    lat, lon = loc.get("latitude"), loc.get("longitude")
    acc = loc.get("accuracy_radius")
    if not isinstance(acc, (int, float)):
        acc = DEFAULT_ACCURACY_KM if city_name else COUNTRY_ACCURACY_KM
    return GeoResult(ip=ip, available=True, country_code=(country.get("iso_code") or None),
                     country=_name(country), region=_name(subs[0]) if subs else None, city=city_name,
                     latitude=lat if isinstance(lat, (int, float)) else None,
                     longitude=lon if isinstance(lon, (int, float)) else None, accuracy_km=float(acc),
                     asn=asn, provider=provider)


def lookup(ip: str | None) -> GeoResult:
    """Where is this public address? Never raises for a missing database or an unknown address."""
    ip = (ip or "").strip()
    if not ip:
        return GeoResult(ip="")
    if is_private(ip):
        return GeoResult(ip=ip, is_private=True)
    _ensure()
    return _cached(ip)
