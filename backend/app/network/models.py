"""Network discovery tables (docs/NETWORK_DISCOVERY.md).

* `network_scans`: one configured scan (targets, exclusions, port check, SNMP
  credentials, schedule, pace) that runs on a dedicated collector.
* `network_snmp_credentials`: SNMP v3 / v2c credentials. Everything that is not
  secret is a column; the secrets (v3 auth / privacy passwords, v2c community)
  are one Fernet token (the same mechanism directory sources use) and are never
  returned by the API, stored in command params or logged.
* `network_scan_runs`: one execution (scheduled, manual, test of one address)
  and the collector command it was queued as.
* `network_devices`: one row per device identity (org + MAC when known, else IP),
  with what SNMP / the port check reported, links to the IT asset and to the
  enrolled endpoint / directory computer it is, and a shadow cloud-inventory
  `assets` row (`asset_id`) that findings are keyed to.
* `network_device_ports`, `network_device_interfaces`, `network_fdb`,
  `network_device_events`: open ports, interfaces, switch forwarding tables
  (switch port -> MAC) and the device history.

They are not the IT asset (`it_assets`) or endpoint (`devices`) tables: a device
only becomes an IT asset when an admin adds it.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from ..tenancy import TenantMixin

SCHEDULES = ("daily", "weekly", "manual")
PACES = (20, 64)
RUN_TRIGGERS = ("scheduled", "manual", "test", "rescan")
RUN_ACTIVE = ("queued", "running")
DEVICE_TYPES = ("switch", "router", "firewall", "access_point", "printer", "ups", "phone", "camera", "server",
                "workstation", "unknown")
INFRASTRUCTURE = ("switch", "router", "firewall", "access_point")
DEFAULT_PORTS = ({"port": 22, "proto": "tcp"}, {"port": 23, "proto": "tcp"}, {"port": 80, "proto": "tcp"},
                 {"port": 443, "proto": "tcp"}, {"port": 445, "proto": "tcp"}, {"port": 3389, "proto": "tcp"},
                 {"port": 161, "proto": "udp"}, {"port": 8080, "proto": "tcp"}, {"port": 8443, "proto": "tcp"},
                 {"port": 9100, "proto": "tcp"})


class NetworkSnmpCredential(TenantMixin, Base):
    __tablename__ = "network_snmp_credentials"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(4))  # v3 | v2c
    username: Mapped[str] = mapped_column(String(128), default="")  # v3
    level: Mapped[str] = mapped_column(String(16), default="")  # authPriv | authNoPriv
    auth_proto: Mapped[str] = mapped_column(String(8), default="")  # SHA | SHA256 | SHA512
    priv_proto: Mapped[str] = mapped_column(String(8), default="")  # AES128 | AES256 | none
    # Fernet token of {"auth_password", "priv_password"} (v3) or {"community"} (v2c).
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Display form of the secret-ish name ("sn••••" / "co••••"), never the secret.
    hint: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NetworkScan(TenantMixin, Base):
    __tablename__ = "network_scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    collector_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("directory_collectors.id", ondelete="SET NULL", name="fk_network_scans_collector_id"),
        nullable=True, index=True)
    targets: Mapped[list] = mapped_column(JSON, default=list)
    exclude: Mapped[list] = mapped_column(JSON, default=list)
    # Where a target came from: {"10.10.1.0/24": "AD Site: HQ"} (display only).
    target_notes: Mapped[dict] = mapped_column(JSON, default=dict)
    port_check: Mapped[bool] = mapped_column(Boolean, default=True)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    concurrency: Mapped[int] = mapped_column(Integer, default=20)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=1500)
    credential_ids: Mapped[list] = mapped_column(JSON, default=list)
    schedule: Mapped[str] = mapped_column(String(8), default="daily")
    schedule_time: Mapped[str] = mapped_column(String(5), default="02:00")  # HH:MM UTC
    schedule_weekday: Mapped[int] = mapped_column(Integer, default=0)  # 0 = Monday (weekly)
    address_count: Mapped[int] = mapped_column(Integer, default=0)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class NetworkScanRun(TenantMixin, Base):
    __tablename__ = "network_scan_runs"
    __table_args__ = (Index("ix_network_scan_runs_scan_queued", "scan_id", "queued_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("network_scans.id", ondelete="SET NULL", name="fk_network_scan_runs_scan_id"),
        nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128), default="")
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    # queued -> running -> succeeded | failed ; or cancelled
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    collector_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("directory_collectors.id", ondelete="SET NULL", name="fk_network_scan_runs_collector_id"),
        nullable=True)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The params as stored (no secrets): what was scanned.
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_batch_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Batch sequence numbers already ingested (idempotent per (scan_id, seq)).
    seqs: Mapped[list] = mapped_column(JSON, default=list)
    devices_seen: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class NetworkDevice(TenantMixin, Base):
    __tablename__ = "network_devices"
    __table_args__ = (Index("ix_network_devices_org_ip", "organization_id", "ip"),
                      Index("ix_network_devices_org_mac", "organization_id", "mac"))

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    ip: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str] = mapped_column(String(17), default="")  # aa:bb:cc:dd:ee:ff or ""
    mac_vendor: Mapped[str] = mapped_column(String(128), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")  # reverse DNS
    sys_name: Mapped[str] = mapped_column(String(255), default="")
    sys_descr: Mapped[str] = mapped_column(Text, default="")
    sys_object_id: Mapped[str] = mapped_column(String(128), default="")
    sys_location: Mapped[str] = mapped_column(String(255), default="")
    sys_contact: Mapped[str] = mapped_column(String(255), default="")
    uptime_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snmp_version: Mapped[str] = mapped_column(String(4), default="")  # v3 | v2c | "" (no SNMP)
    snmp_credential_id: Mapped[str] = mapped_column(String(32), default="")
    default_community: Mapped[str] = mapped_column(String(16), default="")  # public | private | ""
    alive_via: Mapped[list] = mapped_column(JSON, default=list)
    device_type: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    vendor: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    firmware: Mapped[str] = mapped_column(String(64), default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    # What the vulnerability matcher uses: part:vendor:product, version, update.
    family: Mapped[str] = mapped_column(String(32), default="")  # "IOS XE", "FortiOS", ... (normalize.py)
    cpe_product: Mapped[str] = mapped_column(String(64), default="")
    cpe_version: Mapped[str] = mapped_column(String(64), default="")
    cpe_update: Mapped[str] = mapped_column(String(32), default="")
    subnet: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("devices.id", ondelete="SET NULL"),
                                                  nullable=True, index=True)
    directory_computer_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("directory_computers.id", ondelete="SET NULL"), nullable=True)
    it_asset_id: Mapped[str | None] = mapped_column(String(32), ForeignKey("it_assets.id", ondelete="SET NULL"),
                                                    nullable=True, index=True)
    # The `assets` row (source "sensor") of the Linux runtime sensor running on this host, linked by host name. No
    # foreign key: assets have a composite (organization_id, id) key.
    sensor_asset_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Shadow row in the cloud-inventory `assets` table that findings hang on.
    asset_id: Mapped[str | None] = mapped_column(String(512), nullable=True)


class NetworkDevicePort(TenantMixin, Base):
    __tablename__ = "network_device_ports"
    __table_args__ = (UniqueConstraint("device_id", "port", "proto", name="uq_network_device_ports"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("network_devices.id", ondelete="CASCADE"),
                                           index=True)
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(3), default="tcp")
    service: Mapped[str] = mapped_column(String(64), default="")
    banner: Mapped[str] = mapped_column(String(200), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NetworkDeviceInterface(TenantMixin, Base):
    __tablename__ = "network_device_interfaces"
    __table_args__ = (UniqueConstraint("device_id", "if_index", name="uq_network_device_interfaces"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("network_devices.id", ondelete="CASCADE"),
                                           index=True)
    if_index: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(64), default="")
    descr: Mapped[str] = mapped_column(String(255), default="")
    mac: Mapped[str] = mapped_column(String(17), default="")
    oper_up: Mapped[bool] = mapped_column(Boolean, default=False)
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)


class NetworkFdb(TenantMixin, Base):
    """A MAC address a switch learned on one of its ports."""

    __tablename__ = "network_fdb"
    __table_args__ = (UniqueConstraint("device_id", "mac", "port_name", name="uq_network_fdb"),
                      Index("ix_network_fdb_org_mac", "organization_id", "mac"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("network_devices.id", ondelete="CASCADE"),
                                           index=True)
    mac: Mapped[str] = mapped_column(String(17))
    port_name: Mapped[str] = mapped_column(String(64), default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NetworkDeviceEvent(TenantMixin, Base):
    """History of a device: first seen, firmware changed, ports opened / closed, ..."""

    __tablename__ = "network_device_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("network_devices.id", ondelete="CASCADE"),
                                           index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(24))
    detail: Mapped[str] = mapped_column(String(512), default="")
    run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
