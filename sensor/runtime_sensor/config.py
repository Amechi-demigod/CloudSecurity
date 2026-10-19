"""Configuration from CLI flags with environment-variable defaults."""
from __future__ import annotations

import argparse
import os
import socket
from dataclasses import dataclass, field
from typing import List, Optional

from .collectors.file import DEFAULT_WATCHES, WatchSpec, parse_watch_arg
from .shipper import DEFAULT_API_URL, DEFAULT_PAYLOAD_FORMAT, PAYLOAD_FORMATS

ALL_COLLECTORS = ("process", "network", "file", "library")


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    api_url: str = DEFAULT_API_URL
    api_token: Optional[str] = None
    ca_file: Optional[str] = None
    sensor_id: str = ""
    host: str = ""
    collectors: List[str] = field(default_factory=lambda: list(ALL_COLLECTORS))
    poll_interval: float = 2.0
    library_interval: float = 60.0
    dry_run: bool = False
    detections: bool = True
    ebpf: str = "auto"  # auto | on | off
    proc_root: str = "/proc"
    host_root: str = "/"
    sys_root: str = "/sys"
    watches: List[WatchSpec] = field(default_factory=lambda: list(DEFAULT_WATCHES))
    file_mode: str = "auto"
    batch_size: int = 100
    flush_interval: float = 5.0
    max_queue: int = 10_000
    max_retries: int = 5
    payload_format: str = DEFAULT_PAYLOAD_FORMAT
    k8s_api: bool = True
    node_name: Optional[str] = None
    emit_existing: bool = False
    include_loopback: bool = False
    once: bool = False
    log_level: str = "INFO"


def build_parser() -> argparse.ArgumentParser:
    e = os.environ.get
    p = argparse.ArgumentParser(
        prog="runtime-sensor",
        description="Observe-only Linux runtime security sensor for the CNAPP platform.",
    )
    p.add_argument("--api-url", default=e("SENSOR_API_URL", DEFAULT_API_URL),
                   help="ingest endpoint (env SENSOR_API_URL)")
    p.add_argument("--api-token", default=None,
                   help="bearer token (prefer env SENSOR_API_TOKEN so it is not visible in ps)")
    p.add_argument("--ca-file", default=e("SENSOR_CA_FILE") or e("CNAPP_CA_FILE"),
                   help="PEM CA certificate(s) of a private/internal CA to trust in addition to the system "
                        "store, e.g. an on-prem server's CA (env SENSOR_CA_FILE or CNAPP_CA_FILE)")
    p.add_argument("--sensor-id", default=e("SENSOR_ID"), help="sensor id (env SENSOR_ID, default hostname)")
    p.add_argument("--collectors", default=e("SENSOR_COLLECTORS", ",".join(ALL_COLLECTORS)),
                   help="comma list of process,network,file,library (env SENSOR_COLLECTORS)")
    p.add_argument("--poll-interval", type=float, default=float(e("SENSOR_POLL_INTERVAL", "2")),
                   help="seconds between /proc polls (env SENSOR_POLL_INTERVAL)")
    p.add_argument("--library-interval", type=float, default=float(e("SENSOR_LIBRARY_INTERVAL", "60")),
                   help="seconds between loaded-library scans (env SENSOR_LIBRARY_INTERVAL)")
    p.add_argument("--dry-run", action="store_true", default=_env_bool("SENSOR_DRY_RUN", False),
                   help="print events as JSON lines to stdout instead of POSTing (env SENSOR_DRY_RUN)")
    p.add_argument("--no-detections", dest="detections", action="store_false",
                   default=_env_bool("SENSOR_DETECTIONS", True),
                   help="disable local severity_hint/tags annotation (env SENSOR_DETECTIONS=false)")
    p.add_argument("--ebpf", choices=("auto", "on", "off"), default=e("SENSOR_EBPF", "auto"),
                   help="use eBPF (bcc) for exec/connect when available (env SENSOR_EBPF)")
    p.add_argument("--proc-root", default=e("SENSOR_PROC_ROOT", "/proc"),
                   help="procfs mount to read (e.g. /host/proc in a container)")
    p.add_argument("--host-root", default=e("SENSOR_HOST_ROOT", "/"),
                   help="where the host filesystem is mounted (e.g. /host) for file watches & passwd")
    p.add_argument("--sys-root", default=e("SENSOR_SYS_ROOT", "/sys"))
    p.add_argument("--watch", action="append", default=None, metavar="PATH[:reads]",
                   help="sensitive path to watch (repeatable; replaces defaults). Append ':reads' to also "
                        "report open(). Env SENSOR_WATCH_PATHS (comma separated)")
    p.add_argument("--file-mode", choices=("auto", "inotify", "poll"), default=e("SENSOR_FILE_MODE", "auto"))
    p.add_argument("--batch-size", type=int, default=int(e("SENSOR_BATCH_SIZE", "100")))
    p.add_argument("--flush-interval", type=float, default=float(e("SENSOR_FLUSH_INTERVAL", "5")))
    p.add_argument("--max-queue", type=int, default=int(e("SENSOR_MAX_QUEUE", "10000")))
    p.add_argument("--max-retries", type=int, default=int(e("SENSOR_MAX_RETRIES", "5")))
    p.add_argument("--payload-format", choices=PAYLOAD_FORMATS,
                   default=e("SENSOR_PAYLOAD_FORMAT", DEFAULT_PAYLOAD_FORMAT),
                   help="'cnapp-mvp' = translate to the current backend RuntimeEventIn (default); "
                        "'list' = JSON array of native v1.0 events; "
                        "'envelope' = {sensor_id, sent_at, events:[...]} (env SENSOR_PAYLOAD_FORMAT)")
    p.add_argument("--no-k8s-api", dest="k8s_api", action="store_false", default=_env_bool("SENSOR_K8S_API", True),
                   help="do not query the Kubernetes API for pod names")
    p.add_argument("--node-name", default=e("NODE_NAME") or e("SENSOR_NODE_NAME"))
    p.add_argument("--emit-existing", action="store_true", default=_env_bool("SENSOR_EMIT_EXISTING", False),
                   help="also report processes/connections already present at startup")
    p.add_argument("--include-loopback", action="store_true", default=False)
    p.add_argument("--once", action="store_true", help="run a single collection cycle and exit")
    p.add_argument("--log-level", default=e("SENSOR_LOG_LEVEL", "INFO"))
    return p


def load_config(argv: Optional[List[str]] = None) -> Config:
    args = build_parser().parse_args(argv)
    collectors = [c.strip() for c in args.collectors.split(",") if c.strip()]
    unknown = set(collectors) - set(ALL_COLLECTORS)
    if unknown:
        raise SystemExit(f"unknown collector(s): {', '.join(sorted(unknown))}")
    watch_args = args.watch
    if watch_args is None and os.environ.get("SENSOR_WATCH_PATHS"):
        watch_args = [w for w in os.environ["SENSOR_WATCH_PATHS"].split(",") if w.strip()]
    host = args.node_name or socket.gethostname()
    return Config(
        api_url=args.api_url,
        api_token=args.api_token or os.environ.get("SENSOR_API_TOKEN"),
        ca_file=args.ca_file or None,
        sensor_id=args.sensor_id or host,
        host=host,
        collectors=collectors,
        poll_interval=args.poll_interval,
        library_interval=args.library_interval,
        dry_run=args.dry_run,
        detections=args.detections,
        ebpf=args.ebpf,
        proc_root=args.proc_root.rstrip("/") or "/proc",
        host_root=args.host_root,
        sys_root=args.sys_root,
        watches=[parse_watch_arg(w.strip()) for w in watch_args] if watch_args else list(DEFAULT_WATCHES),
        file_mode=args.file_mode,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        max_queue=args.max_queue,
        max_retries=args.max_retries,
        payload_format=args.payload_format,
        k8s_api=args.k8s_api,
        node_name=args.node_name,
        emit_existing=args.emit_existing,
        include_loopback=args.include_loopback,
        once=args.once,
        log_level=args.log_level,
    )
