"""Sensor main loop: collectors -> enrich -> detect -> ship."""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import List, Optional

from .collectors import Collector, FileCollector, LibraryCollector, NetworkCollector, ProcessCollector
from .collectors.ebpf import EbpfCollector, ebpf_unavailable_reason
from .config import Config, load_config
from .detections import apply_detections
from .enrich import Enricher, K8sEnricher, detect_cloud
from .inventory import InventoryReporter, inventory_url
from .schema import RuntimeEvent
from .shipper import Shipper

log = logging.getLogger("runtime_sensor")


def build_collectors(cfg: Config) -> List[Collector]:
    collectors: List[Collector] = []
    use_ebpf = False
    if cfg.ebpf != "off" and ({"process", "network"} & set(cfg.collectors)):
        reason = ebpf_unavailable_reason()
        if reason is None:
            use_ebpf = True
        elif cfg.ebpf == "on":
            raise SystemExit(f"--ebpf=on but eBPF is unavailable: {reason}")
        else:
            log.info("eBPF unavailable (%s); using /proc polling", reason)
    if use_ebpf:
        collectors.append(EbpfCollector(cfg.proc_root, exec_events="process" in cfg.collectors,
                                        connect_events="network" in cfg.collectors))
    if "process" in cfg.collectors and not use_ebpf:
        collectors.append(ProcessCollector(cfg.proc_root, emit_existing=cfg.emit_existing))
    if "network" in cfg.collectors:
        # with eBPF, outbound connects come from the kernel hook; still poll for accepts
        collectors.append(NetworkCollector(cfg.proc_root, emit_existing=cfg.emit_existing,
                                           ignore_loopback=not cfg.include_loopback, outbound=not use_ebpf))
    if "file" in cfg.collectors:
        collectors.append(FileCollector(cfg.watches, host_root=cfg.host_root, mode=cfg.file_mode))
    if "library" in cfg.collectors:
        collectors.append(LibraryCollector(cfg.proc_root, interval=cfg.library_interval))
    return collectors


class Agent:
    def __init__(self, cfg: Config, shipper: Optional[Shipper] = None, collectors: Optional[List[Collector]] = None):
        self.cfg = cfg
        k8s = None
        if os.environ.get("KUBERNETES_SERVICE_HOST") or cfg.node_name:
            k8s = K8sEnricher(cfg.node_name, use_api=cfg.k8s_api)
        self.enricher = Enricher(cfg.sensor_id, cfg.host, proc_root=cfg.proc_root, host_root=cfg.host_root,
                                 k8s=k8s, cloud=detect_cloud(cfg.sys_root))
        self.shipper = shipper or Shipper(
            api_url=cfg.api_url, token=cfg.api_token, sensor_id=cfg.sensor_id, batch_size=cfg.batch_size,
            flush_interval=cfg.flush_interval, max_queue=cfg.max_queue, max_retries=cfg.max_retries,
            dry_run=cfg.dry_run, payload_format=cfg.payload_format, ca_file=cfg.ca_file)
        self.collectors = collectors if collectors is not None else build_collectors(cfg)
        # Host package inventory for vulnerability matching (EVENT_SCHEMA.md#package-inventory).
        self.inventory = InventoryReporter(
            url=cfg.inventory_url or inventory_url(cfg.api_url), sensor_id=cfg.sensor_id, host=cfg.host,
            host_root=cfg.host_root, cloud=self.enricher.cloud, interval=cfg.inventory_interval,
            send=self._send_inventory, dry_run=cfg.dry_run)
        self._stop = threading.Event()

    def _send_inventory(self, url: str, body: bytes) -> None:
        self.shipper._post(url, body, self.shipper._headers(), 60.0)

    def process(self, ev: RuntimeEvent) -> RuntimeEvent:
        self.enricher.enrich(ev)
        if self.cfg.detections:
            apply_detections(ev)
        self.shipper.enqueue(ev)
        return ev

    def run_cycle(self) -> int:
        n = 0
        for c in self.collectors:
            try:
                events = c.poll()
            except Exception:  # one broken collector must not take the sensor down
                log.exception("collector %s failed", c.name)
                continue
            for ev in events:
                self.process(ev)
                n += 1
        return n

    def stop(self, *_args) -> None:
        self._stop.set()

    def run(self) -> None:
        active: List[Collector] = []
        for c in self.collectors:
            try:
                c.setup()
                active.append(c)
            except Exception as exc:
                log.error("collector %s disabled: %s", c.name, exc)
        self.collectors = active
        log.info("sensor %s started: collectors=%s dry_run=%s endpoint=%s", self.cfg.sensor_id,
                 ",".join(c.name for c in active), self.cfg.dry_run, self.cfg.api_url)
        self.shipper.start()
        if not self.cfg.once:
            self.inventory.start()
        try:
            while not self._stop.is_set():
                started = time.monotonic()
                self.run_cycle()
                if self.cfg.once:
                    break
                self._stop.wait(max(0.0, self.cfg.poll_interval - (time.monotonic() - started)))
        finally:
            for c in self.collectors:
                try:
                    c.close()
                except Exception:
                    pass
            self.inventory.stop()
            self.shipper.stop()
            log.info("sensor stopped: %s", self.shipper.stats)


def main(argv: Optional[List[str]] = None) -> int:
    cfg = load_config(argv)
    logging.basicConfig(level=cfg.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    agent = Agent(cfg)
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()
    return 0
