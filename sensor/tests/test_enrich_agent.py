import io
import json

from runtime_sensor.agent import Agent
from runtime_sensor.collectors import NetworkCollector, ProcessCollector
from runtime_sensor.config import load_config
from runtime_sensor.enrich import K8sEnricher, UserResolver, detect_cloud
from runtime_sensor.schema import validate_event_dict
from runtime_sensor.shipper import Shipper

POD_LIST = {"items": [{
    "metadata": {"namespace": "shop", "name": "web-7d9f", "uid": "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901"},
    "status": {"containerStatuses": [{"name": "nginx", "containerID": "containerd://" + "a" * 64}]},
}]}


def test_user_resolver(rootfs):
    users = UserResolver(str(rootfs))
    assert users.lookup(33) == "www-data" and users.lookup(4321) == "4321" and users.lookup(None) is None


def test_k8s_lookup_by_container_and_uid():
    k = K8sEnricher("node-1", use_api=False)
    k.load_pod_list(POD_LIST)
    info = k.lookup("a" * 64, None)
    assert (info.namespace, info.pod, info.container, info.node) == ("shop", "web-7d9f", "nginx", "node-1")
    info = k.lookup(None, "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901")
    assert info.pod == "web-7d9f"
    assert k.lookup(None, None).node == "node-1"


def test_detect_cloud_from_dmi(tmp_path, monkeypatch):
    monkeypatch.delenv("SENSOR_CLOUD_PROVIDER", raising=False)
    d = tmp_path / "class" / "dmi" / "id"
    d.mkdir(parents=True)
    (d / "sys_vendor").write_text("Amazon EC2\n")
    (d / "board_asset_tag").write_text("i-0abc1234def567890\n")
    c = detect_cloud(str(tmp_path))
    assert (c.provider, c.resource_id) == ("aws", "i-0abc1234def567890")
    monkeypatch.setenv("SENSOR_CLOUD_PROVIDER", "gcp")
    assert detect_cloud(str(tmp_path)).provider == "gcp"
    monkeypatch.delenv("SENSOR_CLOUD_PROVIDER")
    assert detect_cloud(str(tmp_path / "nope")).provider is None


def test_config_env_and_flags(monkeypatch):
    monkeypatch.setenv("SENSOR_API_URL", "https://cnapp.example/api/runtime/events")
    monkeypatch.setenv("SENSOR_API_TOKEN", "t0k")
    monkeypatch.setenv("SENSOR_ID", "sensor-a")
    monkeypatch.setenv("SENSOR_COLLECTORS", "process,file")
    cfg = load_config(["--poll-interval", "5", "--watch", "/etc/shadow:reads"])
    assert cfg.api_url == "https://cnapp.example/api/runtime/events"
    assert cfg.api_token == "t0k" and cfg.sensor_id == "sensor-a"
    assert cfg.collectors == ["process", "file"] and cfg.poll_interval == 5
    assert cfg.watches[0].watch_reads is True
    cfg = load_config(["--api-url", "http://other/x"])
    assert cfg.api_url == "http://other/x"


def test_agent_end_to_end_dry_run(fake_proc, rootfs, monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    cfg = load_config(["--dry-run", "--proc-root", fake_proc, "--host-root", str(rootfs),
                       "--node-name", "node-1", "--no-k8s-api"])
    out = io.StringIO()
    shipper = Shipper(dry_run=True, out=out, sensor_id=cfg.sensor_id)
    agent = Agent(cfg, shipper=shipper, collectors=[ProcessCollector(fake_proc, emit_existing=True),
                                                    NetworkCollector(fake_proc, emit_existing=True)])
    agent.enricher.k8s.load_pod_list(POD_LIST)
    assert agent.run_cycle() > 0
    shipper.flush()
    events = [json.loads(line) for line in out.getvalue().splitlines()]
    for e in events:
        assert validate_event_dict(e) == [], e
    sh = next(e for e in events if e["event_type"] == "process_exec" and e["process"]["pid"] == 4243)
    assert sh["container_id"] == "a" * 64
    assert sh["k8s"]["pod"] == "web-7d9f" and sh["k8s"]["namespace"] == "shop"
    assert sh["process"]["user"] == "www-data"
    assert sh["severity_hint"] == "high"
    assert {"shell_spawned_by_web_server", "download_and_execute"} <= set(sh["tags"])
    py = next(e for e in events if e["event_type"] == "process_exec" and e["process"]["pid"] == 5001)
    assert "hunter2" not in json.dumps(py)
    assert py["container_id"] == "b" * 64
