import os
import shutil

from runtime_sensor.collectors.file import (
    IN_CREATE, IN_ISDIR, IN_MODIFY, IN_OPEN, FileCollector, WatchSpec, mask_to_operation, parse_inotify_buffer,
    parse_watch_arg,
)
from runtime_sensor.collectors.libraries import (
    LibraryCollector, PackageIndex, is_interesting, parse_apk_installed, parse_dpkg_status, resolve_library,
    soname_guess,
)
from runtime_sensor.collectors.network import NetworkCollector, classify
from runtime_sensor.collectors.process import ProcessCollector, build_process_info
from runtime_sensor import procfs
import struct


# ---------------------------------------------------------------- process
def test_build_process_info_redacts(fake_proc):
    info = build_process_info(5001, fake_proc)
    assert info.name == "python3" and info.ppid == 1 and info.parent_name == "systemd"
    assert "hunter2" not in info.cmdline and "abc123" not in info.cmdline
    assert info.exe == "/usr/bin/python3.11"


def test_process_collector_baseline_then_new(fake_proc):
    c = ProcessCollector(fake_proc)
    assert c.poll() == []  # first poll is the baseline
    new = os.path.join(fake_proc, "7777")
    shutil.copytree(os.path.join(fake_proc, "4243"), new, symlinks=True)
    with open(os.path.join(new, "stat"), "w") as fh:
        fh.write("7777 (sh) S 4242 " + " ".join(["0"] * 17) + " 9999 " + " ".join(["0"] * 30))
    events = c.poll()
    assert [e.event_type for e in events] == ["process_exec"]
    assert events[0].process.pid == 7777 and events[0].process.parent_name == "nginx"
    assert c.poll() == []


def test_process_collector_pid_reuse_and_priv_change(fake_proc):
    c = ProcessCollector(fake_proc)
    c.poll()
    status = os.path.join(fake_proc, "5001", "status")
    text = open(status).read().replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t0\t0")
    open(status, "w").write(text)
    events = c.poll()
    assert [e.event_type for e in events] == ["privilege_change"]
    assert events[0].process.euid == 0 and "euid:1000->0" in events[0].tags


def test_process_collector_emit_existing(fake_proc):
    events = ProcessCollector(fake_proc, emit_existing=True).poll()
    assert {e.process.pid for e in events} == {1, 4242, 4243, 5001, 6001}


# ---------------------------------------------------------------- network
def test_classify_direction(fake_proc):
    entries = procfs.read_net_tcp(fake_proc)
    dirs = {(e.remote_ip, e.remote_port): d for e, d in classify(entries)}
    assert dirs[("192.168.1.100", 54321)] == "inbound"
    assert dirs[("93.184.216.34", 443)] == "outbound"
    assert dirs[("13.12.11.10", 3333)] == "outbound"  # SYN_SENT tracked


def test_network_collector_emit_existing(fake_proc):
    events = NetworkCollector(fake_proc, emit_existing=True).poll()
    by_dst = {(e.network.dst_ip, e.network.dst_port): e for e in events}
    out = by_dst[("93.184.216.34", 443)]
    assert out.event_type == "network_connect" and out.network.direction == "outbound"
    assert out.process.pid == 5001
    inbound = by_dst[("10.0.2.15", 80)]
    assert inbound.event_type == "network_accept" and inbound.network.src_ip == "192.168.1.100"
    assert inbound.process.pid == 4242
    assert ("127.0.0.1", 8080) not in by_dst  # loopback ignored by default


def test_network_collector_only_new(fake_proc):
    c = NetworkCollector(fake_proc)
    assert c.poll() == []
    assert c.poll() == []


def test_network_collector_inbound_only(fake_proc):
    events = NetworkCollector(fake_proc, emit_existing=True, outbound=False).poll()
    assert events and all(e.network.direction == "inbound" for e in events)


# ---------------------------------------------------------------- libraries
def test_is_interesting():
    assert is_interesting("/usr/lib/libssl.so.3")
    assert is_interesting("/x/site-packages/foo/bar.cpython-311.so")
    assert not is_interesting("/usr/bin/python3.11")
    assert not is_interesting("/usr/lib/locale/locale-archive")


def test_parse_dpkg_status(rootfs):
    v = parse_dpkg_status(open(rootfs / "var/lib/dpkg/status").read())
    assert v == {"libc6": "2.36-9+deb12u4", "libssl3": "3.0.11-1~deb12u2"}


def test_parse_apk(rootfs):
    idx = parse_apk_installed(open(rootfs / "lib/apk/db/installed").read())
    assert idx["/usr/lib/libcrypto.so.3"] == ("libcrypto3", "3.1.4-r5")
    assert idx["/lib/ld-musl-x86_64.so.1"] == ("musl", "1.2.4-r2")


def test_soname_guess():
    assert soname_guess("/usr/lib/libssl.so.3") == ("libssl", "3")
    assert soname_guess("/opt/libcustom-2.4.1.so") == ("libcustom", "2.4.1")
    assert soname_guess("/opt/libplain.so") == ("libplain", None)


def test_resolve_library(rootfs):
    idx = PackageIndex(str(rootfs))
    lib = resolve_library("/usr/lib/x86_64-linux-gnu/libssl.so.3", idx)
    assert (lib.package, lib.version, lib.source) == ("libssl3", "3.0.11-1~deb12u2", "dpkg")
    lib = resolve_library("/lib/x86_64-linux-gnu/libc.so.6", idx)  # usr-merge alias
    assert lib.package == "libc6"
    py = resolve_library("/usr/local/lib/python3.11/site-packages/numpy/core/_m.cpython-311.so", idx)
    assert (py.package, py.version, py.kind) == ("numpy", "1.26.4", "python_package")
    py = resolve_library("/usr/local/lib/python3.11/site-packages/numpy.libs/libopenblas.so", idx)
    assert py.package == "numpy"
    unk = resolve_library("/opt/app/libcustom-2.4.1.so", idx)
    assert (unk.package, unk.version, unk.source) == ("libcustom", "2.4.1", "soname")


def test_library_collector(fake_proc):
    c = LibraryCollector(fake_proc, interval=0)
    events = c.poll()
    libs = {e.library.path: e for e in events}
    assert len(libs) == 5  # python binary and locale archive are skipped
    assert libs["/usr/lib/x86_64-linux-gnu/libssl.so.3"].library.version == "3.0.11-1~deb12u2"
    assert all(e.process.pid == 5001 for e in events)
    assert c.poll() == []  # deduplicated until reemit_after


# ---------------------------------------------------------------- files
def test_mask_to_operation():
    assert mask_to_operation(IN_MODIFY) == "write"
    assert mask_to_operation(IN_CREATE | IN_ISDIR) == "create"
    assert mask_to_operation(IN_OPEN) == "open"
    assert mask_to_operation(0) is None


def test_parse_inotify_buffer():
    name = b"shadow\0\0"
    buf = struct.pack("iIII", 3, IN_OPEN, 0, len(name)) + name + struct.pack("iIII", 4, IN_MODIFY, 0, 0)
    assert parse_inotify_buffer(buf) == [(3, IN_OPEN, 0, "shadow"), (4, IN_MODIFY, 0, "")]


def test_parse_watch_arg():
    assert parse_watch_arg("/etc/shadow:reads") == WatchSpec("/etc/shadow", True)
    assert parse_watch_arg("/etc/passwd") == WatchSpec("/etc/passwd", False)


def _host(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    (tmp_path / "home" / "alice" / ".ssh").mkdir(parents=True)
    return tmp_path


def _collector(tmp_path, mode):
    return FileCollector([WatchSpec("/etc/passwd"), WatchSpec("/home/*/.ssh", watch_reads=True)],
                         host_root=str(tmp_path), mode=mode, dedupe_window=0)


def test_file_collector_poll_mode(tmp_path):
    host = _host(tmp_path)
    c = _collector(host, "poll")
    c.setup()
    assert c.poll() == []
    (host / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\nevil:x:0:0::/:/bin/sh\n")
    (host / "home" / "alice" / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA")
    events = c.poll()
    got = {(e.file.path, e.file.operation) for e in events}
    assert ("/etc/passwd", "write") in got
    assert ("/home/alice/.ssh/authorized_keys", "create") in got
    os.remove(host / "home" / "alice" / ".ssh" / "authorized_keys")
    assert {(e.file.path, e.file.operation) for e in c.poll()} == {("/home/alice/.ssh/authorized_keys", "delete")}
    c.close()


def test_file_collector_inotify_when_available(tmp_path):
    import sys
    import pytest
    if not sys.platform.startswith("linux"):
        pytest.skip("inotify is Linux-only")
    host = _host(tmp_path)
    c = _collector(host, "inotify")
    c.setup()
    assert c.backend == "inotify"
    (host / "home" / "alice" / ".ssh" / "id_rsa").write_text("x")
    # replace /etc/passwd atomically like `useradd` does
    tmp = host / "etc" / "passwd+"
    tmp.write_text("new")
    os.replace(tmp, host / "etc" / "passwd")
    got = {(e.file.path, e.file.operation) for e in c.poll()}
    assert ("/home/alice/.ssh/id_rsa", "create") in got
    assert ("/etc/passwd", "rename") in got
    # the replaced file is re-watched
    (host / "etc" / "passwd").write_text("again")
    assert ("/etc/passwd", "write") in {(e.file.path, e.file.operation) for e in c.poll()}
    c.close()
