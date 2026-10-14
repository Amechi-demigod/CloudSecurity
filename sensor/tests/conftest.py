import os
import shutil
import sys
from pathlib import Path

import pytest

SENSOR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SENSOR_DIR))

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# symlinks cannot be portably committed for /proc-like trees, so add them here
EXE = {1: "/usr/lib/systemd/systemd", 4242: "/usr/sbin/nginx", 4243: "/bin/sh",
       5001: "/usr/bin/python3.11", 6001: "/usr/bin/tricky (deleted)"}
NETNS = {1: "net:[4026531840]", 4242: "net:[4026532001]", 4243: "net:[4026532001]",
         5001: "net:[4026531840]", 6001: "net:[4026531840]"}
SOCKETS = {4242: [22222, 55555], 5001: [33333, 44444], 1: [11111]}


@pytest.fixture
def rootfs() -> Path:
    return FIXTURES / "rootfs"


@pytest.fixture
def fake_proc(tmp_path) -> str:
    """A copy of fixtures/proc with exe/ns/fd/root symlinks added."""
    root = tmp_path / "proc"
    shutil.copytree(FIXTURES / "proc", root)
    for pid, exe in EXE.items():
        d = root / str(pid)
        os.symlink(exe, d / "exe")
        (d / "ns").mkdir()
        os.symlink(NETNS[pid], d / "ns" / "net")
        os.symlink("mnt:[4026531841]" if NETNS[pid].endswith("840]") else "mnt:[4026532100]", d / "ns" / "mnt")
        (d / "fd").mkdir()
        os.symlink("/dev/null", d / "fd" / "0")
        for i, ino in enumerate(SOCKETS.get(pid, []), start=3):
            os.symlink(f"socket:[{ino}]", d / "fd" / str(i))
        os.symlink(str(FIXTURES / "rootfs"), d / "root")
        # per-process net view == the global fixture tables
        os.symlink(str(root / "net"), d / "net")
    return str(root)
