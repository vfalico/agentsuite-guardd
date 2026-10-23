#!/usr/bin/env python3
"""Guest capability preflight only; does not attach BPF or claim enforcement."""

import json
import os
from pathlib import Path


lsm_path = Path("/sys/kernel/security/lsm")
lsms = lsm_path.read_text().strip().split(",") if lsm_path.is_file() else []
checks = {
    "root": os.geteuid() == 0,
    "bpf_lsm": "bpf" in lsms,
    "kernel_btf": Path("/sys/kernel/btf/vmlinux").is_file(),
    "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
    "bpffs_available": Path("/sys/fs/bpf").is_dir(),
}
print(json.dumps({"classification": "guest preflight, native enforcement NOT RUN",
                  "checks": checks}, indent=2))
raise SystemExit(0 if all(checks.values()) else 1)
