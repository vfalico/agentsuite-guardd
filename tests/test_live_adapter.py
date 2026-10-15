import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from agentsuite_guardd.live_adapter import (
    _LINK_NAMES,
    LinuxBPFAdapter,
    LiveAdapterError,
)
from agentsuite_guardd.model import policy_digest
from agentsuite_guardd.policy import compile_policy


class FakeBPF:
    def __init__(self):
        self.maps = {}
        self.invalid_shows = set()

    @staticmethod
    def _bytes(arguments, marker, end_marker=None):
        start = arguments.index(marker) + 2
        end = arguments.index(end_marker) if end_marker else len(arguments)
        return bytes(int(value, 16) for value in arguments[start:end])

    def __call__(self, arguments):
        command = arguments[3]
        if command == "show":
            if arguments[5] in self.invalid_shows:
                return {}
            return [{"id": 1}]
        path = arguments[5]
        key = self._bytes(arguments, "key", "value" if command == "update" else None)
        if command == "update":
            value = self._bytes(arguments, "value")
            self.maps[(path, key)] = value
            return None
        if command == "lookup":
            if (path, key) not in self.maps:
                raise RuntimeError("missing kernel map entry")
            return {"value": [f"0x{byte:02x}" for byte in self.maps[(path, key)]]}
        if command == "delete":
            self.maps.pop((path, key), None)
            return None
        raise AssertionError(arguments)


class LinuxBPFAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.bpffs = root / "bpffs"
        for name in ("guarded_targets", "guarded_paths"):
            path = self.bpffs / "maps" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        for name in _LINK_NAMES:
            path = self.bpffs / "links" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.bpftool = root / "bpftool"
        self.bpftool.write_text("#!/bin/sh\nexit 0\n")
        self.bpftool.chmod(0o700)
        self.cgroups = root / "cgroup"
        self.target = self.cgroups / "job"
        self.target.mkdir(parents=True)
        (self.target / "cgroup.procs").touch()
        self.protected = root / "protected"
        self.protected.mkdir()
        (self.protected / "existing").write_text("value")
        self.unprotected = root / "unprotected"
        self.unprotected.mkdir()
        self.fake = FakeBPF()
        self.state = root / "adapter.json"
        self.adapter = LinuxBPFAdapter(
            str(self.state),
            bpffs_root=str(self.bpffs),
            cgroup_root=str(self.cgroups),
            bpftool=str(self.bpftool),
            runner=self.fake,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def plan(self):
        policy = json.dumps(
            {
                "denyWritePaths": [str(self.protected)],
                "requiredCapabilities": ["filesystem/deny-write/v1"],
                "version": "agentsuite.policy/v1",
            },
            separators=(",", ":"),
        ).encode()
        return compile_policy(
            policy,
            policy_digest(policy),
            "cgroup:" + str(self.target),
        ).object()

    def test_path_selective_map_install_readback_and_cleanup(self):
        desired = self.plan()
        self.assertEqual(self.adapter.capabilities, ("filesystem/deny-write/v1",))
        self.adapter.activate("activation", desired)
        observed = self.adapter.readback("activation")
        self.assertEqual(observed, desired)
        records = json.loads(self.state.read_text())["attachments"]["activation"]
        paths = {entry["path"] for entry in records["entries"]}
        self.assertIn(str(self.protected), paths)
        self.assertIn(str(self.protected / "existing"), paths)
        self.assertNotIn(str(self.unprotected), paths)
        self.adapter.detach("activation")
        self.assertEqual(self.adapter.list_attachments(), ())
        self.assertEqual(self.fake.maps, {})

    def test_independent_readback_rejects_missing_kernel_state(self):
        desired = self.plan()
        self.adapter.activate("activation", desired)
        target_keys = [
            key for key in self.fake.maps if key[0] == str(self.adapter.target_map)
        ]
        self.fake.maps.pop(target_keys[0])
        with self.assertRaises((LiveAdapterError, RuntimeError)):
            self.adapter.readback("activation")

    def test_restart_recovers_from_kernel_maps_not_desired_state_alone(self):
        desired = self.plan()
        self.adapter.activate("activation", desired)
        restarted = LinuxBPFAdapter(
            str(self.state),
            bpffs_root=str(self.bpffs),
            cgroup_root=str(self.cgroups),
            bpftool=str(self.bpftool),
            runner=self.fake,
        )
        self.assertEqual(restarted.readback("activation"), desired)
        path_keys = [
            key for key in self.fake.maps if key[0] == str(self.adapter.path_map)
        ]
        self.fake.maps[path_keys[0]] = struct.pack("=II", 0, 0)
        with self.assertRaises(LiveAdapterError):
            restarted.readback("activation")

    def test_capability_is_gated_when_any_program_link_is_absent(self):
        for name in _LINK_NAMES:
            path = self.bpffs / "links" / name
            path.unlink()
            adapter = LinuxBPFAdapter(
                str(Path(self.tmp.name) / f"missing-{name}.json"),
                bpffs_root=str(self.bpffs),
                cgroup_root=str(self.cgroups),
                bpftool=str(self.bpftool),
                runner=self.fake,
            )
            with self.subTest(name=name):
                self.assertEqual(adapter.capabilities, ())
            path.touch()

    def test_capability_is_gated_when_a_program_link_is_not_queryable(self):
        path = self.bpffs / "links" / "deny_mkdir"
        self.fake.invalid_shows.add(str(path))
        adapter = LinuxBPFAdapter(
            str(Path(self.tmp.name) / "invalid-link.json"),
            bpffs_root=str(self.bpffs),
            cgroup_root=str(self.cgroups),
            bpftool=str(self.bpftool),
            runner=self.fake,
        )
        self.assertEqual(adapter.capabilities, ())

    def test_target_outside_cgroup_root_is_rejected_before_map_updates(self):
        desired = self.plan()
        desired["targetId"] = "cgroup:" + str(self.unprotected)
        with self.assertRaises(LiveAdapterError):
            self.adapter.activate("activation", desired)
        self.assertEqual(self.fake.maps, {})


if __name__ == "__main__":
    unittest.main()
