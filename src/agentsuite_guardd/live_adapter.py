from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import threading

from .model import canonical
from .policy import OPERATIONS

CAPABILITY = "filesystem/deny-write/v1"
_OPERATION_MASK = sum(1 << (index + 1) for index in range(len(OPERATIONS)))
_LINK_NAMES = (
    "deny_writable_open",
    "deny_write",
    "deny_truncate",
    "deny_create",
    "deny_mkdir",
    "deny_mknod",
    "deny_link",
    "deny_metadata",
    "deny_setxattr",
    "deny_removexattr",
    "deny_rename",
    "deny_symlink",
    "deny_unlink",
    "deny_rmdir",
    "deny_mount_bypass",
)


class LiveAdapterError(RuntimeError):
    pass


@dataclass(frozen=True)
class _Identity:
    device: int
    inode: int


class LinuxBPFAdapter:
    """Path-selective BPF-LSM adapter with kernel-map readback.

    The adapter is operational only when all fifteen LSM links and both pinned maps
    exist. Policy entries are installed before the target cgroup is enabled,
    making attachment fail closed. Readback looks up every entry in the live
    kernel maps and restats every source path; the desired-state file is not
    accepted as evidence of attachment by itself.
    """

    capabilities: tuple[str, ...]

    def __init__(
        self,
        state_path: str,
        bpffs_root: str = "/sys/fs/bpf/agentsuite-guardd",
        cgroup_root: str = "/sys/fs/cgroup",
        bpftool: str = "/usr/sbin/bpftool",
        runner=None,
    ):
        self.state_path = Path(state_path)
        self.bpffs_root = Path(bpffs_root)
        self.cgroup_root = Path(cgroup_root).resolve()
        self.bpftool = bpftool
        self.runner = runner or self._run
        self.lock = threading.RLock()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            self._write({"version": 1, "attachments": {}})
        self._load()
        self.capabilities = (CAPABILITY,) if self._operational() else ()

    @property
    def target_map(self) -> Path:
        return self.bpffs_root / "maps/guarded_targets"

    @property
    def path_map(self) -> Path:
        return self.bpffs_root / "maps/guarded_paths"

    def _run(self, args: list[str]) -> object:
        completed = subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        parsed = json.loads(completed.stdout) if completed.stdout.strip() else None
        # bpftool 7.7 prints valid pinned-link JSON but exits 255. Treat a
        # structured non-error object as success; all other nonzero results fail.
        if completed.returncode and (
            not isinstance(parsed, (dict, list))
            or isinstance(parsed, dict)
            and "error" in parsed
        ):
            raise subprocess.CalledProcessError(
                completed.returncode, args, completed.stdout, completed.stderr
            )
        return parsed

    def _command(self, *args: str) -> object:
        return self.runner([self.bpftool, "-j", *args])

    def _operational(self) -> bool:
        if not (shutil.which(self.bpftool) or Path(self.bpftool).is_file()):
            return False
        required = [self.target_map, self.path_map]
        required.extend(self.bpffs_root / "links" / name for name in _LINK_NAMES)
        if not all(path.exists() for path in required):
            return False
        try:
            for path in required[:2]:
                info = self._command("map", "show", "pinned", str(path))
                if not info:
                    return False
            for path in required[2:]:
                info = self._command("link", "show", "pinned", str(path))
                if not info:
                    return False
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
        return True

    def _load(self) -> None:
        try:
            self.data = json.loads(self.state_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise LiveAdapterError("invalid live-adapter state") from error
        if self.data.get("version") != 1 or not isinstance(
            self.data.get("attachments"), dict
        ):
            raise LiveAdapterError("unsupported live-adapter state")

    def _write(self, value: dict) -> None:
        descriptor, temporary = tempfile.mkstemp(
            prefix=self.state_path.name + ".", dir=self.state_path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, sort_keys=True, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.state_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:  # AUDITED: DELIBERATE — atomic cleanup
                pass

    def _target(self, target_id: str) -> tuple[Path, int]:
        if not target_id.startswith("cgroup:"):
            raise LiveAdapterError("targetId must use cgroup:/absolute/path")
        requested = Path(target_id[7:])
        if not requested.is_absolute():
            raise LiveAdapterError("cgroup target must be absolute")
        resolved = requested.resolve(strict=True)
        try:
            resolved.relative_to(self.cgroup_root)
        except ValueError as error:
            raise LiveAdapterError("cgroup target escapes configured root") from error
        stat_result = resolved.stat()
        if not (resolved / "cgroup.procs").is_file():
            raise LiveAdapterError("target is not a cgroup v2 directory")
        return resolved, stat_result.st_ino

    @staticmethod
    def _kernel_device(device: int) -> int:
        major = os.major(device)
        minor = os.minor(device)
        # Linux dev_t as observed by BPF_CORE_READ(inode, i_sb, s_dev)
        # uses MINORBITS=20, unlike userspace st_dev's compact encoding.
        return (major << 20) | minor

    @classmethod
    def _identity(cls, path: Path) -> _Identity:
        result = path.stat(follow_symlinks=False)
        return _Identity(cls._kernel_device(result.st_dev), result.st_ino)

    def _expand(self, roots: list[str]) -> list[tuple[str, _Identity]]:
        observed: dict[tuple[int, int], str] = {}
        for raw_root in roots:
            root = Path(raw_root)
            identity = self._identity(root)
            observed[(identity.device, identity.inode)] = str(root)
            if root.is_dir():
                for directory, names, files in os.walk(root, followlinks=False):
                    for name in names + files:
                        path = Path(directory) / name
                        identity = self._identity(path)
                        observed[(identity.device, identity.inode)] = str(path)
        return [
            (path, _Identity(device, inode))
            for (device, inode), path in sorted(observed.items())
        ]

    @staticmethod
    def _hex(value: bytes) -> list[str]:
        return [f"{byte:02x}" for byte in value]

    def _update(self, map_path: Path, key: bytes, value: bytes) -> None:
        self._command(
            "map",
            "update",
            "pinned",
            str(map_path),
            "key",
            "hex",
            *self._hex(key),
            "value",
            "hex",
            *self._hex(value),
        )

    def _delete(self, map_path: Path, key: bytes, absent_ok: bool = True) -> None:
        try:
            self._command(
                "map", "delete", "pinned", str(map_path), "key", "hex", *self._hex(key)
            )
        except subprocess.CalledProcessError:
            if not absent_ok:
                raise

    def _lookup(self, map_path: Path, key: bytes) -> bytes:
        result = self._command(
            "map", "lookup", "pinned", str(map_path), "key", "hex", *self._hex(key)
        )
        if not isinstance(result, dict) or not isinstance(result.get("value"), list):
            raise LiveAdapterError("unexpected bpftool map lookup response")
        return bytes(
            int(value, 16) if isinstance(value, str) else value
            for value in result["value"]
        )

    @staticmethod
    def _target_key(cgroup_id: int) -> bytes:
        return struct.pack("=Q", cgroup_id)

    @staticmethod
    def _target_value(generation: int) -> bytes:
        return struct.pack("=Q", generation)

    @staticmethod
    def _path_key(generation: int, identity: _Identity) -> bytes:
        return struct.pack("=QQQ", generation, identity.device, identity.inode)

    @staticmethod
    def _path_value() -> bytes:
        return struct.pack("=II", _OPERATION_MASK, 0)

    @staticmethod
    def _generation(activation_id: str, desired: dict) -> int:
        digest = sha256(activation_id.encode() + b"\0" + canonical(desired)).digest()
        value = int.from_bytes(digest[:8], byteorder="little")
        return value or 1

    def activate(self, activation_id: str, desired: dict) -> None:
        with self.lock:
            if not self._operational():
                self.capabilities = ()
                raise LiveAdapterError("complete BPF-LSM adapter is not operational")
            self._load()
            _, cgroup_id = self._target(desired["targetId"])
            entries = self._expand(desired["denyWritePaths"])
            generation = self._generation(activation_id, desired)
            record = {
                "desired": desired,
                "cgroupId": cgroup_id,
                "generation": generation,
                "entries": [
                    {"path": path, "device": identity.device, "inode": identity.inode}
                    for path, identity in entries
                ],
            }
            previous = self.data["attachments"].get(activation_id)
            if previous is not None and previous != record:
                raise LiveAdapterError("live attachment identity conflict")
            installed: list[bytes] = []
            try:
                for _, identity in entries:
                    key = self._path_key(generation, identity)
                    self._update(self.path_map, key, self._path_value())
                    installed.append(key)
                self._update(
                    self.target_map,
                    self._target_key(cgroup_id),
                    self._target_value(generation),
                )
            except Exception:
                for key in installed:
                    self._delete(self.path_map, key)
                raise
            self.data["attachments"][activation_id] = record
            self._write(self.data)

    def readback(self, activation_id: str) -> dict:
        with self.lock:
            if not self._operational():
                self.capabilities = ()
                raise LiveAdapterError("BPF-LSM attachment is no longer operational")
            self._load()
            record = self.data["attachments"].get(activation_id)
            if record is None:
                raise LiveAdapterError("live attachment is absent")
            cgroup_id = int(record["cgroupId"])
            generation = int(record["generation"])
            if self._lookup(
                self.target_map, self._target_key(cgroup_id)
            ) != self._target_value(generation):
                raise LiveAdapterError("kernel target map differs from desired state")
            for entry in record["entries"]:
                identity = self._identity(Path(entry["path"]))
                expected = _Identity(int(entry["device"]), int(entry["inode"]))
                if identity != expected:
                    raise LiveAdapterError("protected path identity changed")
                key = self._path_key(generation, expected)
                if self._lookup(self.path_map, key) != self._path_value():
                    raise LiveAdapterError(
                        "kernel path-policy map differs from desired state"
                    )
            return dict(record["desired"])

    def detach(self, activation_id: str) -> None:
        with self.lock:
            self._load()
            record = self.data["attachments"].get(activation_id)
            if record is None:
                return
            cgroup_key = self._target_key(int(record["cgroupId"]))
            self._delete(self.target_map, cgroup_key)
            for entry in record["entries"]:
                identity = _Identity(int(entry["device"]), int(entry["inode"]))
                self._delete(
                    self.path_map,
                    self._path_key(int(record["generation"]), identity),
                )
            del self.data["attachments"][activation_id]
            self._write(self.data)

    def list_attachments(self) -> tuple[str, ...]:
        with self.lock:
            self._load()
            return tuple(sorted(self.data["attachments"]))
