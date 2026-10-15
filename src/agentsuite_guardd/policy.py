from __future__ import annotations
from dataclasses import dataclass
import json, posixpath
from .model import POLICY_VERSION, CAPABILITY, canonical, policy_digest


@dataclass(frozen=True)
class BackendPlan:
    policy_digest: str
    deny_write_paths: tuple[str, ...]
    operation_set: tuple[str, ...]
    target_id: str

    def object(self) -> dict:
        return {
            "denyWritePaths": list(self.deny_write_paths),
            "operationSet": list(self.operation_set),
            "policyDigest": self.policy_digest,
            "targetId": self.target_id,
        }

    @property
    def configuration_digest(self) -> str:
        return policy_digest(canonical(self.object()))


OPERATIONS = (
    "create",
    "link",
    "metadata",
    "mount-bypass",
    "rename",
    "symlink",
    "truncate",
    "unlink",
    "write",
    "writable-open",
)


def _pairs_hook(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key: {k}")
        d[k] = v
    return d


def compile_policy(data: bytes, expected_digest: str, target_id: str) -> BackendPlan:
    if policy_digest(data) != expected_digest:
        raise ValueError("policy digest mismatch")
    try:
        value = json.loads(data, object_pairs_hook=_pairs_hook)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("invalid policy JSON") from e
    if not isinstance(value, dict) or set(value) != {
        "version",
        "denyWritePaths",
        "requiredCapabilities",
    }:
        raise ValueError("policy fields are not exact")
    if value["version"] != POLICY_VERSION:
        raise ValueError("unsupported policy version")
    if value["requiredCapabilities"] != [CAPABILITY]:
        raise ValueError("unsupported required capability")
    paths = value["denyWritePaths"]
    if not isinstance(paths, list) or not paths:
        raise ValueError("denyWritePaths must be a nonempty list")
    if any(not isinstance(path, str) for path in paths):
        raise ValueError("invalid deny path")
    if paths != sorted(set(paths)):
        raise ValueError("policy paths are not canonical")
    for p in paths:
        if (
            not p.startswith("/")
            or p == "/"
            or posixpath.normpath(p) != p
            or "\x00" in p
        ):
            raise ValueError("invalid deny path")
    authoritative = canonical(value)
    if authoritative != data:
        raise ValueError("policy bytes are not canonical")
    return BackendPlan(expected_digest, tuple(paths), OPERATIONS, target_id)
