from __future__ import annotations
from pathlib import Path
import json, os, tempfile, threading
from .model import canonical, policy_digest


class BackendError(Exception):
    pass


class MemoryBackend:
    """Deterministic backend used only by conformance tests."""

    def __init__(self):
        self.attachments = {}
        self.quarantined = False
        self.fail_readback = False
        self.fail_detach = False
        self.capabilities = ("filesystem/deny-write/v1",)

    def activate(self, activation_id, plan):
        if self.quarantined:
            raise BackendError("backend is quarantined")
        self.attachments[activation_id] = plan.object()
        return activation_id

    def readback(self, activation_id):
        if activation_id not in self.attachments:
            raise BackendError("attachment absent")
        value = dict(self.attachments[activation_id])
        if self.fail_readback:
            value["targetId"] = "mismatched"
        return _readback(activation_id, value)

    def detach(self, activation_id):
        if self.fail_detach:
            self.quarantined = True
            raise BackendError("detach ownership is ambiguous")
        self.attachments.pop(activation_id, None)

    def list_attachments(self):
        return tuple(sorted(self.attachments))


class PersistentBackend:
    """Crash-safe attachment registry used by the service and an OCI Gadget adapter.

    The registry is authoritative only after an adapter has attached all declared LSM
    programs. An optional adapter object must implement activate/readback/detach; its
    observed state is compared with this durable desired-state record on every read.
    """

    def __init__(self, path: str, adapter=None):
        self.path = Path(path)
        self.adapter = adapter
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"version": 1, "quarantined": False, "attachments": {}})
        self._load()

    @property
    def capabilities(self):
        """Advertise only capabilities the live adapter currently proves."""
        if not self.adapter:
            return ()
        # Re-evaluate the complete map/link set for every descriptor and
        # negotiation, so removal of a pinned link revokes advertisement.
        operational = getattr(self.adapter, "_operational", None)
        if callable(operational) and not operational():
            self.adapter.capabilities = ()
            return ()
        return tuple(getattr(self.adapter, "capabilities", ()))

    def reconcile_inventory(self, expected):
        """Detach safe orphans and reject missing durable or live state."""
        with self.lock:
            self._load()
            desired = set(self.data["attachments"])
            expected = set(expected)
            if not self.adapter:
                if desired or expected:
                    raise BackendError("live backend adapter is unavailable")
                return
            # Provider operations are the durable release authority. Desired
            # backend records absent there are safe orphans: detach target-first
            # and remove stale state. Missing state in the other direction is
            # unsafe and quarantines startup.
            for orphan in sorted(desired - expected):
                self.adapter.detach(orphan)
                del self.data["attachments"][orphan]
            if desired - expected:
                self._write(self.data)
            missing_desired = expected - desired
            if missing_desired:
                raise BackendError(
                    "backend desired state is missing activations: "
                    + ", ".join(sorted(missing_desired))
                )
            live = set(self.adapter.list_attachments())
            for orphan in sorted(live - expected):
                self.adapter.detach(orphan)
            missing = expected - live
            if missing:
                raise BackendError(
                    "live adapter is missing activations: " + ", ".join(sorted(missing))
                )

    def _load(self):
        try:
            self.data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise BackendError("invalid backend state") from e
        if self.data.get("version") != 1 or not isinstance(
            self.data.get("attachments"), dict
        ):
            raise BackendError("unsupported backend state")

    def _write(self, value):
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(value, f, sort_keys=True, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            try:
                os.unlink(tmp)
            except (
                FileNotFoundError
            ):  # AUDITED: DELIBERATE — atomic temp cleanup is idempotent
                pass

    def activate(self, activation_id, plan):
        with self.lock:
            self._load()
            if self.data["quarantined"]:
                raise BackendError("backend is quarantined")
            if "filesystem/deny-write/v1" not in self.capabilities:
                raise BackendError(
                    "no complete filesystem enforcement adapter is configured"
                )
            desired = plan.object()
            old = self.data["attachments"].get(activation_id)
            if old is not None and old != desired:
                raise BackendError("activation identity conflict")
            if self.adapter:
                self.adapter.activate(activation_id, desired)
            self.data["attachments"][activation_id] = desired
            self._write(self.data)
            return activation_id

    def readback(self, activation_id):
        with self.lock:
            self._load()
            value = self.data["attachments"].get(activation_id)
            if value is None:
                raise BackendError("attachment absent")
            if not self.adapter:
                raise BackendError("live backend adapter is unavailable")
            observed = self.adapter.readback(activation_id)
            if observed != value:
                raise BackendError("adapter readback differs from durable attachment")
            return _readback(activation_id, value)

    def detach(self, activation_id):
        with self.lock:
            self._load()
            try:
                if self.adapter:
                    self.adapter.detach(activation_id)
            except Exception as e:
                self.data["quarantined"] = True
                self._write(self.data)
                raise BackendError("detach ownership is ambiguous") from e
            self.data["attachments"].pop(activation_id, None)
            self._write(self.data)

    def list_attachments(self):
        with self.lock:
            self._load()
            return tuple(sorted(self.data["attachments"]))


def _readback(activation_id, value):
    return {
        "activationId": activation_id,
        "configurationDigest": policy_digest(canonical(value)),
        "targetId": value["targetId"],
        "policyDigest": value["policyDigest"],
    }
