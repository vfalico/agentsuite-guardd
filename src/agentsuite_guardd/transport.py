from __future__ import annotations
from base64 import b64decode
from datetime import datetime, timezone
import json, os, re, socket, struct, threading
from .model import Authorization, Context
from .provider import ProviderNotFound
from .protocol import TRANSPORT_VERSION
from .store import Conflict

MAX_FRAME = 1024 * 1024


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _exact_object(value, fields: set[str], name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(sorted(missing))}")
    return value


def _parse_time(value: str) -> float:
    if not isinstance(value, str):
        raise ValueError("authorization timestamp must be a string")
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z", value
    )
    if not match:
        raise ValueError("authorization timestamp must be RFC3339Nano UTC")
    fraction = (match.group(2) or "").ljust(6, "0")[:6]
    parsed = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc,
        microsecond=int(fraction or "0"),
    )
    return parsed.timestamp()


def authorization_from_object(value: dict) -> Authorization:
    value = _exact_object(
        value,
        {
            "authorizationId",
            "context",
            "issuedAt",
            "notBefore",
            "expiresAt",
            "epoch",
        },
        "authorization",
    )
    c = _exact_object(
        value["context"],
        {
            "requestId",
            "attemptId",
            "workloadId",
            "providerId",
            "audience",
            "challenge",
            "idempotencyKey",
            "policyDigest",
            "policyBytes",
            "requiredCapabilities",
        },
        "authorization context",
    )
    policy = c["policyBytes"]
    if not isinstance(policy, str):
        raise ValueError("policyBytes must be base64 text")
    raw = b64decode(policy, validate=True)
    capabilities = c["requiredCapabilities"]
    if not isinstance(capabilities, list) or any(
        not isinstance(capability, str) for capability in capabilities
    ):
        raise ValueError("requiredCapabilities must be a string array")
    if type(value["epoch"]) is not int:
        raise ValueError("authorization epoch must be an integer")
    ctx = Context(
        c["requestId"],
        c["attemptId"],
        c["workloadId"],
        c["providerId"],
        c["audience"],
        c["challenge"],
        c["idempotencyKey"],
        c["policyDigest"],
        raw,
        tuple(capabilities),
    )
    return Authorization(
        value["authorizationId"],
        ctx,
        _parse_time(value["issuedAt"]),
        _parse_time(value["notBefore"]),
        _parse_time(value["expiresAt"]),
        value["epoch"],
        value["issuedAt"],
        value["notBefore"],
        value["expiresAt"],
    )


def authorization_to_object(a: Authorization) -> dict:
    return a.object()


class UnixServer:
    def __init__(
        self, path: str, provider, allowed_uids: tuple[int, ...], mode: int = 0o660
    ):
        self.path = path
        self.provider = provider
        self.allowed_uids = set(allowed_uids)
        self.mode = mode
        self.socket = None
        self.stop_event = threading.Event()

    def serve_forever(self, ready=None):
        parent = os.path.dirname(self.path)
        os.makedirs(parent, mode=0o750, exist_ok=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:  # AUDITED: DELIBERATE — unlink is idempotent
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket = sock
        try:
            sock.bind(self.path)
            os.chmod(self.path, self.mode)
            sock.listen(32)
            sock.settimeout(0.25)
            if ready:
                ready.set()
            while not self.stop_event.is_set():
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                threading.Thread(
                    target=self._serve_connection, args=(conn,), daemon=True
                ).start()
        finally:
            sock.close()
            self.socket = None
            try:
                os.unlink(self.path)
            except FileNotFoundError:  # AUDITED: DELIBERATE — unlink is idempotent
                pass

    def shutdown(self):
        self.stop_event.set()

    def _serve_connection(self, conn):
        with conn:
            _pid, uid, _gid = struct.unpack(
                "3i",
                conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if uid not in self.allowed_uids:
                self._send(
                    conn,
                    {
                        "version": TRANSPORT_VERSION,
                        "ok": False,
                        "error": {
                            "code": "unauthenticated",
                            "message": "peer uid is not allowed",
                        },
                    },
                )
                return
            f = conn.makefile("rb")
            while True:
                line = f.readline(MAX_FRAME + 1)
                if not line:
                    return
                if len(line) > MAX_FRAME:
                    self._send(
                        conn, self._error("frame_too_large", "request exceeds limit")
                    )
                    return
                req = {}
                try:
                    req = json.loads(line, parse_constant=_reject_json_constant)
                    result = self.dispatch(req)
                    out = {
                        "version": TRANSPORT_VERSION,
                        "id": req.get("id"),
                        "ok": True,
                        "result": result,
                    }
                except Conflict as e:
                    out = self._error(
                        "conflict",
                        str(e),
                        req.get("id") if isinstance(req, dict) else None,
                    )
                except ProviderNotFound as e:
                    out = self._error(
                        "not_found",
                        str(e),
                        req.get("id") if isinstance(req, dict) else None,
                    )
                except (ValueError, KeyError, TypeError) as e:
                    out = self._error(
                        "invalid_request",
                        str(e),
                        req.get("id") if isinstance(req, dict) else None,
                    )
                except (
                    Exception
                ):  # AUDITED: BROAD — protocol boundary redacts internals and fails request closed
                    out = self._error(
                        "internal",
                        "operation failed",
                        req.get("id") if isinstance(req, dict) else None,
                    )
                self._send(conn, out)

    def _error(self, code, message, request_id=None):
        return {
            "version": TRANSPORT_VERSION,
            "id": request_id,
            "ok": False,
            "error": {"code": code, "message": message},
        }

    def _send(self, conn, value):
        conn.sendall(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )

    def dispatch(self, req):
        req = _exact_object(
            req, {"version", "id", "operation", "parameters"}, "request"
        )
        if req["version"] != TRANSPORT_VERSION:
            raise ValueError("unsupported transport version")
        if not isinstance(req["id"], str) or not req["id"]:
            raise ValueError("request id is required")
        if not isinstance(req["operation"], str) or not req["operation"]:
            raise ValueError("operation is required")
        op = req["operation"]
        p = req["parameters"]
        if op == "DiscoverDescriptor":
            _exact_object(p, set(), "parameters")
            return self.provider.descriptor()
        if op == "NegotiateCapabilities":
            p = _exact_object(p, {"requiredCapabilities"}, "parameters")
            return self.provider.negotiate(p["requiredCapabilities"])
        if op == "Prepare":
            p = _exact_object(p, {"authorization"}, "parameters")
            prepared = self.provider.prepare(
                authorization_from_object(p["authorization"])
            )
            return {"preparationId": prepared["preparationId"]}
        if op == "Activate":
            p = _exact_object(
                p, {"authorization", "preparationId"}, "parameters"
            )
            active = self.provider.activate(
                authorization_from_object(p["authorization"]), p["preparationId"]
            )
            return {
                "proof": {
                    "activationId": active["proof"]["activationId"],
                }
            }
        if op == "ReadBack":
            p = _exact_object(p, {"activationId"}, "parameters")
            return self.provider.readback(p["activationId"])
        if op == "GetProof":
            p = _exact_object(p, {"activationId"}, "parameters")
            return self.provider.proof(p["activationId"])
        if op == "Release":
            p = _exact_object(
                p,
                {"activationId", "authorizationId", "proofId", "releaseId"},
                "parameters",
            )
            self.provider.release(
                p["activationId"], p["authorizationId"], p["proofId"], p["releaseId"]
            )
            return {}
        if op == "GetStatus":
            p = _exact_object(p, {"activationId"}, "parameters")
            return {"state": self.provider.status(p["activationId"])["state"]}
        if op == "Reconcile":
            p = _exact_object(p, {"attemptId"}, "parameters")
            return {"state": self.provider.reconcile(p["attemptId"])["state"]}
        if op == "Cleanup":
            p = _exact_object(
                p, {"attemptId", "activationId", "cleanupId"}, "parameters"
            )
            self.provider.cleanup(
                p["attemptId"], p["activationId"], p["cleanupId"]
            )
            return {}
        raise ValueError("unknown operation")


class UnixClient:
    def __init__(self, path: str, timeout: float = 3):
        self.path = path
        self.timeout = timeout
        self.counter = 0

    def call(self, operation: str, parameters=None):
        self.counter += 1
        req = {
            "version": TRANSPORT_VERSION,
            "id": str(self.counter),
            "operation": operation,
            "parameters": parameters or {},
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
            line = s.makefile("rb").readline(MAX_FRAME + 1)
        if not line or len(line) > MAX_FRAME:
            raise RuntimeError("invalid response frame")
        value = json.loads(line)
        if not value.get("ok"):
            raise RuntimeError(
                value.get("error", {}).get("code", "provider error")
                + ": "
                + value.get("error", {}).get("message", "")
            )
        return value["result"]
