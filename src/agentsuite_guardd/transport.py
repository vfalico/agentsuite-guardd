from __future__ import annotations
from base64 import b64decode, b64encode
from dataclasses import asdict
import json, os, socket, struct, threading
from .model import Authorization, Context
from .store import Conflict

MAX_FRAME = 1024 * 1024


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def authorization_from_object(value: dict) -> Authorization:
    c = value["context"]
    policy = c["policyBytes"]
    raw = b64decode(policy, validate=True) if isinstance(policy, str) else bytes(policy)
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
        tuple(c["requiredCapabilities"]),
    )
    return Authorization(
        value["authorizationId"],
        ctx,
        float(value["issuedAt"]),
        float(value["notBefore"]),
        float(value["expiresAt"]),
        int(value["epoch"]),
    )


def authorization_to_object(a: Authorization) -> dict:
    c = a.context
    return {
        "authorizationId": a.authorization_id,
        "issuedAt": a.issued_at,
        "notBefore": a.not_before,
        "expiresAt": a.expires_at,
        "epoch": a.epoch,
        "context": {
            "requestId": c.request_id,
            "attemptId": c.attempt_id,
            "workloadId": c.workload_id,
            "providerId": c.provider_id,
            "audience": c.audience,
            "challenge": c.challenge,
            "idempotencyKey": c.idempotency_key,
            "policyDigest": c.policy_digest,
            "policyBytes": b64encode(c.policy_bytes).decode(),
            "requiredCapabilities": list(c.required_capabilities),
        },
    }


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
            pid, uid, gid = struct.unpack(
                "3i",
                conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if uid not in self.allowed_uids:
                self._send(
                    conn,
                    {
                        "version": 1,
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
                        "version": 1,
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
            "version": 1,
            "id": request_id,
            "ok": False,
            "error": {"code": code, "message": message},
        }

    def _send(self, conn, value):
        conn.sendall(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )

    def dispatch(self, req):
        if req.get("version") != 1:
            raise ValueError("unsupported transport version")
        op = req.get("operation")
        p = req.get("parameters") or {}
        if op == "DiscoverDescriptor":
            return self.provider.descriptor()
        if op == "NegotiateCapabilities":
            return self.provider.negotiate(p["requiredCapabilities"])
        if op == "Prepare":
            return self.provider.prepare(authorization_from_object(p["authorization"]))
        if op == "Activate":
            return self.provider.activate(
                authorization_from_object(p["authorization"]), p["preparationId"]
            )
        if op == "ReadBack":
            return self.provider.readback(p["activationId"])
        if op == "GetProof":
            return self.provider.proof(p["activationId"])
        if op == "Release":
            return self.provider.release(
                p["activationId"], p["authorizationId"], p["proofId"], p["releaseId"]
            )
        if op == "GetStatus":
            return self.provider.status(p["activationId"])
        if op == "Reconcile":
            return self.provider.reconcile(p["activationId"])
        if op == "Cleanup":
            return self.provider.cleanup(p["activationId"])
        raise ValueError("unknown operation")


class UnixClient:
    def __init__(self, path: str, timeout: float = 3):
        self.path = path
        self.timeout = timeout
        self.counter = 0

    def call(self, operation: str, parameters=None):
        self.counter += 1
        req = {
            "version": 1,
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
