from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import struct
import time

POLICY_VERSION = "agentsuite.policy/v1"
CAPABILITY = "filesystem/deny-write/v1"
PROTOCOL = "orka.enforcement-provider/v1"
DOMAIN = b"agentsuite-effective-policy\x00v1\x00"


def canonical(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for protocol-owned values."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def policy_digest(data: bytes) -> str:
    preimage = DOMAIN + struct.pack(">Q", len(data)) + data
    return "sha256:" + sha256(preimage).hexdigest()


def object_digest(value: object) -> str:
    return "sha256:" + sha256(canonical(value)).hexdigest()


def require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} is required")


@dataclass(frozen=True)
class Context:
    request_id: str
    attempt_id: str
    workload_id: str
    provider_id: str
    audience: str
    challenge: str
    idempotency_key: str
    policy_digest: str
    policy_bytes: bytes
    required_capabilities: tuple[str, ...] = (CAPABILITY,)

    def validate(self) -> None:
        for name in (
            "request_id",
            "attempt_id",
            "workload_id",
            "provider_id",
            "audience",
            "challenge",
            "idempotency_key",
            "policy_digest",
        ):
            require_text(name, getattr(self, name))
        if self.provider_id != "agentsuite-guardd/v1":
            raise ValueError("provider identity mismatch")
        if policy_digest(self.policy_bytes) != self.policy_digest:
            raise ValueError("policy digest mismatch")
        if self.required_capabilities != (CAPABILITY,):
            raise ValueError("unsupported required capabilities")

    def object(self) -> dict:
        return {
            "requestId": self.request_id,
            "attemptId": self.attempt_id,
            "workloadId": self.workload_id,
            "providerId": self.provider_id,
            "audience": self.audience,
            "challenge": self.challenge,
            "idempotencyKey": self.idempotency_key,
            "policyDigest": self.policy_digest,
            "policyBytes": self.policy_bytes.hex(),
            "requiredCapabilities": list(self.required_capabilities),
        }


@dataclass(frozen=True)
class Authorization:
    authorization_id: str
    context: Context
    issued_at: float
    not_before: float
    expires_at: float
    epoch: int

    def validate(self, now: float | None = None) -> None:
        current = time.time() if now is None else now
        require_text("authorization_id", self.authorization_id)
        self.context.validate()
        if self.epoch < 1:
            raise ValueError("authorization epoch is invalid")
        timestamps = (current, self.issued_at, self.not_before, self.expires_at)
        if not all(math.isfinite(value) for value in timestamps):
            raise ValueError("authorization timestamps must be finite")
        if not self.issued_at <= self.not_before < self.expires_at:
            raise ValueError("authorization interval is invalid")
        if (
            current < self.issued_at
            or current < self.not_before
            or current >= self.expires_at
        ):
            raise ValueError("authorization is not fresh")

    def object(self) -> dict:
        return {
            "authorizationId": self.authorization_id,
            "context": self.context.object(),
            "issuedAt": self.issued_at,
            "notBefore": self.not_before,
            "expiresAt": self.expires_at,
            "epoch": self.epoch,
        }
