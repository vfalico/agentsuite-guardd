from __future__ import annotations

from base64 import b64decode
from datetime import datetime, timezone
from hashlib import sha256
import struct


PROTOCOL = "orka.enforcement-provider/v2"
TRANSPORT_VERSION = 2


def format_time(value: float) -> str:
    rendered = (
        datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    )
    if "." in rendered:
        head, fraction = rendered[:-1].split(".", 1)
        fraction = fraction.rstrip("0")
        rendered = f"{head}.{fraction}Z" if fraction else f"{head}Z"
    return rendered


class Transcript:
    def __init__(self) -> None:
        self.data = bytearray()

    def field(self, tag: int, value: bytes) -> None:
        self.data.extend(struct.pack(">HQ", tag, len(value)))
        self.data.extend(value)

    def text(self, tag: int, value: str) -> None:
        self.field(tag, value.encode())

    def number(self, tag: int, value: int) -> None:
        self.field(tag, struct.pack(">Q", value))


def encode_strings(values: list[str] | tuple[str, ...]) -> bytes:
    encoded = Transcript()
    encoded.number(1, len(values))
    for value in values:
        encoded.text(2, value)
    return bytes(encoded.data)


def transcript(domain: str, fields) -> bytes:
    encoded = Transcript()
    encoded.text(1, domain)
    encoded.number(2, 1)
    fields(encoded)
    return bytes(encoded.data)


def hash_transcript(domain: str, fields) -> str:
    return "sha256:" + sha256(transcript(domain, fields)).hexdigest()


def descriptor_message(descriptor: dict) -> bytes:
    def fields(encoded: Transcript) -> None:
        encoded.text(10, PROTOCOL)
        encoded.text(11, descriptor["providerId"])
        encoded.text(12, descriptor["endpointId"])
        encoded.text(13, descriptor["algorithm"])
        encoded.text(14, descriptor["keyId"])
        encoded.field(15, b64decode(descriptor["publicKey"], validate=True))
        encoded.number(16, descriptor["epoch"])
        encoded.text(17, descriptor["issuedAt"])
        encoded.text(18, descriptor["expiresAt"])
        encoded.field(19, encode_strings(descriptor["protocolVersions"]))
        encoded.field(20, encode_strings(descriptor["capabilities"]))

    return transcript("orka.enforcement.descriptor/v2", fields)


def authorization_digest(authorization: dict) -> str:
    context = authorization["context"]

    def fields(encoded: Transcript) -> None:
        encoded.text(10, authorization["authorizationId"])
        encoded.text(11, context["requestId"])
        encoded.text(12, context["attemptId"])
        encoded.text(13, context["workloadId"])
        encoded.text(14, context["providerId"])
        encoded.text(15, context["audience"])
        encoded.text(16, context["challenge"])
        encoded.text(17, context["idempotencyKey"])
        encoded.text(18, context["policyDigest"])
        encoded.field(19, b64decode(context["policyBytes"], validate=True))
        encoded.field(20, encode_strings(context["requiredCapabilities"]))
        encoded.text(21, authorization["issuedAt"])
        encoded.text(22, authorization["notBefore"])
        encoded.text(23, authorization["expiresAt"])
        encoded.number(24, authorization["epoch"])

    return hash_transcript("orka.enforcement.authorization/v2", fields)


def authorization_digest_for_model(authorization) -> str:
    return authorization_digest(authorization.object())


def readback_digest(readback: dict) -> str:
    def fields(encoded: Transcript) -> None:
        encoded.text(10, readback["activationId"])
        encoded.text(11, readback["targetId"])
        encoded.text(12, readback["policyDigest"])
        encoded.text(13, readback["configurationDigest"])

    return hash_transcript("orka.enforcement.readback/v2", fields)


def proof_message(proof: dict) -> bytes:
    def fields(encoded: Transcript) -> None:
        encoded.text(10, PROTOCOL)
        encoded.text(11, proof["proofId"])
        encoded.text(12, proof["authorizationId"])
        encoded.text(13, proof["authorizationDigest"])
        encoded.text(14, proof["activationId"])
        encoded.text(15, proof["workloadId"])
        encoded.text(16, proof["providerId"])
        encoded.text(17, proof["audience"])
        encoded.text(18, proof["challenge"])
        encoded.text(19, proof["policyDigest"])
        encoded.text(20, proof["readBackDigest"])
        encoded.text(21, proof["keyId"])
        encoded.number(22, proof["epoch"])
        encoded.text(23, proof["issuedAt"])
        encoded.text(24, proof["expiresAt"])

    return transcript("orka.enforcement.proof/v2", fields)
