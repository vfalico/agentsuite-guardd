from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import time

from .backend import BackendError
from .model import Authorization, PROTOCOL, canonical, object_digest
from .policy import compile_policy
from .store import Conflict

PROVIDER_ID = "agentsuite-guardd/v1"


def format_time(value: float) -> str:
    """Format an epoch value exactly like Go's RFC3339Nano."""
    from datetime import datetime, timezone

    rendered = (
        datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    )
    if "." in rendered:
        head, fraction = rendered[:-1].split(".", 1)
        fraction = fraction.rstrip("0")
        rendered = f"{head}.{fraction}Z" if fraction else f"{head}Z"
    return rendered


def proof_message(proof: dict) -> bytes:
    fields = (
        PROTOCOL,
        proof["proofId"],
        proof["authorizationId"],
        proof["activationId"],
        proof["workloadId"],
        proof["providerId"],
        proof["audience"],
        proof["challenge"],
        proof["policyDigest"],
        proof["readBackDigest"],
        proof["keyId"],
        str(proof["epoch"]),
        proof["issuedAt"],
        proof["expiresAt"],
    )
    return "\x00".join(fields).encode()


def descriptor_message(descriptor: dict) -> bytes:
    fields = (
        PROTOCOL,
        descriptor["providerId"],
        descriptor["endpointId"],
        descriptor["algorithm"],
        descriptor["keyId"],
        descriptor["publicKey"],
        str(descriptor["epoch"]),
        descriptor["issuedAt"],
        descriptor["expiresAt"],
        ",".join(descriptor["protocolVersions"]),
        ",".join(descriptor["capabilities"]),
    )
    return "\x00".join(fields).encode()


def readback_digest(readback: dict) -> str:
    """Match the provider-neutral Orka readback digest contract exactly."""
    fields = (
        readback["activationId"],
        readback["targetId"],
        readback["policyDigest"],
        readback["configurationDigest"],
    )
    return "sha256:" + sha256("\x00".join(fields).encode()).hexdigest()


class Provider:
    def __init__(
        self,
        store,
        backend,
        signer,
        now=time.time,
        endpoint_id: str = "local-unix",
        epoch: int = 1,
    ):
        if epoch < 1:
            raise ValueError("provider epoch must be positive")
        self.store = store
        self.backend = backend
        self.signer = signer
        self.now = now
        self.epoch = epoch
        self.endpoint_id = endpoint_id

    def descriptor(self) -> dict:
        now = self.now()
        body = {
            "providerId": PROVIDER_ID,
            "endpointId": self.endpoint_id,
            "protocolVersions": [PROTOCOL],
            "capabilities": sorted(self.backend.capabilities),
            "epoch": self.epoch,
            "issuedAt": format_time(now),
            "expiresAt": format_time(now + 300),
            "keyId": self.signer.key_id,
            "algorithm": self.signer.algorithm,
            "publicKey": self.signer.public_key,
        }
        signature = b64encode(self.signer.sign_bytes(descriptor_message(body))).decode()
        return {**body, "signature": signature}

    def negotiate(self, required: list[str]) -> dict:
        unsupported = sorted(set(required) - set(self.backend.capabilities))
        if unsupported:
            raise ValueError("unsupported capabilities: " + ", ".join(unsupported))
        return {
            "protocolVersion": PROTOCOL,
            "capabilities": sorted(set(required)),
        }

    def _validate_authorization(self, authorization: Authorization) -> None:
        authorization.validate(self.now())
        if authorization.epoch != self.epoch:
            raise ValueError("authorization epoch does not match active provider epoch")
        self.negotiate(list(authorization.context.required_capabilities))

    def prepare(self, authorization: Authorization) -> dict:
        self._validate_authorization(authorization)
        context = authorization.context
        operation_id = "prepare:" + context.attempt_id
        plan = compile_policy(
            context.policy_bytes,
            context.policy_digest,
            context.workload_id,
        )
        value = {
            "preparationId": operation_id,
            "authorization": authorization.object(),
            "authorizationDigest": object_digest(authorization.object()),
            "contextDigest": object_digest(context.object()),
            "plan": plan.object(),
            "configurationDigest": plan.configuration_digest,
        }
        return self.store.reserve(operation_id, object_digest(value), value)

    def activate(self, authorization: Authorization, preparation_id: str) -> dict:
        self._validate_authorization(authorization)
        prepared_state, prepared = self.store.get(preparation_id)
        if prepared_state != "reserved":
            raise Conflict("preparation is not reserved")

        authorization_digest = object_digest(authorization.object())
        context_digest = object_digest(authorization.context.object())
        if prepared["authorizationDigest"] != authorization_digest:
            raise Conflict("preparation authorization mismatch")
        if prepared["contextDigest"] != context_digest:
            raise Conflict("preparation context mismatch")
        if prepared["authorization"] != authorization.object():
            raise Conflict("preparation authorization changed")

        context = authorization.context
        activation_id = "activation:" + context.attempt_id
        request = {
            "authorization": authorization.object(),
            "authorizationDigest": authorization_digest,
            "contextDigest": context_digest,
            "preparationId": preparation_id,
            "configurationDigest": prepared["configurationDigest"],
        }
        request_digest = object_digest(request)
        self.store.reserve(activation_id, request_digest, request)

        state, current = self.store.get(activation_id)
        if state in {"active", "released"}:
            if current.get("request") != request:
                raise Conflict("activation request identity conflict")
            return current

        plan = compile_policy(
            context.policy_bytes,
            context.policy_digest,
            context.workload_id,
        )
        if plan.object() != prepared["plan"]:
            raise Conflict("prepared plan does not match authorization")
        self.backend.activate(activation_id, plan)
        readback = self.backend.readback(activation_id)
        if (
            readback["configurationDigest"] != plan.configuration_digest
            or readback["targetId"] != context.workload_id
            or readback["policyDigest"] != context.policy_digest
        ):
            try:
                self.backend.detach(activation_id)
            except (
                BackendError
            ):  # AUDITED: DELIBERATE — preserve the original readback failure
                pass
            raise BackendError("independent readback mismatch")

        now = self.now()
        proof = {
            "proofId": "proof:" + context.attempt_id,
            "authorizationId": authorization.authorization_id,
            "activationId": activation_id,
            "workloadId": context.workload_id,
            "providerId": context.provider_id,
            "audience": context.audience,
            "challenge": context.challenge,
            "policyDigest": context.policy_digest,
            "readBackDigest": readback_digest(readback),
            "epoch": self.epoch,
            "issuedAt": format_time(now),
            "expiresAt": format_time(min(now + 120, authorization.expires_at)),
            "keyId": self.signer.key_id,
        }
        proof["signature"] = b64encode(
            self.signer.sign_bytes(proof_message(proof))
        ).decode()
        value = {"request": request, "readback": readback, "proof": proof}
        return self.store.transition(
            activation_id,
            request_digest,
            "reserved",
            "active",
            value,
        )

    def readback(self, activation_id: str) -> dict:
        return self.backend.readback(activation_id)

    def proof(self, activation_id: str) -> dict:
        state, value = self.store.get(activation_id)
        if state not in {"active", "released"}:
            raise ValueError("activation has no proof")
        return value["proof"]

    def release(
        self,
        activation_id: str,
        authorization_id: str,
        proof_id: str,
        release_id: str,
    ) -> dict:
        state, value = self.store.get(activation_id)
        proof = value["proof"]
        request = {
            "activationId": activation_id,
            "authorizationId": authorization_id,
            "proofId": proof_id,
            "releaseId": release_id,
        }
        if proof["authorizationId"] != authorization_id or proof["proofId"] != proof_id:
            raise Conflict("release binding mismatch")
        if state == "released":
            if value.get("release") != request:
                raise Conflict("release identity conflict")
            return value
        if state != "active":
            raise Conflict("activation is not releasable")

        self.store.reserve("release:" + release_id, object_digest(request), request)
        return self.store.transition(
            activation_id,
            object_digest(value["request"]),
            "active",
            "released",
            {**value, "release": request},
        )

    def status(self, activation_id: str) -> dict:
        state, value = self.store.get(activation_id)
        return {
            "activationId": activation_id,
            "state": state,
            "proofId": value.get("proof", {}).get("proofId"),
        }

    def reconcile(self, activation_id: str) -> dict:
        state, value = self.store.get(activation_id)
        if state not in {"active", "released"}:
            raise ValueError("activation cannot be reconciled")
        readback = self.backend.readback(activation_id)
        if readback_digest(readback) != value["proof"]["readBackDigest"]:
            raise BackendError("reconciliation readback mismatch")
        return {"state": state, "readback": readback}

    def reconcile_all(self) -> dict:
        results = {}
        all_activation_ids = self.store.list_ids("activation:")
        cleaning_ids = tuple(
            activation_id
            for activation_id in all_activation_ids
            if self.store.get(activation_id)[0] == "cleaning"
        )
        for activation_id in cleaning_ids:
            try:
                results[activation_id] = self.cleanup(activation_id)
            except (
                Exception
            ) as error:  # AUDITED: BROAD — startup quarantines interrupted cleanup failures
                results[activation_id] = {
                    "state": "quarantined",
                    "error": str(error),
                }
        if any(value["state"] == "quarantined" for value in results.values()):
            return results
        activation_ids = tuple(
            activation_id
            for activation_id in all_activation_ids
            if self.store.get(activation_id)[0] in {"active", "released"}
        )
        try:
            reconcile_inventory = getattr(self.backend, "reconcile_inventory", None)
            if reconcile_inventory:
                reconcile_inventory(activation_ids)
        except Exception as error:  # AUDITED: BROAD — startup must fail closed
            return {"backend-inventory": {"state": "quarantined", "error": str(error)}}
        for activation_id in activation_ids:
            try:
                results[activation_id] = self.reconcile(activation_id)
            except (
                Exception
            ) as error:  # AUDITED: BROAD — startup quarantines unknown failures
                results[activation_id] = {
                    "state": "quarantined",
                    "error": str(error),
                }
        return results

    def cleanup(self, activation_id: str) -> dict:
        state, value = self.store.get(activation_id)
        if state == "cleaned":
            return {"activationId": activation_id, "state": "cleaned"}
        if state == "released":
            self.store.transition(
                activation_id,
                object_digest(value["request"]),
                "released",
                "cleaning",
                value,
            )
        elif state != "cleaning":
            raise Conflict("activation must be released before cleanup")
        self.backend.detach(activation_id)
        self.store.transition(
            activation_id,
            object_digest(value["request"]),
            "cleaning",
            "cleaned",
            value,
        )
        return {"activationId": activation_id, "state": "cleaned"}
