from __future__ import annotations

from base64 import b64encode
import time

from .backend import BackendError
from .model import Authorization, object_digest
from .policy import compile_policy
from .protocol import (
    PROTOCOL,
    authorization_digest_for_model,
    descriptor_message,
    format_time,
    proof_message,
    readback_digest,
)
from .store import Conflict

PROVIDER_ID = "agentsuite-guardd/v1"


class ProviderNotFound(Exception):
    pass


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

    def _get(self, operation_id: str) -> tuple[str, dict]:
        try:
            return self.store.get(operation_id)
        except KeyError as error:
            raise ProviderNotFound(f"{operation_id} is absent") from error

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
        wire_authorization = authorization.object()
        value = {
            "preparationId": operation_id,
            "authorization": wire_authorization,
            "authorizationDigest": authorization_digest_for_model(authorization),
            "contextDigest": object_digest(context.object()),
            "plan": plan.object(),
            "configurationDigest": plan.configuration_digest,
        }
        return self.store.reserve(operation_id, object_digest(value), value)

    def activate(self, authorization: Authorization, preparation_id: str) -> dict:
        self._validate_authorization(authorization)
        prepared_state, prepared = self._get(preparation_id)
        if prepared_state != "reserved":
            raise Conflict("preparation is not reserved")

        wire_authorization = authorization.object()
        auth_digest = authorization_digest_for_model(authorization)
        context_digest = object_digest(authorization.context.object())
        if prepared["authorizationDigest"] != auth_digest:
            raise Conflict("preparation authorization mismatch")
        if prepared["contextDigest"] != context_digest:
            raise Conflict("preparation context mismatch")
        if prepared["authorization"] != wire_authorization:
            raise Conflict("preparation authorization changed")

        context = authorization.context
        activation_id = "activation:" + context.attempt_id
        request = {
            "authorization": wire_authorization,
            "authorizationDigest": auth_digest,
            "contextDigest": context_digest,
            "preparationId": preparation_id,
            "configurationDigest": prepared["configurationDigest"],
        }
        request_digest = object_digest(request)
        self.store.reserve(activation_id, request_digest, request)

        state, current = self._get(activation_id)
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
            "authorizationDigest": auth_digest,
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
        self._get(activation_id)
        return self.backend.readback(activation_id)

    def proof(self, activation_id: str) -> dict:
        state, value = self._get(activation_id)
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
        state, value = self._get(activation_id)
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
        state, value = self._get(activation_id)
        return {
            "activationId": activation_id,
            "state": state,
            "proofId": value.get("proof", {}).get("proofId"),
        }

    def reconcile(self, attempt_id: str) -> dict:
        activation_id = "activation:" + attempt_id
        state, value = self._get(activation_id)
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
                _, value = self.store.get(activation_id)
                cleanup = value.get("cleanup")
                if not cleanup:
                    raise ValueError("cleaning activation has no cleanup identity")
                results[activation_id] = self.cleanup(
                    cleanup["attemptId"],
                    cleanup["activationId"],
                    cleanup["cleanupId"],
                )
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
                results[activation_id] = self.reconcile(
                    activation_id.removeprefix("activation:")
                )
            except (
                Exception
            ) as error:  # AUDITED: BROAD — startup quarantines unknown failures
                results[activation_id] = {
                    "state": "quarantined",
                    "error": str(error),
                }
        return results

    def cleanup(self, attempt_id: str, activation_id: str, cleanup_id: str) -> dict:
        if activation_id != "activation:" + attempt_id:
            raise Conflict("cleanup attempt and activation do not match")
        request = {
            "attemptId": attempt_id,
            "activationId": activation_id,
            "cleanupId": cleanup_id,
        }
        state, value = self._get(activation_id)
        if state == "cleaned":
            if value.get("cleanup") != request:
                raise Conflict("cleanup identity conflict")
            return {"activationId": activation_id, "state": "cleaned"}
        if state == "released":
            value = {**value, "cleanup": request}
            self.store.transition(
                activation_id,
                object_digest(value["request"]),
                "released",
                "cleaning",
                value,
            )
        elif state == "cleaning":
            if value.get("cleanup") != request:
                raise Conflict("cleanup identity conflict")
        else:
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
