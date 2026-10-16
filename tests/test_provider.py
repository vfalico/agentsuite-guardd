import json, tempfile, time, unittest
from agentsuite_guardd.backend import MemoryBackend, BackendError
from agentsuite_guardd.crypto import Signer
from base64 import b64decode
from agentsuite_guardd.model import (
    Authorization,
    Context,
    canonical,
    object_digest,
    policy_digest,
)
from agentsuite_guardd.provider import (
    Provider,
    ProviderNotFound,
    proof_message,
    descriptor_message,
)
from agentsuite_guardd.store import Store, Conflict


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.policy = (
            b'{"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        d = policy_digest(self.policy)
        self.context = Context(
            "request",
            "attempt",
            "workload",
            "agentsuite-guardd/v1",
            "orka",
            "challenge",
            "idem",
            d,
            self.policy,
        )
        self.auth = Authorization("authorization", self.context, 999, 999, 1100, 1)
        self.backend = MemoryBackend()
        self.signer = Signer(b"x" * 32)
        self.p = Provider(Store(), self.backend, self.signer, lambda: self.now)

    def test_lifecycle_and_idempotency(self):
        a = self.p.prepare(self.auth)
        self.assertEqual(a, self.p.prepare(self.auth))
        active = self.p.activate(self.auth, a["preparationId"])
        self.assertTrue(self.p.proof(active["proof"]["activationId"])["signature"])
        released = self.p.release(
            active["proof"]["activationId"],
            "authorization",
            active["proof"]["proofId"],
            "release",
        )
        self.assertEqual(
            released,
            self.p.release(
                active["proof"]["activationId"],
                "authorization",
                active["proof"]["proofId"],
                "release",
            ),
        )
        self.assertEqual(
            self.p.reconcile(self.context.attempt_id)["state"], "released"
        )

    def test_descriptor_and_proof_use_ed25519(self):
        descriptor = self.p.descriptor()
        self.assertEqual(descriptor["algorithm"], "ed25519")
        self.assertEqual(len(b64decode(descriptor["publicKey"])), 32)
        body = dict(descriptor)
        signature = body.pop("signature")
        self.signer._key.public_key().verify(
            b64decode(signature), descriptor_message(body)
        )
        a = self.p.prepare(self.auth)
        active = self.p.activate(self.auth, a["preparationId"])
        proof = dict(active["proof"])
        signature = b64decode(proof.pop("signature"))
        self.signer._key.public_key().verify(signature, proof_message(proof))

    def test_policy_mutation_rejected(self):
        bad = Context(**{**self.context.__dict__, "policy_bytes": self.policy + b" "})
        a = Authorization("authorization", bad, 999, 999, 1100, 1)
        with self.assertRaises(ValueError):
            self.p.prepare(a)

    def test_readback_mismatch_rolls_back(self):
        a = self.p.prepare(self.auth)
        self.backend.fail_readback = True
        with self.assertRaises(BackendError):
            self.p.activate(self.auth, a["preparationId"])
        self.assertFalse(self.backend.attachments)

    def test_ambiguous_rollback_quarantines(self):
        a = self.p.prepare(self.auth)
        self.backend.fail_readback = True
        self.backend.fail_detach = True
        with self.assertRaises(BackendError):
            self.p.activate(self.auth, a["preparationId"])
        self.assertTrue(self.backend.quarantined)

    def test_conflicting_retry(self):
        self.p.store.reserve("x", "one", {"a": 1})
        with self.assertRaises(Conflict):
            self.p.store.reserve("x", "two", {"a": 2})

    def test_changed_release_retries_conflict_even_after_restart(self):
        with tempfile.NamedTemporaryFile() as f:
            first = Provider(Store(f.name), self.backend, self.signer, lambda: self.now)
            prepared = first.prepare(self.auth)
            active = first.activate(self.auth, prepared["preparationId"])
            proof = active["proof"]
            first.release(
                proof["activationId"],
                self.auth.authorization_id,
                proof["proofId"],
                "release",
            )
            restarted = Provider(
                Store(f.name), self.backend, self.signer, lambda: self.now
            )
            self.assertEqual(
                restarted.release(
                    proof["activationId"],
                    self.auth.authorization_id,
                    proof["proofId"],
                    "release",
                )["release"]["releaseId"],
                "release",
            )
            for authorization, proof_id, release_id in (
                ("wrong", proof["proofId"], "release"),
                (self.auth.authorization_id, "wrong", "release"),
                (self.auth.authorization_id, proof["proofId"], "changed"),
            ):
                with self.subTest(
                    authorization=authorization, proof=proof_id, release=release_id
                ), self.assertRaises(Conflict):
                    restarted.release(
                        proof["activationId"], authorization, proof_id, release_id
                    )

    def test_changed_cleanup_retries_conflict_even_after_restart(self):
        with tempfile.NamedTemporaryFile() as f:
            first = Provider(Store(f.name), self.backend, self.signer, lambda: self.now)
            prepared = first.prepare(self.auth)
            active = first.activate(self.auth, prepared["preparationId"])
            proof = active["proof"]
            first.release(
                proof["activationId"],
                self.auth.authorization_id,
                proof["proofId"],
                "release",
            )
            first.cleanup(
                self.context.attempt_id,
                proof["activationId"],
                "cleanup",
            )
            restarted = Provider(
                Store(f.name), self.backend, self.signer, lambda: self.now
            )
            self.assertEqual(
                restarted.cleanup(
                    self.context.attempt_id,
                    proof["activationId"],
                    "cleanup",
                )["state"],
                "cleaned",
            )
            for attempt_id, activation_id, cleanup_id in (
                ("wrong", proof["activationId"], "cleanup"),
                (self.context.attempt_id, proof["activationId"], "changed"),
            ):
                with self.subTest(
                    attempt=attempt_id,
                    activation=activation_id,
                    cleanup=cleanup_id,
                ), self.assertRaises(Conflict):
                    restarted.cleanup(attempt_id, activation_id, cleanup_id)
            with self.assertRaises(ProviderNotFound):
                restarted.cleanup(
                    "missing",
                    "activation:missing",
                    "cleanup",
                )

    def test_restart_reconciliation_fails_closed_when_backend_is_missing(self):
        with tempfile.NamedTemporaryFile() as f:
            backend = MemoryBackend()
            first = Provider(Store(f.name), backend, self.signer, lambda: self.now)
            prepared = first.prepare(self.auth)
            active = first.activate(self.auth, prepared["preparationId"])
            activation = active["proof"]["activationId"]
            backend.attachments.clear()
            restarted = Provider(Store(f.name), backend, self.signer, lambda: self.now)
            result = restarted.reconcile_all()
            self.assertEqual(result[activation]["state"], "quarantined")

    def test_stale_authorization(self):
        self.now = 1200
        with self.assertRaises(ValueError):
            self.p.prepare(self.auth)

    def test_authorization_rejects_nonfinite_and_incoherent_timestamps(self):
        for field in ("issued_at", "not_before", "expires_at"):
            for value in (float("nan"), float("inf"), float("-inf")):
                changed = Authorization(
                    **{**self.auth.__dict__, field: value}
                )
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    ValueError, "finite"
                ):
                    changed.validate(self.now)
        for issued_at, not_before, expires_at in (
            (1001, 1000, 1100),
            (999, 1100, 1100),
            (999, 1101, 1100),
        ):
            changed = Authorization(
                **{
                    **self.auth.__dict__,
                    "issued_at": issued_at,
                    "not_before": not_before,
                    "expires_at": expires_at,
                }
            )
            with self.subTest(
                issued_at=issued_at,
                not_before=not_before,
                expires_at=expires_at,
            ), self.assertRaisesRegex(ValueError, "interval"):
                changed.validate(self.now)

    def test_startup_completes_cleanup_interrupted_before_or_after_detach(self):
        for detached in (False, True):
            backend = MemoryBackend()
            provider = Provider(Store(), backend, self.signer, lambda: self.now)
            prepared = provider.prepare(self.auth)
            active = provider.activate(self.auth, prepared["preparationId"])
            activation = active["proof"]["activationId"]
            provider.release(
                activation,
                self.auth.authorization_id,
                active["proof"]["proofId"],
                "release",
            )
            _, value = provider.store.get(activation)
            cleanup = {
                "attemptId": self.context.attempt_id,
                "activationId": activation,
                "cleanupId": "cleanup",
            }
            provider.store.transition(
                activation,
                object_digest(value["request"]),
                "released",
                "cleaning",
                {**value, "cleanup": cleanup},
            )
            if detached:
                backend.detach(activation)

            with self.subTest(detached=detached):
                result = provider.reconcile_all()
                self.assertEqual(result[activation]["state"], "cleaned")
                self.assertFalse(backend.attachments)
                self.assertEqual(provider.store.get(activation)[0], "cleaned")
                self.assertEqual(provider.reconcile_all(), {})

    def test_authorization_epoch_must_match_active_provider_epoch(self):
        stale = Authorization(
            self.auth.authorization_id,
            self.auth.context,
            self.auth.issued_at,
            self.auth.not_before,
            self.auth.expires_at,
            2,
        )
        with self.assertRaisesRegex(ValueError, "active provider epoch"):
            self.p.prepare(stale)

    def test_activation_binds_complete_prepared_authorization(self):
        prepared = self.p.prepare(self.auth)
        mutations = {
            "authorization": {"authorization_id": "changed-auth"},
            "audience": {
                "context": Context(**{**self.context.__dict__, "audience": "changed"})
            },
            "challenge": {
                "context": Context(**{**self.context.__dict__, "challenge": "changed"})
            },
            "idempotency": {
                "context": Context(
                    **{**self.context.__dict__, "idempotency_key": "changed"}
                )
            },
            "policy": {
                "context": Context(
                    **{
                        **self.context.__dict__,
                        "policy_bytes": self.policy.replace(b"source", b"target"),
                        "policy_digest": policy_digest(
                            self.policy.replace(b"source", b"target")
                        ),
                    }
                )
            },
        }
        for name, changes in mutations.items():
            values = {
                "authorization_id": self.auth.authorization_id,
                "context": self.auth.context,
                "issued_at": self.auth.issued_at,
                "not_before": self.auth.not_before,
                "expires_at": self.auth.expires_at,
                "epoch": self.auth.epoch,
            }
            values.update(changes)
            changed = Authorization(**values)
            with self.subTest(name=name), self.assertRaises(Conflict):
                self.p.activate(changed, prepared["preparationId"])

    def test_prepare_and_activate_reject_full_transaction_mutation_matrix(self):
        prepared = self.p.prepare(self.auth)
        changed_policy = self.policy.replace(b"source", b"target")
        context_mutations = {
            "provider": {"provider_id": "other-provider/v1"},
            "audience": {"audience": "changed-audience"},
            "challenge": {"challenge": "changed-challenge"},
            "idempotency-key": {"idempotency_key": "changed-idempotency"},
            "policy-bytes-only": {"policy_bytes": changed_policy},
            "policy-digest-only": {"policy_digest": policy_digest(changed_policy)},
            "policy-bytes-and-digest": {
                "policy_bytes": changed_policy,
                "policy_digest": policy_digest(changed_policy),
            },
            "capabilities-missing": {"required_capabilities": ()},
            "capabilities-unknown": {"required_capabilities": ("unknown/v1",)},
        }
        for name, changes in context_mutations.items():
            values = dict(self.context.__dict__)
            values.update(changes)
            context = Context(**values)
            changed = Authorization(
                self.auth.authorization_id,
                context,
                self.auth.issued_at,
                self.auth.not_before,
                self.auth.expires_at,
                self.auth.epoch,
            )
            with self.subTest(stage="prepare", field=name), self.assertRaises(
                (Conflict, ValueError)
            ):
                self.p.prepare(changed)
            with self.subTest(stage="activate", field=name), self.assertRaises(
                (Conflict, ValueError)
            ):
                self.p.activate(changed, prepared["preparationId"])

        authorization_mutations = {
            "authorization-id": {"authorization_id": "changed-authorization"},
            "issued-at": {"issued_at": self.auth.issued_at - 1},
            "not-before": {"not_before": self.auth.not_before - 1},
            "expires-at": {"expires_at": self.auth.expires_at + 1},
            "epoch": {"epoch": self.auth.epoch + 1},
        }
        for name, changes in authorization_mutations.items():
            values = dict(self.auth.__dict__)
            values.update(changes)
            changed = Authorization(**values)
            with self.subTest(stage="activate", field=name), self.assertRaises(
                (Conflict, ValueError)
            ):
                self.p.activate(changed, prepared["preparationId"])

    def test_complete_transaction_mutations_fail_after_store_restart(self):
        with tempfile.NamedTemporaryFile() as state:
            first = Provider(
                Store(state.name), self.backend, self.signer, lambda: self.now
            )
            prepared = first.prepare(self.auth)
            controls = Provider(
                Store(state.name), self.backend, self.signer, lambda: self.now
            )
            self.assertEqual(controls.prepare(self.auth), prepared)

            changed_policy = self.policy.replace(b"source", b"target")
            context_mutations = {
                "request": {"request_id": "changed-request"},
                "workload": {"workload_id": "changed-workload"},
                "provider": {"provider_id": "other-provider/v1"},
                "audience": {"audience": "changed-audience"},
                "challenge": {"challenge": "changed-challenge"},
                "idempotency-key": {"idempotency_key": "changed-idempotency"},
                "policy-bytes-only": {"policy_bytes": changed_policy},
                "policy-digest-only": {"policy_digest": policy_digest(changed_policy)},
                "policy-bytes-and-digest": {
                    "policy_bytes": changed_policy,
                    "policy_digest": policy_digest(changed_policy),
                },
                "capabilities-missing": {"required_capabilities": ()},
                "capabilities-unknown": {"required_capabilities": ("unknown/v1",)},
            }
            for name, changes in context_mutations.items():
                values = dict(self.context.__dict__)
                values.update(changes)
                changed = Authorization(
                    self.auth.authorization_id,
                    Context(**values),
                    self.auth.issued_at,
                    self.auth.not_before,
                    self.auth.expires_at,
                    self.auth.epoch,
                )
                restarted = Provider(
                    Store(state.name), self.backend, self.signer, lambda: self.now
                )
                with self.subTest(kind="context", field=name), self.assertRaises(
                    (Conflict, ValueError)
                ):
                    restarted.activate(changed, prepared["preparationId"])

            authorization_mutations = {
                "authorization-id": {"authorization_id": "changed-authorization"},
                "issued-at": {"issued_at": self.auth.issued_at - 1},
                "not-before": {"not_before": self.auth.not_before - 1},
                "expires-at": {"expires_at": self.auth.expires_at + 1},
                "epoch": {"epoch": self.auth.epoch + 1},
            }
            for name, changes in authorization_mutations.items():
                values = dict(self.auth.__dict__)
                values.update(changes)
                changed = Authorization(**values)
                restarted = Provider(
                    Store(state.name), self.backend, self.signer, lambda: self.now
                )
                with self.subTest(kind="authorization", field=name), self.assertRaises(
                    (Conflict, ValueError)
                ):
                    restarted.activate(changed, prepared["preparationId"])

    def test_activation_rejects_reused_authorization_id_with_changed_context_after_restart(
        self,
    ):
        with tempfile.NamedTemporaryFile() as state:
            first = Provider(
                Store(state.name), self.backend, self.signer, lambda: self.now
            )
            prepared = first.prepare(self.auth)
            changed_context = Context(
                **{**self.context.__dict__, "audience": "changed"}
            )
            changed = Authorization(
                self.auth.authorization_id,
                changed_context,
                self.auth.issued_at,
                self.auth.not_before,
                self.auth.expires_at,
                self.auth.epoch,
            )
            restarted = Provider(
                Store(state.name), self.backend, self.signer, lambda: self.now
            )
            with self.assertRaises(Conflict):
                restarted.activate(changed, prepared["preparationId"])


if __name__ == "__main__":
    unittest.main()
