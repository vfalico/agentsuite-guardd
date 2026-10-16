from base64 import b64encode
import json, os, socket, tempfile, threading, time, unittest
from agentsuite_guardd.backend import MemoryBackend, PersistentBackend
from agentsuite_guardd.crypto import Signer
from agentsuite_guardd.model import Authorization, Context, policy_digest
from agentsuite_guardd.provider import Provider
from agentsuite_guardd.store import Store
from agentsuite_guardd.transport import (
    MAX_FRAME,
    UnixClient,
    UnixServer,
    authorization_from_object,
    authorization_to_object,
)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.socket = os.path.join(root, "provider.sock")
        self.backend = MemoryBackend()
        self.provider = Provider(
            Store(os.path.join(root, "state.db")),
            self.backend,
            Signer(b"s" * 32),
            endpoint_id="test-endpoint",
        )
        self.server = UnixServer(self.socket, self.provider, (os.getuid(),))
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self.server.serve_forever, args=(self.ready,), daemon=True
        )
        self.thread.start()
        self.assertTrue(self.ready.wait(2))
        self.client = UnixClient(self.socket)

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(2)
        self.tmp.cleanup()

    def raw_call(self, request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.socket)
            client.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            return json.loads(client.makefile("rb").readline())

    def test_all_external_operations_and_restart_readback(self):
        descriptor = self.client.call("DiscoverDescriptor")
        self.assertEqual(descriptor["endpointId"], "test-endpoint")
        self.assertEqual(
            self.client.call(
                "NegotiateCapabilities",
                {"requiredCapabilities": ["filesystem/deny-write/v1"]},
            )["protocolVersion"],
            "orka.enforcement-provider/v2",
        )
        now = time.time()
        policy = (
            b'{"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        digest = policy_digest(policy)
        a = Authorization(
            "auth",
            Context(
                "req",
                "attempt",
                "workload",
                "agentsuite-guardd/v1",
                "orka",
                "challenge",
                "idem",
                digest,
                policy,
            ),
            now - 1,
            now - 1,
            now + 60,
            1,
        )
        wire = authorization_to_object(a)
        prepared = self.client.call("Prepare", {"authorization": wire})
        active = self.client.call(
            "Activate",
            {"authorization": wire, "preparationId": prepared["preparationId"]},
        )
        activation = active["proof"]["activationId"]
        self.assertEqual(
            self.client.call("ReadBack", {"activationId": activation})["policyDigest"],
            digest,
        )
        proof = self.client.call("GetProof", {"activationId": activation})
        self.assertEqual(proof["authorizationId"], "auth")
        self.assertEqual(
            self.client.call("GetStatus", {"activationId": activation})["state"],
            "active",
        )
        self.assertEqual(
            self.client.call("Reconcile", {"attemptId": "attempt"})["state"],
            "active",
        )
        self.assertEqual(
            self.client.call(
            "Release",
            {
                "activationId": activation,
                "authorizationId": "auth",
                "proofId": proof["proofId"],
                "releaseId": "release",
            },
            ),
            {},
        )
        with self.assertRaisesRegex(RuntimeError, "conflict"):
            self.client.call(
                "Release",
                {
                    "activationId": activation,
                    "authorizationId": "auth",
                    "proofId": proof["proofId"],
                    "releaseId": "changed",
                },
            )
        restarted = Provider(
            Store(os.path.join(self.tmp.name, "state.db")),
            self.backend,
            Signer(b"s" * 32),
            endpoint_id="test-endpoint",
        )
        self.assertEqual(restarted.reconcile_all()[activation]["state"], "released")
        self.assertEqual(
            self.client.call(
                "Cleanup",
                {
                    "attemptId": "attempt",
                    "activationId": activation,
                    "cleanupId": "cleanup",
                },
            ),
            {},
        )
        cleaned_restart = Provider(
            Store(os.path.join(self.tmp.name, "state.db")),
            self.backend,
            Signer(b"s" * 32),
            endpoint_id="test-endpoint",
        )
        self.assertEqual(cleaned_restart.reconcile_all(), {})

    def test_protocol_downgrade_and_unknown_fields_fail_closed(self):
        base = {
            "version": 2,
            "id": "strict",
            "operation": "DiscoverDescriptor",
            "parameters": {},
        }
        for name, request in (
            ("downgrade", {**base, "version": 1}),
            ("top-level field", {**base, "extra": True}),
            (
                "parameter field",
                {
                    **base,
                    "operation": "GetStatus",
                    "parameters": {"activationId": "missing", "extra": True},
                },
            ),
        ):
            with self.subTest(name=name):
                reply = self.raw_call(request)
                self.assertFalse(reply["ok"])
                self.assertEqual(reply["error"]["code"], "invalid_request")

    def test_authorization_wire_types_are_exact(self):
        now = time.time()
        policy = (
            b'{"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        authorization = Authorization(
            "auth",
            Context(
                "req",
                "attempt",
                "workload",
                "agentsuite-guardd/v1",
                "orka",
                "challenge",
                "idem",
                policy_digest(policy),
                policy,
            ),
            now - 1,
            now - 1,
            now + 60,
            1,
        )
        wire = authorization_to_object(authorization)
        for name, changed in (
            ("boolean epoch", {**wire, "epoch": True}),
            (
                "scalar capabilities",
                {
                    **wire,
                    "context": {
                        **wire["context"],
                        "requiredCapabilities": "filesystem/deny-write/v1",
                    },
                },
            ),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                authorization_from_object(changed)

    def test_rfc3339_nanoseconds_are_preserved_for_transcript_identity(self):
        policy = (
            b'{"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        wire = {
            "authorizationId": "auth",
            "context": {
                "requestId": "req",
                "attemptId": "attempt",
                "workloadId": "workload",
                "providerId": "agentsuite-guardd/v1",
                "audience": "orka",
                "challenge": "challenge",
                "idempotencyKey": "idem",
                "policyDigest": policy_digest(policy),
                "policyBytes": b64encode(policy).decode(),
                "requiredCapabilities": ["filesystem/deny-write/v1"],
            },
            "issuedAt": "2026-01-01T00:00:00.123456789Z",
            "notBefore": "2026-01-01T00:00:00.123456789Z",
            "expiresAt": "2026-01-01T00:01:00.987654321Z",
            "epoch": 1,
        }
        self.assertEqual(authorization_from_object(wire).object(), wire)

    def test_absent_provider_state_is_typed_not_found(self):
        for operation, parameters in (
            ("ReadBack", {"activationId": "missing"}),
            ("GetProof", {"activationId": "missing"}),
            ("GetStatus", {"activationId": "missing"}),
            ("Reconcile", {"attemptId": "missing"}),
            (
                "Cleanup",
                {
                    "attemptId": "missing",
                    "activationId": "activation:missing",
                    "cleanupId": "cleanup",
                },
            ),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                RuntimeError, "^not_found:"
            ):
                self.client.call(operation, parameters)

    def test_malformed_frame_returns_bound_error(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.socket)
            client.sendall(b"not-json\n")
            reply = json.loads(client.makefile("rb").readline())
            self.assertFalse(reply["ok"])
            self.assertEqual(reply["error"]["code"], "invalid_request")

    def test_nonfinite_json_constant_is_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.socket)
            client.sendall(
                b'{"version":2,"id":"nan","operation":"DiscoverDescriptor",'
                b'"parameters":{},"value":NaN}\n'
            )
            reply = json.loads(client.makefile("rb").readline())
            self.assertFalse(reply["ok"])
            self.assertEqual(reply["error"]["code"], "invalid_request")
            self.assertIn("invalid JSON constant", reply["error"]["message"])

    def test_exact_limit_frame_is_accepted(self):
        prefix = (
            b'{"version":2,"id":"limit","operation":"DiscoverDescriptor",'
            b'"parameters":{},"padding":"'
        )
        suffix = b'"}\n'
        frame = prefix + (b"x" * (MAX_FRAME - len(prefix) - len(suffix))) + suffix
        self.assertEqual(len(frame), MAX_FRAME)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(self.socket)
            client.sendall(frame)
            reply = json.loads(client.makefile("rb").readline())
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "invalid_request")
        self.assertNotEqual(reply["error"]["code"], "frame_too_large")

    def test_oversized_frame_without_newline_is_rejected_immediately(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(self.socket)
            client.sendall(b"x" * (MAX_FRAME + 1))
            stream = client.makefile("rb")
            reply = json.loads(stream.readline())
            self.assertFalse(reply["ok"])
            self.assertEqual(reply["error"]["code"], "frame_too_large")
            self.assertEqual(stream.readline(), b"")

    def test_protocol_and_capability_fail_closed(self):
        with self.assertRaises(RuntimeError):
            self.client.call(
                "NegotiateCapabilities", {"requiredCapabilities": ["unknown/v1"]}
            )
        with self.assertRaises(RuntimeError):
            self.client.call("NoSuchOperation")


class CapabilityAdvertisementTests(unittest.TestCase):

    def test_persistent_desired_state_is_not_independent_readback(self):
        with tempfile.TemporaryDirectory() as d:
            backend = PersistentBackend(os.path.join(d, "backend.json"))
            backend.data["attachments"]["activation"] = {
                "policyDigest": "x",
                "targetId": "t",
            }
            backend._write(backend.data)
            from agentsuite_guardd.backend import BackendError

            with self.assertRaises(BackendError):
                backend.readback("activation")

    def test_packaged_backend_does_not_overclaim_without_live_adapter(self):
        with tempfile.TemporaryDirectory() as d:
            backend = PersistentBackend(os.path.join(d, "backend.json"))
            provider = Provider(
                Store(os.path.join(d, "state.db")), backend, Signer(b"s" * 32)
            )
            self.assertEqual(provider.descriptor()["capabilities"], [])
            with self.assertRaises(ValueError):
                provider.negotiate(["filesystem/deny-write/v1"])


class LiveAdapterBackendIntegrationTests(unittest.TestCase):
    class OperationalAdapter:
        capabilities = ("filesystem/deny-write/v1",)

        def __init__(self):
            self.attachments = {}
            self.operational = True

        def _operational(self):
            return self.operational

        def activate(self, activation_id, desired):
            self.attachments[activation_id] = desired

        def readback(self, activation_id):
            return self.attachments[activation_id]

        def detach(self, activation_id):
            self.attachments.pop(activation_id, None)

        def list_attachments(self):
            return tuple(sorted(self.attachments))

    def test_capability_tracks_operational_adapter_and_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = self.OperationalAdapter()
            backend = PersistentBackend(
                os.path.join(directory, "backend.json"), adapter=adapter
            )
            provider = Provider(
                Store(os.path.join(directory, "state.db")),
                backend,
                Signer(b"s" * 32),
            )
            self.assertEqual(
                provider.descriptor()["capabilities"],
                ["filesystem/deny-write/v1"],
            )
            adapter.operational = False
            self.assertEqual(provider.descriptor()["capabilities"], [])
            with self.assertRaises(ValueError):
                provider.negotiate(["filesystem/deny-write/v1"])

    def test_inventory_removes_orphan_and_rejects_missing_live_state(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = self.OperationalAdapter()
            backend = PersistentBackend(
                os.path.join(directory, "backend.json"), adapter=adapter
            )
            orphan = {"policyDigest": "digest", "targetId": "target"}
            adapter.attachments["orphan"] = orphan
            backend.data["attachments"]["orphan"] = orphan
            backend._write(backend.data)
            backend.reconcile_inventory(())
            self.assertEqual(adapter.attachments, {})
            self.assertEqual(backend.data["attachments"], {})
            with self.assertRaisesRegex(Exception, "desired state is missing"):
                backend.reconcile_inventory(("activation:x",))
            backend.data["attachments"]["activation:x"] = orphan
            backend._write(backend.data)
            with self.assertRaisesRegex(Exception, "live adapter is missing"):
                backend.reconcile_inventory(("activation:x",))
