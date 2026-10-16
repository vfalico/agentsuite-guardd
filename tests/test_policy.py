import unittest

from agentsuite_guardd.model import policy_digest
from agentsuite_guardd.policy import compile_policy


class PolicyCompatibilityTests(unittest.TestCase):
    def test_kaimahi_canonical_payload_compiles(self):
        policy = (
            b'{"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        digest = "sha256:e26d7dc5ef39e5a547a5a5d732576424df638e64d39b8abd64f871290d61646f"
        plan = compile_policy(policy, digest, "cgroup:/sys/fs/cgroup/test")
        self.assertEqual(plan.policy_digest, digest)

    def test_suite_utf16_ordering_vector_compiles(self):
        policy = (
            '{"denyWritePaths":["/workspace/source","/𐀀","/\ue000"],'
            '"requiredCapabilities":["filesystem/deny-write/v1"],'
            '"version":"agentsuite.policy/v1"}'
        ).encode()
        digest = "sha256:c06512cf93ae8e9275dc8196425734668f9682e1747dd6ec2d14012e18e80188"
        plan = compile_policy(policy, digest, "cgroup:/sys/fs/cgroup/test")
        self.assertEqual(plan.deny_write_paths, ("/workspace/source", "/𐀀", "/\ue000"))

    def test_unicode_codepoint_order_is_not_accepted_as_canonical(self):
        policy = (
            '{"denyWritePaths":["/workspace/source","/\ue000","/𐀀"],'
            '"requiredCapabilities":["filesystem/deny-write/v1"],'
            '"version":"agentsuite.policy/v1"}'
        ).encode()
        with self.assertRaisesRegex(ValueError, "paths are not canonical"):
            compile_policy(
                policy,
                policy_digest(policy),
                "cgroup:/sys/fs/cgroup/test",
            )

    def test_noncanonical_key_order_is_rejected(self):
        policy = (
            b'{"version":"agentsuite.policy/v1",'
            b'"denyWritePaths":["/workspace/source"],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"]}'
        )
        with self.assertRaisesRegex(ValueError, "not canonical"):
            compile_policy(
                policy,
                policy_digest(policy),
                "cgroup:/sys/fs/cgroup/test",
            )

    def test_nontext_path_is_rejected_as_invalid_policy(self):
        policy = (
            b'{"denyWritePaths":[{}],'
            b'"requiredCapabilities":["filesystem/deny-write/v1"],'
            b'"version":"agentsuite.policy/v1"}'
        )
        with self.assertRaisesRegex(ValueError, "invalid deny path"):
            compile_policy(
                policy,
                policy_digest(policy),
                "cgroup:/sys/fs/cgroup/test",
            )


if __name__ == "__main__":
    unittest.main()
