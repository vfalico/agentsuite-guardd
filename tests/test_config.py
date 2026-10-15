import json, os, stat, tempfile, unittest
from pathlib import Path
from unittest import mock
from agentsuite_guardd.config import load_config, load_signing_seed


class ConfigTests(unittest.TestCase):
    @staticmethod
    def _stat_with_owner(result, uid):
        return os.stat_result(
            (
                result.st_mode,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                uid,
                result.st_gid,
                result.st_size,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )

    def test_root_owned_credential_and_config(self):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "key")
            Path(key).write_bytes(b"k" * 32)
            os.chmod(key, 0o600)
            key_stat = os.stat(key)
            with mock.patch(
                "agentsuite_guardd.config.os.stat",
                return_value=self._stat_with_owner(key_stat, 0),
            ):
                self.assertEqual(load_signing_seed(key), b"k" * 32)
            config = os.path.join(d, "config.json")
            Path(config).write_text(
                json.dumps(
                    {
                        "listen": "unix://" + d + "/sock",
                        "state": d + "/state",
                        "keyFile": key,
                        "backendState": d + "/backend",
                        "adapterState": d + "/adapter",
                        "bpffsRoot": d + "/bpffs",
                        "cgroupRoot": d + "/cgroup",
                        "bpftool": d + "/bpftool",
                        "providerId": "agentsuite-guardd/v1",
                        "endpointId": "test",
                        "allowedUIDs": [os.getuid()],
                    }
                )
            )
            self.assertEqual(load_config(config).endpoint_id, "test")

            with mock.patch(
                "agentsuite_guardd.config.os.stat",
                return_value=self._stat_with_owner(key_stat, 1000),
            ), self.assertRaises(PermissionError):
                load_signing_seed(key)

            os.chmod(key, 0o644)
            permissive_stat = os.stat(key)
            with mock.patch(
                "agentsuite_guardd.config.os.stat",
                return_value=self._stat_with_owner(permissive_stat, 0),
            ), self.assertRaises(PermissionError):
                load_signing_seed(key)

    def test_missing_credential_fails_without_fallback(self):
        with self.assertRaises(FileNotFoundError):
            load_signing_seed("/definitely/missing/guardd-key")
