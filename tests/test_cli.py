from __future__ import annotations

import json
import sqlite3
from unittest import mock

import pytest

from agentsuite_guardd import cli
from agentsuite_guardd.backend import BackendError
from agentsuite_guardd.live_adapter import LiveAdapterError


def test_corrupt_state_is_reported_without_traceback(capsys) -> None:
    with mock.patch.object(
        cli,
        "build_provider",
        side_effect=sqlite3.DatabaseError("file is not a database"),
    ):
        assert cli.main(["--config", "config.json", "descriptor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "agentsuite-guardd: configuration error: file is not a database\n"
    )


@pytest.mark.parametrize("error", [BackendError("bad backend"), LiveAdapterError("bad live state")])
def test_operational_state_errors_are_reported_without_traceback(
    capsys, error: Exception
) -> None:
    with mock.patch.object(cli, "build_provider", side_effect=error):
        assert cli.main(["--config", "config.json", "descriptor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"agentsuite-guardd: configuration error: {error}\n"


def test_startup_reconciliation_reports_the_root_failure(capsys) -> None:
    provider = mock.Mock()
    provider.reconcile_all.return_value = {
        "activation:attempt": {
            "state": "quarantined",
            "error": "protected path identity changed",
        }
    }
    with (
        mock.patch.object(cli, "build_provider", return_value=(mock.Mock(), provider)),
        mock.patch.object(cli, "UnixServer"),
    ):
        assert cli.main(["--config", "config.json", "serve"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "agentsuite-guardd: configuration error: startup reconciliation failed: "
        "activation:attempt: protected path identity changed\n"
    )


def test_malformed_config_path_type_is_reported_without_traceback(
    capsys, tmp_path
) -> None:
    config = {
        "listen": "unix:///tmp/guardd.sock",
        "state": "/tmp/state.db",
        "keyFile": [],
        "backendState": "/tmp/backend.json",
        "adapterState": "/tmp/adapter.json",
        "bpffsRoot": "/sys/fs/bpf/agentsuite-guardd",
        "cgroupRoot": "/sys/fs/cgroup",
        "bpftool": "/usr/sbin/bpftool",
        "providerId": "agentsuite-guardd/v1",
        "endpointId": "test",
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))

    assert cli.main(["--config", str(path), "descriptor"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "agentsuite-guardd: configuration error: "
        "keyFile must be a nonempty string\n"
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("socketMode", True, "socketMode must be an octal string or integer"),
        ("socketMode", 0o1000, "socketMode must contain only permission bits"),
        (
            "allowedUIDs",
            [True],
            "allowedUIDs entries must be nonnegative integers",
        ),
        (
            "allowedUIDs",
            [1.5],
            "allowedUIDs entries must be nonnegative integers",
        ),
        (
            "allowedUIDs",
            ["12"],
            "allowedUIDs entries must be nonnegative integers",
        ),
    ],
)
def test_security_relevant_config_numbers_are_not_coerced(
    capsys, tmp_path, field, value, message
) -> None:
    config = {
        "listen": "unix:///tmp/guardd.sock",
        "state": "/tmp/state.db",
        "keyFile": "/tmp/signing.seed",
        "backendState": "/tmp/backend.json",
        "adapterState": "/tmp/adapter.json",
        "bpffsRoot": "/sys/fs/bpf/agentsuite-guardd",
        "cgroupRoot": "/sys/fs/cgroup",
        "bpftool": "/usr/sbin/bpftool",
        "providerId": "agentsuite-guardd/v1",
        "endpointId": "test",
        field: value,
    }
    path = tmp_path / f"{field}.json"
    path.write_text(json.dumps(config))

    assert cli.main(["--config", str(path), "descriptor"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"agentsuite-guardd: configuration error: {message}\n"
