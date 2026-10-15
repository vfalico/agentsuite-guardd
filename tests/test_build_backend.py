from __future__ import annotations

import gzip
from io import BytesIO
from pathlib import Path
import tarfile
import zipfile

from _backend.reproducible_sdist import normalize_sdist, normalize_wheel


def _write_sdist(path: Path, mtime: int) -> None:
    with tarfile.open(path, "w:gz") as archive:
        entry = tarfile.TarInfo("agentsuite-guardd/example.txt")
        entry.size = len(b"example")
        entry.mtime = mtime
        entry.uid = mtime
        entry.gid = mtime
        archive.addfile(entry, BytesIO(b"example"))


def test_sdist_normalization_removes_archive_metadata_variance(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, 100)
    _write_sdist(second, 200)

    normalize_sdist(str(tmp_path), first.name, 42)
    normalize_sdist(str(tmp_path), second.name, 42)

    assert first.read_bytes() == second.read_bytes()
    with gzip.open(first) as compressed:
        with tarfile.open(fileobj=compressed, mode="r:") as archive:
            member = archive.getmember("agentsuite-guardd/example.txt")
            assert member.mtime == 42
            assert member.mode == 0o644
            assert (member.uid, member.gid) == (0, 0)
            assert (member.uname, member.gname) == ("root", "root")


def _write_wheel(path: Path, mode: int) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        directory = zipfile.ZipInfo("agentsuite_guardd/")
        directory.create_system = 3
        directory.external_attr = 0o40775 << 16
        archive.writestr(directory, b"")
        entry = zipfile.ZipInfo("agentsuite_guardd/example.py")
        entry.create_system = 3
        entry.external_attr = mode << 16
        archive.writestr(entry, b"example = True\n")


def test_wheel_normalization_removes_mode_variance(tmp_path: Path) -> None:
    first = tmp_path / "first.whl"
    second = tmp_path / "second.whl"
    _write_wheel(first, 0o100644)
    _write_wheel(second, 0o100664)

    normalize_wheel(str(tmp_path), first.name, 42)
    normalize_wheel(str(tmp_path), second.name, 42)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        directory = archive.getinfo("agentsuite_guardd/")
        member = archive.getinfo("agentsuite_guardd/example.py")
        assert directory.is_dir()
        assert directory.compress_type == zipfile.ZIP_STORED
        assert directory.external_attr >> 16 == 0o40755
        assert member.external_attr >> 16 == 0o100644
