from __future__ import annotations

import copy
import gzip
from io import BytesIO
import os
from pathlib import Path
import stat
import tarfile
import time
import zipfile


def source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH", "0")
    epoch = int(value)
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    return epoch


def normalize_sdist(directory: str, filename: str, epoch: int) -> None:
    path = Path(directory) / filename
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            payload = source.extractfile(member).read() if member.isfile() else None
            entries.append((member, payload))

    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=epoch) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.GNU_FORMAT,
            ) as target:
                for member, payload in sorted(entries, key=lambda entry: entry[0].name):
                    normalized = copy.copy(member)
                    normalized.uid = 0
                    normalized.gid = 0
                    normalized.uname = "root"
                    normalized.gname = "root"
                    normalized.mtime = epoch
                    normalized.pax_headers = {}
                    if normalized.isdir():
                        normalized.mode = 0o755
                    elif normalized.isfile():
                        normalized.mode = (
                            0o755 if normalized.mode & 0o111 else 0o644
                        )
                    target.addfile(
                        normalized,
                        BytesIO(payload) if payload is not None else None,
                    )
    temporary.replace(path)


def normalize_wheel(directory: str, filename: str, epoch: int) -> None:
    path = Path(directory) / filename
    with zipfile.ZipFile(path) as source:
        entries = [
            (entry, source.read(entry.filename))
            for entry in source.infolist()
        ]

    timestamp = time.gmtime(max(epoch, 315532800))[:6]
    temporary = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(
        temporary,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as target:
        for entry, payload in sorted(entries, key=lambda item: item[0].filename):
            normalized = zipfile.ZipInfo(entry.filename, timestamp)
            normalized.create_system = 3
            if entry.is_dir():
                normalized.compress_type = zipfile.ZIP_STORED
                normalized.external_attr = (stat.S_IFDIR | 0o755) << 16
            else:
                normalized.compress_type = zipfile.ZIP_DEFLATED
                original_mode = entry.external_attr >> 16
                mode = 0o755 if original_mode & 0o111 else 0o644
                normalized.external_attr = (stat.S_IFREG | mode) << 16
            target.writestr(normalized, payload)
    temporary.replace(path)
