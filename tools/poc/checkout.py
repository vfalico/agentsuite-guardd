#!/usr/bin/env python3
"""Fetch owner-only, exact PoC source pins and write separate Go workspaces."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess


EXPECTED = {
    "guardd", "orka", "sessions", "kaimahi", "kagent",
    "substrate-kagent", "substrate-sessions", "suite",
}


def git(directory, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", str(directory), *args],
        text=True,
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=(
        Path(__file__).resolve().parents[2] / "docs/poc/sources.json"
    ))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="Validate the local lock only; no network or writes")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    rows = manifest["rows"]
    if manifest["schema_version"] != 1 or len(rows) != len(EXPECTED):
        parser.error("unsupported or incomplete source lock")
    if {row["repository"] for row in rows} != EXPECTED:
        parser.error("source lock must declare all eight distinct checkouts")
    for row in rows:
        if not re.fullmatch(r"https://github\.com/vfalico/[A-Za-z0-9_.-]+\.git", row["url"]):
            parser.error("source URL is not an authorized owner destination")
        if any(not re.fullmatch(r"[0-9a-f]{40}", row[key]) for key in ("commit", "tree", "base")):
            parser.error("source commit, tree and base must be exact SHA-1 identities")
    if args.check:
        print("Source lock valid: eight exact owner-only snapshots; workloads NOT RUN")
        return
    if args.root is None:
        parser.error("--root is required unless --check is used")
    root = args.root.absolute()
    if root.exists() or root.is_symlink() or not root.parent.is_dir():
        parser.error("root must be NEW with an existing parent; no overwrite or implicit cleanup")
    if shutil.disk_usage(root.parent).free < 8 * 1024**3:
        parser.error("source checkout requires at least 8 GiB free; native builds need more")
    root.mkdir(mode=0o700)
    sources = root / "sources"
    sources.mkdir()
    for row in rows:
        destination = sources / row["repository"]
        destination.mkdir()
        git(destination, "init", "--quiet")
        git(destination, "remote", "add", "origin", row["url"])
        git(destination, "fetch", "--quiet", "--depth=1", "origin", row["commit"])
        git(destination, "checkout", "--quiet", "--detach", "FETCH_HEAD")
        if git(destination, "rev-parse", "HEAD") != row["commit"]:
            raise RuntimeError("source commit mismatch: " + row["repository"])
        if git(destination, "rev-parse", "HEAD^{tree}") != row["tree"]:
            raise RuntimeError("source tree mismatch: " + row["repository"])
        print(row["repository"], row["commit"], flush=True)
    workspaces = root / "workspaces"
    workspaces.mkdir()
    modules = {
        "kagent": ["kagent/go", "substrate-kagent"],
        "sessions": ["sessions", "sessions/integrations/substrate", "substrate-sessions"],
        "kaimahi": ["kaimahi", "sessions", "suite"],
    }
    for name, paths in modules.items():
        uses = "".join(" " + json.dumps(str(sources / path)) + "\n" for path in paths)
        (workspaces / (name + ".work")).write_text("go 1.27.2\nuse (\n" + uses + ")\n")
    (root / "SOURCE-LOCK.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Sources verified; external workspaces written. Tests and native workloads NOT RUN.")


if __name__ == "__main__":
    main()
