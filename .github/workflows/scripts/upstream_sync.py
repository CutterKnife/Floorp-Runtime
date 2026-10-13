# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# SPDX-License-Identifier: MPL-2.0

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def git(root, *args, env=None):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or "Git operation failed")
    return result.stdout.strip()


def sync_action(root, upstream, base_manifest=None):
    current = git(upstream, "rev-parse", "HEAD")
    manifest = root / ".github/runtime-upstream.json"
    if not manifest.exists():
        if base_manifest is None or not base_manifest.exists():
            return "sync"
        manifest = base_manifest
    recorded = json.loads(manifest.read_text())["upstream"]["commit"]
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{40}", recorded):
        raise ValueError("Invalid recorded immutable upstream commit")
    if recorded == current:
        return "skip"
    raise ValueError(
        "Recorded source cohort requires deliberate reintegration for upstream "
        + current
    )


def required_patches(root):
    directory = root / ".github/patches/upstream"
    paths = sorted(directory.glob("*.patch"))
    policy = root / ".github/qa/source-policy.json"
    if not policy.exists():
        return paths
    entries = json.loads(policy.read_text())["commonPatches"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Missing required upstream patch inventory")
    required = []
    for entry in entries:
        relative = Path(entry["path"])
        if (
            relative.parent != Path(".github/patches/upstream")
            or relative.suffix != ".patch"
        ):
            raise ValueError("Invalid required upstream patch path")
        patch = root / relative
        if hashlib.sha256(patch.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Required upstream patch hash changed: " + str(relative))
        required.append(patch)
    if len(set(required)) != len(required) or set(required) != set(paths):
        raise ValueError("Required upstream patch inventory differs from source policy")
    return required


def check_patches(root):
    patches = required_patches(root)
    with tempfile.TemporaryDirectory(prefix="upstream-patch-check-") as temporary:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temporary).resolve() / "index")}
        git(root, "read-tree", "HEAD", env=env)
        git(root, "add", "--all", "--force", ".", env=env)
        for patch in patches:
            try:
                git(
                    root,
                    "apply",
                    "--cached",
                    "--whitespace=error-all",
                    str(patch),
                    env=env,
                )
            except ValueError as error:
                raise ValueError(
                    f"Required upstream patch {patch.name}: {error}"
                ) from error
    return len(patches)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--upstream", required=True, type=Path)
    guard.add_argument("--base-manifest", type=Path)
    guard.add_argument("--output", type=Path, default=os.environ.get("GITHUB_OUTPUT"))
    commands.add_parser("check-patches")
    args = parser.parse_args()
    root = Path.cwd()
    try:
        if args.command == "guard":
            action = sync_action(root, args.upstream, args.base_manifest)
            if args.output:
                with args.output.open("a") as stream:
                    stream.write("action=" + action + "\n")
            print("Upstream sync action: " + action)
        else:
            print(f"All {check_patches(root)} required upstream patches apply cleanly")
    except (KeyError, TypeError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
