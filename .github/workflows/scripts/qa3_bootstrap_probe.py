# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import hashlib
import inspect
import json
import os
import sys
from pathlib import Path

ROOT_URL = "https://firefox-ci-tc.services.mozilla.com"
SCM_LEVEL = "3"
CACHE_ENV = ("TASKCLUSTER_ROOT_URL", "MOZ_SCM_LEVEL")


def validate_environment(phase, env):
    if (
        env.get("TASKCLUSTER_ROOT_URL") != ROOT_URL
        or env.get("MOZ_SCM_LEVEL") != SCM_LEVEL
        or env.get("MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE") != "pip"
        or "TASK_ID" in env
        or "MACH_NO_FUNC_CACHE" in env
    ):
        raise ValueError("unexpected hosted metadata environment")
    if phase == "prepare":
        if "MOZ_AUTOMATION" in env:
            raise ValueError("metadata preparation must omit automation")
    elif phase != "verify" or env.get("MOZ_AUTOMATION") != "1":
        raise ValueError("metadata verification requires build automation")


def prohibit_subprocess(event, args):
    if event == "subprocess.Popen":
        raise RuntimeError("expected source cache hit attempted a subprocess")


def catalog_snapshot(source, phase):
    from mach import func_cache
    from mozbuild.toolchains import toolchain_task_definitions

    validate_environment(phase, os.environ)
    if Path(func_cache._topsrcdir).resolve() != source.resolve():
        raise ValueError("metadata source differs from Mach source")
    if phase == "verify":
        sys.addaudithook(prohibit_subprocess)
    tasks = toolchain_task_definitions()
    if not isinstance(tasks, dict) or not 0 < len(tasks) <= 10000:
        raise ValueError("missing or unbounded toolchain catalog")
    clang = tasks.get("toolchain-linux64-clang", {})
    if (
        clang.get("kind") != "toolchain"
        or clang.get("attributes", {}).get("local-toolchain") is not True
        or clang.get("attributes", {}).get("toolchain-artifact")
        != "public/build/clang.tar.zst"
        or not clang.get("optimization", {}).get("index-search")
    ):
        raise ValueError("missing source-defined public Linux clang")
    catalog = json.dumps(tasks, sort_keys=True).encode()
    if len(catalog) > 8 * 1024**2:
        raise ValueError("toolchain catalog byte budget exceeded")
    cache_dir = func_cache._cache_dir / func_cache._derive_cache_name(
        inspect.unwrap(toolchain_task_definitions)
    )
    dynamic = cache_dir / "_dynamic_inputs.json"
    if (
        dynamic.is_symlink()
        or not dynamic.is_file()
        or dynamic.stat().st_size > 1024**2
    ):
        raise ValueError("missing source cache dynamic inputs")
    extra = json.loads(dynamic.read_text())
    if (
        not isinstance(extra, list)
        or not 0 < len(extra) <= 4096
        or not all(isinstance(name, str) and name for name in extra)
    ):
        raise ValueError("missing source cache resource paths")
    key = func_cache._hash_inputs(["taskcluster", *extra], env_vars=CACHE_ENV)
    cache = cache_dir / (key + ".json")
    if cache.is_symlink() or not cache.is_file() or cache.stat().st_size > 8 * 1024**2:
        raise ValueError("missing or unsafe source cache entry")
    raw = cache.read_bytes()
    if json.loads(raw) != tasks:
        raise ValueError("source cache and catalog differ")
    return {
        "schema": "qa3-hosted-bootstrap-catalog-v1",
        "source": str(source.resolve()),
        "state": str(func_cache._cache_dir.parent.resolve()),
        "sourceCacheKey": key,
        "cacheBytes": len(raw),
        "cacheSha256": hashlib.sha256(raw).hexdigest(),
        "catalogBytes": len(catalog),
        "catalogSha256": hashlib.sha256(catalog).hexdigest(),
        "catalogTasks": len(tasks),
        "dynamicInputs": extra,
        "cacheEnvironment": {name: os.environ[name] for name in CACHE_ENV},
        "nativeExecuted": False,
        "publicationAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--phase", choices=("prepare", "verify"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = catalog_snapshot(args.source, args.phase)
    with args.output.open("x") as stream:
        json.dump(result, stream, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps({
            "phase": args.phase,
            "catalogSha256": result["catalogSha256"],
            "sourceCacheKey": result["sourceCacheKey"],
            "nativeExecuted": False,
        }),
        flush=True,
    )


if __name__ == "__main__":
    main()
