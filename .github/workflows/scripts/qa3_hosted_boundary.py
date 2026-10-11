# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""One disposable cold-consumer service; no builder or material publisher."""

import argparse
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qa3_hosted import (
    PROFILE,
    consume,
    context_from_environment,
    raw_git,
    require,
    validate_context,
    validate_producer,
    verify_consumer,
    verify_recipe_metadata,
)
from qa3_native_io import GIB, capture_material_tree, read_json, write_json
from qa3_source_cohort import file_digest

ROOT = Path("/var/lib/qa3-hosted-consumer")
FILES = (
    "qa3_hosted.py",
    "qa3_hosted_support.py",
    "qa3_hosted_boundary.py",
    "qa3_native_io.py",
    "qa3_native_transport.py",
    "qa3_mozlog.py",
    "qa3_source_cohort.py",
    "qa3_build_profile.py",
    "runtime_build_context.py",
    "qa3_xpcshell_entry.py",
)
METADATA = (
    ".github/runtime-upstream.json",
    ".github/qa/source-policy.json",
    ".github/qa/linux-proof-plan.json",
)
MAX_EXPORT = 128 * 1024**2


def protected(path):
    for component in (path, *path.parents):
        info = component.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o022,
            "unsafe root-owned ancestor",
        )
    return path


def make_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o755)
    protected(path)


def stage_inputs(source, destination):
    require(
        all(
            p.is_file() and not p.is_symlink() and p.stat().st_nlink == 1
            for p in source.iterdir()
        ),
        "unsafe controller input",
    )
    shutil.copytree(source, destination)
    destination.chmod(0o555)
    for path in destination.rglob("*"):
        require(not path.is_symlink(), "link in consumer inputs")
        path.chmod(0o555 if path.is_dir() else 0o444)


def service_command(spec):
    state = spec["state"]
    root = spec["root"]
    return [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--collect",
        "--service-type=exec",
        "--unit=" + spec["unit"],
        "--property=User=" + str(spec["uid"]),
        "--property=Group=" + str(spec["gid"]),
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=RuntimeMaxSec=3000s",
        "--property=CPUQuota=400%",
        "--property=CPUQuotaPeriodSec=100ms",
        f"--property=MemoryMax={14 * GIB}",
        "--property=MemorySwapMax=0",
        "--property=TasksMax=512",
        "--property=UMask=0077",
        "--property=LimitCORE=0",
        f"--property=LimitFSIZE={50 * GIB}",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateNetwork=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateUsers=yes",
        "--property=ProtectProc=invisible",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectHostname=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=InaccessiblePaths=-/run/user -/run/credentials /etc/shadow /etc/gshadow "
        + " ".join(spec["controllerPaths"]),
        "--property=ReadWritePaths=" + state,
        "--property=StandardInput=null",
        "--property=StandardOutput=append:" + root + "/evidence/native.stdout",
        "--property=StandardError=append:" + root + "/evidence/native.stderr",
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "HOME=" + state + "/home",
        "USER=qa3-native",
        "LOGNAME=qa3-native",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "TZ=UTC",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "/usr/bin/python3.12",
        "-I",
        root + "/recipe/.github/workflows/scripts/qa3_hosted_boundary.py",
        "worker",
        "--spec",
        root + "/spec.json",
    ]


def verify_worker(spec):
    require(
        os.getuid() == spec["uid"] > 0 and os.getgid() == spec["gid"],
        "wrong native account",
    )
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    require(
        status["NoNewPrivs"].strip() == "1" and int(status["CapEff"], 16) == 0,
        "worker retained privileges",
    )
    namespaces = {
        name: os.readlink("/proc/self/ns/" + name) for name in ("mnt", "net", "user")
    }
    require(
        all(namespaces[n] != spec["controllerNamespaces"][n] for n in namespaces),
        "native mount, network or user namespace was not isolated",
    )
    require(
        socket.if_nameindex() == [(1, "lo")]
        and not Path(f"/proc/{spec['controllerPID']}").exists()
        and all(not os.access(path, os.R_OK) for path in spec["controllerPaths"]),
        "native worker can observe controller process, network or inputs",
    )
    records = Path("/proc/self/cgroup").read_text().splitlines()
    require(len(records) == 1 and records[0].startswith("0::/"), "non-unified cgroup")
    relative = Path(records[0][3:])
    require(relative.name == spec["unit"], "wrong dedicated consumer service cgroup")
    group = Path("/sys/fs/cgroup") / str(relative).lstrip("/")
    expected = {
        "memory.max": str(14 * GIB),
        "memory.swap.max": "0",
        "pids.max": "512",
        "cpu.max": "400000 100000",
    }
    require(
        all(
            (group / name).read_text().strip() == value
            for name, value in expected.items()
        ),
        "consumer limits differ",
    )
    events = dict(
        line.split() for line in (group / "memory.events").read_text().splitlines()
    )
    require(events.get("oom") == events.get("oom_kill") == "0", "consumer OOM")
    return {"scope": str(relative), "limits": expected, "namespaces": namespaces}


def export_after_stop(root, complete, context):
    destination = root / "export"
    make_directory(destination)
    make_directory(destination / "logs")
    output = root / "state/output"
    allowed = {"consumer.json", "worker-failure.json"} | {
        f"logs/{phase}.{suffix}"
        for phase in (
            "cold-venv",
            "offline-install",
            "pip-check",
            "native-0-required",
            "native-0-assertion-canary",
            "native-1-required",
            "native-1-assertion-canary",
        )
        for suffix in ("stdout", "stderr", "process.json")
    }
    rows = []
    total = 0
    if output.exists():
        for path in output.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                continue
            name = path.relative_to(output).as_posix()
            info = path.lstat()
            require(
                name in allowed
                and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and not info.st_mode & 0o6111
                and info.st_size <= 16 * 1024**2,
                "arbitrary or oversized native output",
            )
            total += info.st_size
            require(total <= MAX_EXPORT, "consumer export budget exceeded")
            target = destination / name
            with path.open("rb") as source, target.open("xb") as sink:
                shutil.copyfileobj(source, sink, 1024**2)
            target.chmod(0o644)
            rows.append({
                "path": name,
                "bytes": target.stat().st_size,
                "sha256": file_digest(target),
            })
    if complete:
        require(
            not (destination / "worker-failure.json").exists(),
            "worker originally failed",
        )
        verify_consumer(
            destination,
            root / "state/support",
            read_json(root / "inputs/producer.json"),
            context,
        )
    write_json(
        destination / "export.json", {"schema": "qa3-hosted-export-v1", "files": rows}
    )
    (destination / "export.json").chmod(0o644)
    return rows


def launch(args):
    require(os.geteuid() == 0, "root disposable-consumer preparation required")
    inputs = args.inputs.resolve(strict=True)
    context = validate_context(read_json(inputs / "context.json"))
    require(
        {p.name for p in inputs.iterdir()}
        == {
            "context.json",
            "transport.json",
            "producer.json",
            "runtime.tar.xz",
            "test-support.tar.gz",
        },
        "arbitrary source/HOME/OBJDIR in controller inputs",
    )
    producer = validate_producer(read_json(inputs / "producer.json"), context)
    verify_recipe_metadata(args.recipe, producer)
    require(
        Path("/run/systemd/system").is_dir()
        and Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "fresh systemd cgroup-v2 VM required",
    )
    for name in ("/usr/bin/python3.12", "/usr/bin/xvfb-run", "/usr/bin/prlimit"):
        protected(Path(name).resolve(strict=True))
    try:
        pwd.getpwnam("qa3-native")
    except KeyError:
        pass
    else:
        raise ValueError("dedicated native account already exists")
    require(not ROOT.exists() and not ROOT.is_symlink(), "consumer root already exists")
    protected(ROOT.parent)
    make_directory(ROOT)
    root = ROOT / f"{context['run']}-1"
    make_directory(root)
    for name in (
        "recipe",
        "recipe/.github",
        "recipe/.github/qa",
        "recipe/.github/workflows",
        "recipe/.github/workflows/scripts",
        "evidence",
    ):
        make_directory(root / name)
    for name in FILES:
        relative = ".github/workflows/scripts/" + name
        raw = raw_git(
            args.recipe, "cat-file", "blob", context["runtimeRecipe"] + ":" + relative
        )
        require(
            raw == (args.recipe / relative).read_bytes(),
            "consumer code differs from raw R",
        )
        path = root / "recipe" / relative
        path.write_bytes(raw)
        path.chmod(0o444)
    for relative in METADATA:
        raw = raw_git(
            args.recipe, "cat-file", "blob", context["runtimeRecipe"] + ":" + relative
        )
        require(
            raw == (args.recipe / relative).read_bytes(), "metadata differs from raw R"
        )
        path = root / "recipe" / relative
        path.write_bytes(raw)
        path.chmod(0o444)
    stage_inputs(inputs, root / "inputs")
    subprocess.run(
        [
            "/usr/sbin/useradd",
            "--system",
            "--user-group",
            "--no-log-init",
            "--home-dir",
            str(root / "state/home"),
            "--shell",
            "/usr/sbin/nologin",
            "qa3-native",
        ],
        check=True,
        timeout=15,
        env={"PATH": "/usr/bin:/bin"},
    )
    native = pwd.getpwnam("qa3-native")
    state = root / "state"
    state.mkdir(mode=0o700)
    os.chown(state, native.pw_uid, native.pw_gid)
    spec = {
        "profile": PROFILE,
        "root": str(root),
        "state": str(state),
        "context": context,
        "uid": native.pw_uid,
        "gid": native.pw_gid,
        "unit": f"qa3-hosted-{context['run']}-1-consumer.service",
        "inputSnapshot": capture_material_tree(root / "inputs"),
        "controllerPID": os.getpid(),
        "controllerNamespaces": {
            name: os.readlink("/proc/self/ns/" + name)
            for name in ("mnt", "net", "user")
        },
        "controllerPaths": [str(args.recipe.resolve()), str(inputs.parent)],
    }
    require(
        all(
            path.startswith("/") and not re.search(r"\s", path)
            for path in spec["controllerPaths"]
        ),
        "unsafe controller path in service policy",
    )
    write_json(root / "spec.json", spec)
    (root / "spec.json").chmod(0o444)
    result = None
    first_failure = None
    clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    rows = []
    scope_empty = False

    def cancelled(signum, frame):
        raise KeyboardInterrupt

    handlers = {s: signal.signal(s, cancelled) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = subprocess.run(
            service_command(spec), env=clean, timeout=3060, check=False
        )
        if result.returncode:
            first_failure = "native service failed"
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        first_failure = "controller timeout or cancellation"
    finally:
        for action in (["kill", "--kill-whom=all", "--signal=KILL"], ["stop"]):
            try:
                subprocess.run(
                    ["/usr/bin/systemctl", *action, spec["unit"]],
                    env=clean,
                    timeout=15,
                    check=False,
                    capture_output=True,
                )
            except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
                first_failure = first_failure or "consumer cleanup failed"
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    try:
        group = Path("/sys/fs/cgroup/system.slice") / spec["unit"]
        require(
            not group.exists()
            or dict(
                line.split()
                for line in (group / "cgroup.events").read_text().splitlines()
            ).get("populated")
            == "0",
            "native children survived in service cgroup",
        )
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                try:
                    require(
                        entry.stat().st_uid != spec["uid"],
                        "native account process survived",
                    )
                except FileNotFoundError:
                    pass
        scope_empty = True
        require(
            capture_material_tree(root / "inputs") == spec["inputSnapshot"],
            "readonly inputs changed",
        )
        rows = export_after_stop(root, first_failure is None, context)
        for path in (root / "evidence").iterdir():
            require(
                path.is_file()
                and not path.is_symlink()
                and path.stat().st_size <= 16 * 1024**2,
                "unsafe service raw log",
            )
            path.chmod(0o644)
    except (ValueError, OSError, KeyboardInterrupt) as exc:
        first_failure = (
            first_failure
            or "consumer evidence or cleanup rejected: " + type(exc).__name__
        )
    write_json(
        root / "evidence/final.json",
        {
            "schema": "qa3-hosted-root-supervision-v1",
            "context": context,
            "status": "FAIL" if first_failure else "PASS",
            "reason": first_failure,
            "scopeEmpty": scope_empty,
            "serviceExit": None if result is None else result.returncode,
            "export": rows,
            "publicationAuthorized": False,
        },
    )
    (root / "evidence/final.json").chmod(0o644)
    require(first_failure is None, "original native consumer failed")


def collect(args):
    destination = args.output
    destination.mkdir(mode=0o700)
    context = context_from_environment(args.build_id)
    root = ROOT / f"{context['run']}-1"
    write_json(
        destination / "collection.json",
        {
            "schema": "qa3-hosted-collection-v1",
            "context": context,
            "status": "COLLECTION_STARTED",
            "acquireOutcome": os.environ.get("QA3_ACQUIRE_OUTCOME"),
            "launchOutcome": os.environ.get("QA3_LAUNCH_OUTCOME"),
            "publicationAuthorized": False,
        },
    )
    protected(root / "evidence")
    for folder in ("evidence", "export"):
        source = root / folder
        if not source.exists():
            continue
        total = 0
        for path in source.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                continue
            protected(path)
            info = path.stat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_size <= 16 * 1024**2,
                "unsafe controller export",
            )
            total += info.st_size
            require(total <= MAX_EXPORT, "controller evidence budget exceeded")
            target = destination / folder / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    final = read_json(destination / "evidence/final.json")
    require(
        final.get("schema") == "qa3-hosted-root-supervision-v1"
        and final.get("context") == context
        and final.get("status") == "PASS"
        and final.get("reason") is None
        and final.get("scopeEmpty") is True
        and final.get("serviceExit") == 0
        and final.get("publicationAuthorized") is False
        and os.environ.get("QA3_LAUNCH_OUTCOME") == "success",
        "original consumer job failed",
    )
    require(
        os.environ.get("QA3_ACQUIRE_OUTCOME") == "success",
        "original artifact acquisition failed",
    )
    rows = read_json(destination / "export/export.json")["files"]
    require(rows == final["export"], "root export receipt differs")
    for row in rows:
        path = destination / "export" / row["path"]
        require(
            path.stat().st_size == row["bytes"] and file_digest(path) == row["sha256"],
            "root evidence bytes changed",
        )
    write_json(
        destination / "collection-result.json",
        {
            "schema": "qa3-hosted-collection-result-v1",
            "context": context,
            "status": "PASS_DEBUG_HARNESS_ONLY",
            "publicationAuthorized": False,
        },
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write("verdict=PASS_DEBUG_HARNESS_ONLY\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("launch", "worker", "collect"))
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-id")
    args = parser.parse_args()
    if args.operation == "launch":
        launch(args)
    elif args.operation == "collect":
        try:
            collect(args)
        except BaseException as exc:
            if args.output.is_dir() and not args.output.is_symlink():
                write_json(
                    args.output / "collection-result.json",
                    {
                        "schema": "qa3-hosted-collection-result-v1",
                        "status": "INCOMPLETE",
                        "type": type(exc).__name__,
                        "publicationAuthorized": False,
                    },
                )
            raise
    else:
        spec = read_json(protected(args.spec))
        observation = verify_worker(spec)
        state = Path(spec["state"])
        (state / "home").mkdir(mode=0o700)
        try:
            result = consume(
                Path(spec["root"]) / "inputs",
                state,
                Path(spec["root"]) / "recipe",
                spec["context"],
            )
            require(
                verify_worker(spec) == observation, "native resource boundary changed"
            )
            require(result["context"] == spec["context"], "native context changed")
        except BaseException as exc:
            if (state / "output").is_dir():
                write_json(
                    state / "output/worker-failure.json",
                    {
                        "schema": "qa3-hosted-failure-v1",
                        "phase": "consumer",
                        "type": type(exc).__name__,
                        "status": "FAIL",
                        "publicationAuthorized": False,
                    },
                )
            raise


if __name__ == "__main__":
    main()
