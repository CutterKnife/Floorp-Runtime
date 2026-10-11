# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Same-run hosted Debug packaging and cold-consumer contracts."""

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qa3_hosted_support import (
    canary_case,
    harness_argv,
    install_canaries,
    merge_materials,
    verify_primary,
    verify_python_environment,
)
from qa3_mozlog import verify_mozlog
from qa3_native_io import (
    GIB,
    ExpansionBudget,
    IOBudget,
    capture_material_tree,
    child_environment,
    elf_identity,
    extract_archive,
    fresh,
    pack_tree,
    read_json,
    run_owned,
    write_json,
)
from qa3_native_transport import API, download_artifact, worker_boot_identity
from qa3_source_cohort import file_digest, hash_value, verify_patches
from runtime_build_context import derive_build_id, fetch_actions_run

REPOSITORY = "Floorp-Projects/Floorp-Runtime"
BRANCH = "codex/qa3-actions-native-proof"
WORKFLOW = ".github/workflows/qa3-hosted-linux-debug.yml"
PROFILE = "github-hosted-debug-to-blacksmith-consumer"
SEED_SHA = "e084ba7bb4b62a0581266319bfefd7f671bdeb3e39e7f7149de9657cb97a718c"
MAX_TRANSFER = 20 * GIB
MAX_ARTIFACT_STORAGE = 40 * GIB
WRAPPER_FILES = {"runtime.tar.xz", "test-support.tar.gz", "producer.json"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_mode(platform_name, arch, debug, pgo, mode=""):
    require(
        type(debug) is bool
        and type(pgo) is bool
        and (platform_name, arch, debug, pgo, mode)
        == ("linux", "x86_64", True, False, ""),
        "hosted proof requires native Linux x64 canonical Debug without PGO",
    )


def context_from_environment(build_id):
    require(re.fullmatch(r"[0-9]{14}", build_id), "invalid BuildID")
    sha = hash_value(os.environ["GITHUB_SHA"], 40)
    require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "push"
        and os.environ.get("GITHUB_REF") == "refs/heads/" + BRANCH
        and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
        and os.environ.get("GITHUB_WORKFLOW_SHA") == sha
        and os.environ.get("GITHUB_WORKFLOW_REF")
        == REPOSITORY + "/" + WORKFLOW + "@refs/heads/" + BRANCH,
        "foreign hosted workflow, source, branch or attempt",
    )
    event = read_json(Path(os.environ["GITHUB_EVENT_PATH"]))
    require(
        event.get("created") is True and event.get("deleted") is False,
        "proof is limited to first branch creation",
    )
    run = os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch(r"[1-9][0-9]*", run), "invalid run")
    return {
        "schema": "qa3-hosted-context-v1",
        "profile": PROFILE,
        "executionRepository": REPOSITORY,
        "controllerHead": sha,
        "runtimeRecipe": sha,
        "run": int(run),
        "attempt": 1,
        "buildID": build_id,
        "publicationAuthorized": False,
    }


def validate_context(value):
    require(
        set(value)
        == {
            "schema",
            "profile",
            "executionRepository",
            "controllerHead",
            "runtimeRecipe",
            "run",
            "attempt",
            "buildID",
            "publicationAuthorized",
        }
        and value["schema"] == "qa3-hosted-context-v1"
        and value["profile"] == PROFILE
        and value["executionRepository"] == REPOSITORY
        and value["controllerHead"] == value["runtimeRecipe"]
        and type(value["run"]) is int
        and value["run"] > 0
        and type(value["attempt"]) is int
        and value["attempt"] == 1
        and value["publicationAuthorized"] is False
        and re.fullmatch(r"[0-9]{14}", value["buildID"]),
        "invalid hosted context",
    )
    hash_value(value["runtimeRecipe"], 40)
    return value


def host_identity():
    release = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    value = {
        "os": release.get("ID", "").strip('"'),
        "version": release.get("VERSION_ID", "").strip('"'),
        "machine": platform.machine(),
        "pythonABI": f"cp{sys.version_info.major}{sys.version_info.minor}",
        "libc": list(platform.libc_ver()),
    }
    require(
        value["os"] == "ubuntu"
        and value["version"] == "24.04"
        and value["machine"] == "x86_64"
        and value["pythonABI"] == "cp312"
        and value["libc"][0] == "glibc",
        "unqualified hosted OS/architecture/Python/libc",
    )
    return value


def validate_effective(value, source, objdir):
    require(
        value.get("schemaVersion") == 1
        and value.get("source") == str(source.resolve())
        and value.get("objdir") == str(objdir.resolve()),
        "effective source/OBJDIR differs from existing build",
    )
    substs = value["substs"]
    for name in ("ENABLE_TESTS", "MOZ_DEBUG"):
        require(
            type(substs.get(name)) in {bool, int, str}
            and substs[name] in (True, 1, "1"),
            "effective Debug/tests missing",
        )
    for name in ("MOZ_ARTIFACT_BUILDS", "MOZ_PROFILE_GENERATE", "MOZ_PROFILE_USE"):
        require(substs.get(name) in (None, False, 0, "", "0"), "artifact/PGO build")
    require(
        substs.get("TARGET_CPU") == "x86_64"
        and substs.get("OS_TARGET") == "Linux"
        and substs.get("target") == "x86_64-pc-linux-gnu",
        "wrong effective native target",
    )


def raw_git(source, *args):
    return subprocess.check_output(
        [
            "/usr/bin/git",
            "-C",
            str(source),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "safe.directory=" + str(source.resolve()),
            *args,
        ],
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        timeout=60,
    )


def python_inputs(source, runtime, destination):
    lock = read_json(source / ".github/qa/hosted-consumer-python.lock.json")
    seed = source / ".github/qa/hosted-consumer-seed.zip"
    require(lock["seedSha256"] == SEED_SHA == file_digest(seed), "seed changed")
    require(
        lock.get("schema") == "qa3-hosted-consumer-python-lock-v1"
        and lock.get("readiness") == "INPUTS_LOCKED_NOT_TARGET_QUALIFIED"
        and lock.get("pythonABI") == "cp312"
        and lock.get("target") == "x86_64-pc-linux-gnu"
        and lock.get("publicationAuthorized") is False
        and len(lock["wheels"]) == 40
        and len({r["filename"] for r in lock["wheels"]}) == 40
        and all(
            type(r["bytes"]) is int and 0 < r["bytes"] <= 64 * 1024**2
            for r in lock["wheels"]
        )
        and sum(r["bytes"] for r in lock["wheels"]) <= 4 * 1024**2,
        "unqualified Python wheel lock",
    )
    fresh(destination)
    (destination / "wheelhouse").mkdir()
    with zipfile.ZipFile(seed) as z:
        provenance = [
            read_seed_json(z, "reference/source-wheels.provenance.json"),
            read_seed_json(z, "reference/marionette-source-wheel.provenance.json"),
        ]
        groups = provenance[0]["packages"]
        for package in groups:
            rows = package["trackedFiles"]
            expected = {r["path"] for r in rows}
            actual = set(
                raw_git(
                    source,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    runtime,
                    "--",
                    package["sourcePath"],
                )
                .decode()
                .splitlines()
            )
            require(actual == expected, "source wheel package tree changed at R")
            for row in rows:
                raw = raw_git(source, "cat-file", "blob", runtime + ":" + row["path"])
                require(
                    len(raw) == row["bytes"]
                    and hashlib.sha256(raw).hexdigest() == row["sha256"],
                    "source wheel blob changed at R",
                )
        marionette = provenance[1]["files"]
        require(
            set(
                raw_git(
                    source,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    runtime,
                    "--",
                    "testing/marionette/client",
                )
                .decode()
                .splitlines()
            )
            == {r["path"] for r in marionette},
            "marionette source tree changed",
        )
        for row in marionette:
            raw = raw_git(source, "cat-file", "blob", runtime + ":" + row["path"])
            require(
                len(raw) == row["bytes"]
                and hashlib.sha256(raw).hexdigest() == row["sha256"],
                "marionette source differs at R",
            )
        raw = z.read("profiles/consumer/requirements.lock")
        require(
            hashlib.sha256(raw).hexdigest() == lock["requirementsSha256"],
            "requirements changed",
        )
        (destination / "requirements.lock").write_bytes(raw)
        for item in lock["wheels"]:
            name = item["filename"]
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", name), "unsafe wheel")
            target = destination / "wheelhouse" / name
            if item["source"].startswith("source-wheels/"):
                raw = z.read(item["source"])
            else:
                parsed = urllib.parse.urlsplit(item["url"])
                require(
                    parsed.scheme == "https"
                    and parsed.hostname == "files.pythonhosted.org"
                    and not parsed.query
                    and not parsed.username,
                    "foreign wheel URL",
                )
                with urllib.request.urlopen(item["url"], timeout=30) as response:
                    raw = response.read(item["bytes"] + 1)
            require(
                len(raw) == item["bytes"]
                and hashlib.sha256(raw).hexdigest() == item["sha256"],
                "wheel bytes/hash differ",
            )
            target.write_bytes(raw)
    snapshot = capture_material_tree(destination)
    verify_python_environment(destination, snapshot["sha256"])
    return snapshot["sha256"]


def read_seed_json(z, name):
    from runtime_build_context import parse_rest_json

    return parse_rest_json(z.read(name))


def verify_compiled_source(value, pin, runtime):
    require(
        value.get("schema_version") == pin.get("schema_version") == 1
        and value.get("runtime_commit") == runtime
        and value.get("upstream") == pin.get("upstream")
        and value.get("floorp_patch") == pin.get("floorp_patch"),
        "compiled Firefox/Floorp source receipt differs from pinned distribution",
    )
    hash_value(pin["upstream"]["commit"], 40)
    hash_value(pin["floorp_patch"]["commit"], 40)
    hash_value(pin["floorp_patch"]["sha256"])


def verify_recipe_metadata(recipe, value):
    require(
        read_json(recipe / ".github/runtime-upstream.json") == value["runtimeUpstream"]
        and read_json(recipe / ".github/qa/source-policy.json") == value["sourcePolicy"]
        and file_digest(recipe / ".github/qa/linux-proof-plan.json")
        == value["planSha256"],
        "producer metadata differs from original Runtime recipe",
    )


def verify_support(support, value):
    require(
        capture_material_tree(support) == value["supportInventory"],
        "support inventory changed",
    )
    verify_python_environment(
        support / "python-environment", value["pythonEnvironmentSha256"]
    )
    require(file_digest(support / "plan.json") == value["planSha256"], "plan changed")
    plan = read_json(support / "plan.json")
    require(
        plan.get("role") == "canonical-debug"
        and plan.get("target") == "x86_64-pc-linux-gnu"
        and plan.get("publicationAuthorized") is False
        and len(plan["selection"]) == 2
        and [c["suite"] for c in plan["selection"]] == ["browser-chrome", "xpcshell"],
        "finite required Debug selection differs",
    )
    source_hashes = {r["path"]: r["sha256"] for r in plan["sourceMaterials"]}
    for case in plan["selection"]:
        require(
            case["requiredNoSkip"] is True
            and type(case["minimumAssertions"]) is int
            and case["minimumAssertions"] > 0
            and file_digest(support / case["archivePath"]) == source_hashes[case["id"]],
            "required packaged test differs from pinned source",
        )
        canary_case(case, support, value)
    for source, archive in (
        ("testing/mochitest/runtests.py", "mochitest/runtests.py"),
        ("testing/mochitest/mochitest_options.py", "mochitest/mochitest_options.py"),
        ("testing/xpcshell/runxpcshelltests.py", "xpcshell/runxpcshelltests.py"),
        ("testing/xpcshell/xpcshellcommandline.py", "xpcshell/xpcshellcommandline.py"),
        (
            "browser/base/content/test/performance/head.js",
            "mochitest/browser/browser/base/content/test/performance/head.js",
        ),
        (
            "xpcom/tests/unit/head_xpcom.js",
            "xpcshell/tests/xpcom/tests/unit/head_xpcom.js",
        ),
    ):
        require(
            file_digest(support / archive) == source_hashes[source],
            "packaged Mozilla harness differs",
        )
    require(
        {
            name: elf_identity(support / "bin" / name)
            for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
        }
        == value["helpers"],
        "same-build helper identity differs",
    )
    return plan


def producer_environment(source, objdir, build_id):
    env = child_environment(
        source, {"MOZ_BUILD_DATE": build_id, "MOZ_OBJDIR": str(objdir.resolve())}
    )
    env["MOZBUILD_STATE_PATH"] = os.environ.get(
        "MOZBUILD_STATE_PATH", str(Path(env["HOME"]) / ".mozbuild")
    )
    return env


def artifact_storage_budget(primary, output):
    entries = capture_material_tree(primary)["entries"]
    sizes = {row["path"]: (primary / row["path"]).stat().st_size for row in entries}
    primary_bytes = sum(sizes.values())
    host_bytes = sum(
        size for path, size in sizes.items() if path.startswith("dist-host/")
    )
    application_bytes = sizes["floorp-application.ini"]
    support_bytes = sum(
        (output / name).stat().st_size
        for name in ("runtime.tar.xz", "test-support.tar.gz")
    )
    total = (
        primary_bytes
        + host_bytes
        + application_bytes
        + support_bytes
        + 16 * 1024**2
        + 512 * 1024**2
    )
    require(total <= MAX_ARTIFACT_STORAGE, "whole-run artifact storage budget exceeded")
    return {
        "maximumBytes": MAX_ARTIFACT_STORAGE,
        "boundedBytes": total,
        "retentionDays": 1,
        "primaryBundleBytes": primary_bytes,
        "distHostDuplicateBytes": host_bytes,
        "applicationDuplicateBytes": application_bytes,
        "consumerAndDiagnosticsReservedBytes": 512 * 1024**2,
    }


def produce(args):
    context = context_from_environment(args.build_id)
    require(
        raw_git(args.source, "rev-parse", "HEAD").decode().strip()
        == context["runtimeRecipe"],
        "checkout differs from original R",
    )
    host = host_identity()
    output = fresh(args.output)
    logs = fresh(output / "logs")
    budget = IOBudget(output)
    expansion = ExpansionBudget()
    env = producer_environment(args.source, args.objdir, context["buildID"])
    commands = []

    def command(name, argv, timeout, **kwargs):
        result = run_owned(
            argv,
            args.source,
            env,
            logs,
            name,
            timeout,
            log_limit=16 * 1024**2,
            **kwargs,
        )
        commands.append(result)
        return result

    effective = output / "effective-config.json"
    command(
        "effective-config",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "python",
            "--virtualenv",
            "build",
            str(Path(__file__).parent / "qa3_config_probe.py"),
            "--source",
            str(args.source),
            "--objdir",
            str(args.objdir),
            "--output",
            str(effective),
        ],
        120,
    )
    effective_value = read_json(effective)
    validate_effective(effective_value, args.source, args.objdir)
    packages = sorted(args.primary.glob("*.tar.xz"))
    require(
        len(packages) == 1 and not packages[0].is_symlink(),
        "existing primary package missing",
    )
    primary = output / "runtime.tar.xz"
    shutil.copyfile(packages[0], primary)
    primary_root = output / "primary-expanded"
    extract_archive(primary, primary_root, budget=budget, expansion=expansion)
    identity = verify_primary(primary_root, context)
    compiled_identity = verify_primary(
        args.objdir / "dist",
        context,
        app=args.objdir / "dist/bin",
        object_root=args.objdir,
    )
    require(
        all(
            identity[k]["gnuBuildID"] == compiled_identity[k]["gnuBuildID"]
            for k in identity
        ),
        "packaged primary differs from same OBJDIR build",
    )
    command(
        "package-tests",
        [
            "/usr/bin/python3.12",
            str(args.source / "mach"),
            "build",
            "--jobs=1",
            "package-tests-common",
            "package-tests-mochitest",
            "package-tests-xpcshell",
        ],
        1800,
    )
    support = fresh(output / "support-expanded")
    archives = []
    for kind in ("common", "mochitest", "xpcshell"):
        matches = sorted((args.objdir / "dist").rglob(f"*.{kind}.tests.*"))
        require(
            len(matches) == 1 and not matches[0].is_symlink(),
            "missing same-OBJDIR tests",
        )
        archive = matches[0]
        archives.append({
            "kind": kind,
            "sha256": file_digest(archive),
            "bytes": archive.stat().st_size,
        })
        require(archive.name.endswith(".tar.zst"), "unqualified test archive format")
        command(
            "decode-" + kind,
            ["/usr/bin/zstd", "-d", "--stdout", "--", str(archive)],
            600,
            data_stdout=True,
            data_limit=30 * GIB,
            io_budget=budget,
        )
        archive = logs / ("decode-" + kind + ".stdout")
        stage = output / ("archive-" + kind)
        extract_archive(archive, stage, budget=budget, expansion=expansion)
        merge_materials(stage, support, budget)
        budget.release_tree(stage)
        if archive.parent == logs:
            budget.release_tree(archive)
    plan = read_json(args.source / ".github/qa/linux-proof-plan.json")
    for row in plan["sourceMaterials"]:
        require(
            file_digest(args.source / row["path"]) == row["sha256"],
            "actual source differs from pinned harness/test selection",
        )
    transforms = install_canaries(args.source, support, plan)
    shutil.copyfile(
        args.source / ".github/qa/linux-proof-plan.json", support / "plan.json"
    )
    python_sha = python_inputs(
        args.source, context["runtimeRecipe"], support / "python-environment"
    )
    helpers = {
        name: elf_identity(support / "bin" / name)
        for name in ("xpcshell", "ssltunnel", "certutil", "pk12util")
    }
    for name in ("modules", "certs", "mozbase", "mochitest", "xpcshell"):
        require(
            (support / name).is_dir() and any((support / name).iterdir()),
            "incomplete support",
        )
    support_sha = pack_tree(support, output / "test-support.tar.gz", budget)
    source_record = read_json(args.primary / "runtime-source-provenance.json")
    upstream = read_json(args.source / ".github/runtime-upstream.json")
    verify_compiled_source(source_record, upstream, context["runtimeRecipe"])
    policy = read_json(args.source / ".github/qa/source-policy.json")
    for field, directory in (("commonPatches", "upstream"), ("debugPatches", "debug")):
        verify_patches(args.source, policy[field], ".github/patches/" + directory)
    changes = raw_git(
        args.source, "diff", "--binary", "HEAD", "--", ".", ":(exclude).github"
    )
    receipt = {
        "schema": "qa3-hosted-debug-producer-v1",
        "status": "PACKAGED_NOT_CONSUMED",
        "context": context,
        "bootSha256": worker_boot_identity(),
        "host": host,
        "objdir": str(args.objdir.resolve()),
        "effectiveConfig": effective_value,
        "runtimeUpstream": upstream,
        "sourcePolicy": policy,
        "actualSourceDeltaSha256": hashlib.sha256(changes).hexdigest(),
        "compiledSource": source_record,
        "archives": archives,
        "commands": commands,
        "primarySha256": file_digest(primary),
        "primaryIdentity": identity,
        "compiledIdentity": compiled_identity,
        "supportSha256": support_sha,
        "supportInventory": capture_material_tree(support),
        "pythonEnvironmentSha256": python_sha,
        "helpers": helpers,
        "planSha256": file_digest(support / "plan.json"),
        "canaryTransforms": transforms,
        "producer": "existing-common-build-github-hosted",
        "consumerVerdict": "UNVERIFIED",
        "publicationAuthorized": False,
        "artifactStorageBudget": artifact_storage_budget(args.primary, output),
    }
    verify_support(support, receipt)
    write_json(output / "producer.json", receipt)
    require(
        (output / "producer.json").stat().st_size <= 16 * 1024**2,
        "producer receipt budget exceeded",
    )
    require(
        sum((output / name).stat().st_size for name in WRAPPER_FILES)
        <= MAX_TRANSFER - 1024**2,
        "producer transport budget exceeded",
    )
    return receipt


def validate_producer(value, context):
    validate_context(context)
    require(
        value.get("schema") == "qa3-hosted-debug-producer-v1"
        and value.get("status") == "PACKAGED_NOT_CONSUMED"
        and value.get("context") == context
        and value.get("producer") == "existing-common-build-github-hosted"
        and value.get("consumerVerdict") == "UNVERIFIED"
        and value.get("publicationAuthorized") is False,
        "foreign or incomplete producer",
    )
    hash_value(value["bootSha256"])
    require(
        value["bootSha256"] != worker_boot_identity(), "consumer reused producer boot"
    )
    require(value["host"] == host_identity(), "producer/consumer OS ABI differs")
    verify_compiled_source(
        value["compiledSource"], value["runtimeUpstream"], context["runtimeRecipe"]
    )
    require(
        all(
            value["primaryIdentity"][k]["gnuBuildID"]
            == value["compiledIdentity"][k]["gnuBuildID"]
            for k in ("floorp", "libxul.so")
        ),
        "same OBJDIR binary identity differs",
    )
    effective = value["effectiveConfig"]
    validate_effective(effective, Path(effective["source"]), Path(value["objdir"]))
    require(
        [r["kind"] for r in value["archives"]] == ["common", "mochitest", "xpcshell"],
        "missing original test archives",
    )
    for row in value["archives"]:
        hash_value(row["sha256"])
        require(
            type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_TRANSFER,
            "invalid original test archive size",
        )
    for name in (
        "primarySha256",
        "supportSha256",
        "planSha256",
        "pythonEnvironmentSha256",
        "actualSourceDeltaSha256",
    ):
        hash_value(value[name])
    require(
        all(
            type(c.get("exit")) is int
            and c["exit"] == 0
            and c.get("stop") is None
            and c.get("ownedCleanupComplete") is True
            and not c.get("cancelled")
            and not c.get("error")
            and not c.get("cleanupErrors")
            for c in value["commands"]
        )
        and [c["name"] for c in value["commands"]]
        == [
            "effective-config",
            "package-tests",
            "decode-common",
            "decode-mochitest",
            "decode-xpcshell",
        ],
        "unexecuted, skipped, retried or failing producer phase",
    )
    return value


def acquire(args):
    context = context_from_environment(args.build_id)
    payload = fetch_actions_run(
        api_url=API,
        repository=REPOSITORY,
        workflow_run_id=str(context["run"]),
        github_token=os.environ["GITHUB_TOKEN"],
    )
    require(
        payload.get("id") == context["run"]
        and payload.get("head_sha") == context["runtimeRecipe"]
        and payload.get("run_attempt") == 1
        and payload.get("event") == "push"
        and payload.get("path") == WORKFLOW
        and payload.get("head_branch") == BRANCH,
        "REST run differs from original same-workflow producer",
    )
    require(
        derive_build_id(payload["created_at"]) == context["buildID"],
        "BuildID differs from original run creation",
    )
    fresh(args.output)
    archive = args.output / "original.zip"
    download_artifact(
        context,
        args.artifact_id,
        "support",
        args.artifact_sha256,
        archive,
    )
    destination = fresh(args.output / "inputs")
    unpack_wrapper(archive, destination)
    producer = validate_producer(read_json(destination / "producer.json"), context)
    verify_recipe_metadata(args.recipe, producer)
    require(
        file_digest(destination / "runtime.tar.xz") == producer["primarySha256"]
        and file_digest(destination / "test-support.tar.gz")
        == producer["supportSha256"],
        "original producer payload differs",
    )
    write_json(destination / "context.json", context)
    write_json(
        destination / "transport.json",
        {
            "artifactId": args.artifact_id,
            "zipSha256": args.artifact_sha256,
            "context": context,
        },
    )


def unpack_wrapper(archive, destination):
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        require(
            len(members) == len(WRAPPER_FILES)
            and {m.filename for m in members} == WRAPPER_FILES
            and sum(m.file_size for m in members) <= MAX_TRANSFER,
            "unsafe original artifact wrapper",
        )
        for m in members:
            require(
                not m.flag_bits & 1
                and (m.external_attr >> 16) & 0o170000 in (0, 0o100000),
                "special/encrypted artifact member",
            )
            with z.open(m) as source, (destination / m.filename).open("xb") as sink:
                shutil.copyfileobj(source, sink, 1024**2)


def consume(inputs, state, recipe, context):
    require(
        os.geteuid() > 0
        and not any(
            k.startswith(("GITHUB", "ACTIONS"))
            or any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD"))
            for k in os.environ
        ),
        "native worker sees controller credentials",
    )
    value = validate_producer(read_json(inputs / "producer.json"), context)
    require(
        file_digest(inputs / "runtime.tar.xz") == value["primarySha256"]
        and file_digest(inputs / "test-support.tar.gz") == value["supportSha256"],
        "input bytes changed",
    )
    output = fresh(state / "output")
    logs = fresh(output / "logs")
    env = child_environment(state)
    budget = IOBudget(state)
    expansion = ExpansionBudget()
    commands = []

    def command(name, argv, timeout, **kw):
        result = run_owned(
            argv,
            state,
            env,
            logs,
            name,
            timeout,
            memory=14 * GIB,
            log_limit=16 * 1024**2,
            **kw,
        )
        commands.append(result)
        return result

    app_root = state / "primary"
    support = state / "support"
    extract_archive(
        inputs / "runtime.tar.xz", app_root, budget=budget, expansion=expansion
    )
    extract_archive(
        inputs / "test-support.tar.gz", support, budget=budget, expansion=expansion
    )
    require(
        verify_primary(app_root, context) == value["primaryIdentity"],
        "binary ELF identity changed",
    )
    verify_recipe_metadata(recipe, value)
    plan = verify_support(support, value)
    app = app_root / "floorp"
    venv = state / "venv"
    command("cold-venv", ["/usr/bin/python3.12", "-I", "-m", "venv", str(venv)], 120)
    python = str(venv / "bin/python")
    offline = support / "python-environment"
    command(
        "offline-install",
        [
            python,
            "-I",
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--require-hashes",
            "--only-binary=:all:",
            "--find-links",
            str(offline / "wheelhouse"),
            "-r",
            str(offline / "requirements.lock"),
        ],
        180,
    )
    command("pip-check", [python, "-I", "-m", "pip", "check"], 60)
    modules = [support / "modules", support, *sorted((support / "mozbase").iterdir())]
    require(all(p.is_dir() for p in modules), "missing mozbase roots")
    env.update(
        PYTHONPATH=":".join(map(str, modules)),
        MOZ_HEADLESS="1",
        LIBGL_ALWAYS_SOFTWARE="1",
        LD_LIBRARY_PATH=str(app) + ":" + str(support / "bin"),
    )
    cases = []
    require(
        len(plan["selection"]) == 2
        and {c["suite"] for c in plan["selection"]} == {"browser-chrome", "xpcshell"},
        "finite suites differ",
    )
    for index, case in enumerate(plan["selection"]):
        for canary in (False, True):
            selected = canary_case(case, support, value) if canary else case
            name = f"native-{index}-{'assertion-canary' if canary else 'required'}"
            argv = [
                "/usr/bin/xvfb-run",
                "-a",
                *harness_argv(
                    python, support, app, selected, state / (name + "-profile")
                ),
            ]
            if selected["suite"] == "xpcshell":
                argv[4] = str(
                    recipe / ".github/workflows/scripts/qa3_xpcshell_entry.py"
                )
                env["QA3_XPCSHELL_SUPPORT"] = str(support)
            else:
                env.pop("QA3_XPCSHELL_SUPPORT", None)
            result = command(name, argv, 600, allow_nonzero=canary)
            verdict = verify_mozlog(
                logs / (name + ".stdout"), selected, support, result, canary=canary
            )
            cases.append({
                "name": name,
                "suite": case["suite"],
                "canary": canary,
                "process": result,
                "mozlog": verdict,
            })
    require(
        capture_material_tree(support) == value["supportInventory"]
        and verify_primary(app_root, context) == value["primaryIdentity"],
        "harness mutated inputs",
    )
    receipt = {
        "schema": "qa3-hosted-cold-consumer-v1",
        "status": "PASS",
        "context": context,
        "producerBootSha256": value["bootSha256"],
        "consumerBootSha256": worker_boot_identity(),
        "commands": commands,
        "cases": cases,
        "nativeProductQualification": "UNVERIFIED",
        "publicationAuthorized": False,
    }
    write_json(output / "consumer.json", receipt)
    return receipt


def verify_consumer(output, support, producer, context):
    value = read_json(output / "consumer.json")
    require(
        value.get("schema") == "qa3-hosted-cold-consumer-v1"
        and value.get("status") == "PASS"
        and value.get("context") == context
        and value.get("producerBootSha256") == producer["bootSha256"]
        and value.get("consumerBootSha256") == worker_boot_identity()
        and value.get("nativeProductQualification") == "UNVERIFIED"
        and value.get("publicationAuthorized") is False,
        "incomplete native result",
    )
    phases = [
        "cold-venv",
        "offline-install",
        "pip-check",
        "native-0-required",
        "native-0-assertion-canary",
        "native-1-required",
        "native-1-assertion-canary",
    ]
    require(
        [r["name"] for r in value["commands"]] == phases and len(value["cases"]) == 4,
        "native phase skipped, duplicated or retried",
    )
    for command in value["commands"]:
        name = command["name"]
        require(
            type(command.get("exit")) is int
            and command["exit"] == (1 if name.endswith("assertion-canary") else 0)
            and command.get("stop") is None
            and command.get("ownedCleanupComplete") is True
            and command.get("stdoutIsData") is False
            and not command.get("cancelled")
            and not command.get("error")
            and not command.get("cleanupErrors"),
            "original native phase failed",
        )
        require(
            read_json(output / "logs" / (name + ".process.json")) == command
            and file_digest(output / "logs" / (name + ".stdout"))
            == command["stdoutSha256"]
            and file_digest(output / "logs" / (name + ".stderr"))
            == command["stderrSha256"],
            "original native raw evidence differs",
        )
    plan = verify_support(support, producer)
    for index, item in enumerate(value["cases"]):
        case = plan["selection"][index // 2]
        canary = bool(index % 2)
        selected = canary_case(case, support, producer) if canary else case
        command = value["commands"][index + 3]
        require(
            item["name"] == command["name"]
            and item["suite"] == case["suite"]
            and item["canary"] is canary
            and item["process"] == command
            and item["mozlog"]
            == verify_mozlog(
                output / "logs" / (command["name"] + ".stdout"),
                selected,
                support,
                command,
                canary=canary,
            ),
            "raw Mozilla outcome differs",
        )
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("produce", "acquire", "worker"))
    for name in (
        "source",
        "objdir",
        "primary",
        "output",
        "inputs",
        "state",
        "recipe",
        "context",
    ):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--build-id")
    parser.add_argument("--artifact-id", type=int)
    parser.add_argument("--artifact-sha256")
    args = parser.parse_args()
    if args.operation == "produce":
        try:
            produce(args)
        except BaseException as exc:
            if args.output and args.output.is_dir():
                write_json(
                    args.output / "failure.json",
                    {
                        "schema": "qa3-hosted-failure-v1",
                        "phase": "producer",
                        "type": type(exc).__name__,
                        "status": "FAIL",
                        "publicationAuthorized": False,
                    },
                )
            raise
    elif args.operation == "acquire":
        acquire(args)
    else:
        consume(
            args.inputs,
            args.state,
            args.recipe,
            validate_context(read_json(args.context)),
        )


if __name__ == "__main__":
    main()
