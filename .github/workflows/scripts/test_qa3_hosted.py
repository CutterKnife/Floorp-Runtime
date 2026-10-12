# SPDX-License-Identifier: MPL-2.0

import ast
import copy
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import qa3_hosted as hosted
import qa3_hosted_boundary as boundary
from qa3_mozlog import verify_mozlog
from qa3_native_io import GIB, IOBudget, extract_archive, read_json, write_json
from qa3_native_transport import verify_artifact_metadata
from qa3_source_cohort import file_digest

SOURCE = Path(__file__).resolve().parents[3]
SHA = "a" * 40
DIGEST = "b" * 64
BOOT = "c" * 64
HOST = {
    "os": "ubuntu",
    "version": "24.04",
    "machine": "x86_64",
    "pythonABI": "cp312",
    "libc": ["glibc", "2.39"],
}
PHASES = [
    "cold-venv",
    "offline-install",
    "pip-check",
    "native-0-required",
    "native-0-assertion-canary",
    "native-1-required",
    "native-1-assertion-canary",
]


ORIGINAL_BUILD_STEP_DIGESTS = {
    "Validate build identity": "1db4d544a310a669ba8ecd55bf89e33c83a6d121ee13e12ff254b87f58490dc0",
    "Setup Node.js": "849ad66f6e99d7d823c487f689dbec3b3813e38283f197decfeb11205f87746d",
    "Checkout repository": "4aa7df71361cc2f7e93867ca8943d6e8510878717baebf483f997150a92a3d54",
    "Download macOS SDK": "0228e12ea23df96c9e7c2c259f087d3d697de6d25d4412c4190e8526fac5cb6f",
    "Setup macOS cross-compilation": "0ab58a044180bb159b0779bd6f4042b2adac69744b3a5007a21b0e92093d6f41",
    "Apply upstream patches": "294c76de999bdaffd10d47cde1756eb623f71cb297797087abd7014b8e13eeeb",
    "Setup sccache": "c0938be9679c1b22619d82963429b6baa32b12cbd35749a5432e8f65ceddee64",
    "Setup Rust toolchain": "cb02c53ff90ac371f670c905b5acd67eb6484ff64d2fb10199180da75c3da00c",
    "Allocate swap space": "05005de237107f34d0ccfcb2a6b04923560479589d65d86626293f5dad520d38",
    "Download PGO artifact": "069e23f3dd5a03d63e8747dc59c80aafbb0cd357da890068d152ba295cd5fdf6",
    "Setup floorp configuration": "595ce2e09ae1d8445abd1dadad60229545509b13ca6bc337eb374ff2b4163ae2",
    "Build and package": "84aea376e5ce3c3c4c89770eb449cdd561c44600d68c17cf61bf93f3f55b2326",
    "Verify and record compiled Runtime source": "ea2661cd2b3c1488f7514100b90540fd63c2b7d49ad2e60c482e56f95dde1e72",
    "Upload build artifact": "ebe9da54032640ac1c9574621b862c92ddc353a04c191482fcb2572e5d953f71",
    "Upload PGO profile generation package (Windows)": "26e87d3c02eadf4418f623378eb4a4978ce254f37702e5f5c95333d51d49a0b9",
    "Upload PGO profile generation package (Linux)": "344bd62536afaef56bbf506b43c27c40dfa0621e6a8aa574787d5e6f62cf9865",
    "Upload PGO profile generation package (Mac)": "cfb1dff2447d1709d23fd86332ef5496ea133c8f6bb024f01bbd14aa81c1b6d8",
    "Upload dist/host for MAR": "b0756e3841526acf4fecdaee31e865091a3a67386815275a855e11154602540c",
    "Upload application.ini for MAR": "bca285ffc9e5d815fec3c9c1921fdbe9e88cc76f120d5208a4e275a68baabf79",
}


def context():
    return {
        "schema": "qa3-hosted-context-v1",
        "profile": hosted.PROFILE,
        "executionRepository": hosted.REPOSITORY,
        "controllerHead": SHA,
        "runtimeRecipe": SHA,
        "run": 10,
        "attempt": 1,
        "buildID": "20261011000000",
        "publicationAuthorized": False,
    }


def effective():
    return {
        "schemaVersion": 1,
        "source": "/source",
        "objdir": "/source/obj",
        "substs": {
            "ENABLE_TESTS": True,
            "MOZ_DEBUG": True,
            "MOZ_ARTIFACT_BUILDS": False,
            "MOZ_PROFILE_GENERATE": False,
            "MOZ_PROFILE_USE": False,
            "TARGET_CPU": "x86_64",
            "OS_TARGET": "Linux",
            "target": "x86_64-pc-linux-gnu",
        },
    }


def producer():
    pin = read_json(SOURCE / ".github/runtime-upstream.json")
    identities = {
        name: {"sha256": DIGEST, "gnuBuildID": "ab", "machine": "x86_64"}
        for name in ("floorp", "libxul.so")
    }
    return {
        "schema": "qa3-hosted-debug-producer-v1",
        "status": "PACKAGED_NOT_CONSUMED",
        "context": context(),
        "producer": "existing-common-build-github-hosted",
        "consumerVerdict": "UNVERIFIED",
        "publicationAuthorized": False,
        "bootSha256": BOOT,
        "host": HOST,
        "objdir": "/source/obj",
        "effectiveConfig": effective(),
        "runtimeUpstream": pin,
        "sourcePolicy": read_json(SOURCE / ".github/qa/source-policy.json"),
        "compiledSource": {
            "schema_version": 1,
            "runtime_commit": SHA,
            "upstream": pin["upstream"],
            "floorp_patch": pin["floorp_patch"],
        },
        "archives": [
            {"kind": k, "bytes": 1, "sha256": DIGEST}
            for k in ("common", "mochitest", "xpcshell")
        ],
        "commands": [
            {"name": n, "exit": 0, "stop": None, "ownedCleanupComplete": True}
            for n in (
                "effective-config",
                "package-tests",
                "decode-common",
                "decode-mochitest",
                "decode-xpcshell",
            )
        ],
        "primaryIdentity": identities,
        "compiledIdentity": copy.deepcopy(identities),
        **{
            n: DIGEST
            for n in (
                "primarySha256",
                "supportSha256",
                "planSha256",
                "pythonEnvironmentSha256",
                "actualSourceDeltaSha256",
            )
        },
    }


class HostedEntryBudgets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def probe(self, role, mode):
        maximum, reserve = (
            (30 * GIB, 20 * GIB)
            if role == "producer"
            else (
                50 * GIB,
                10 * GIB,
            )
        )
        inputs = self.root / "inputs"
        inputs.mkdir()
        archive = inputs / "runtime.tar.xz"
        with tarfile.open(archive, "w:xz") as output:
            member = tarfile.TarInfo("fixture")
            member.size = 4
            output.addfile(member, io.BytesIO(b"data"))
        state = self.root / "state"
        source = self.root / "source"
        source.mkdir()
        args = SimpleNamespace(
            source=source,
            objdir=source / "obj",
            output=state,
            primary=inputs,
            build_id=context()["buildID"],
        )
        value = producer()
        value["primarySha256"] = file_digest(archive)
        (inputs / "test-support.tar.gz").write_bytes(b"synthetic support")
        value["supportSha256"] = file_digest(inputs / "test-support.tar.gz")
        write_json(inputs / "producer.json", value)
        budgets = []

        class ProbeComplete(Exception):
            pass

        def extract(path, destination, *, budget, expansion):
            self.assertIsInstance(budget, IOBudget)
            self.assertEqual(budget.root, state)
            self.assertEqual(budget.maximum, maximum)
            self.assertEqual(budget.minimum_free, reserve)
            budgets.append(budget)
            if mode == "cumulative":
                budget.used = maximum
            extract_archive(path, destination, budget=budget, expansion=expansion)
            self.assertEqual((destination / "fixture").read_bytes(), b"data")
            raise ProbeComplete

        def command(argv, cwd, env, logs, name, timeout, **kwargs):
            self.assertEqual(name, "effective-config")
            config = effective()
            config.update(source=str(source), objdir=str(args.objdir))
            write_json(state / "effective-config.json", config)
            return {"name": name, "exit": 0}

        expected = ProbeComplete if mode == "available" else ValueError
        message = {
            "available": "",
            "reserve": "native I/O would consume reserved free space",
            "cumulative": "cumulative staging byte budget exceeded",
        }[mode]
        free = reserve if mode == "reserve" else 100 * GIB
        with mock.patch.dict(
            os.environ, {"HOME": str(self.root), "PATH": os.defpath}, clear=True
        ), mock.patch.object(
            hosted, "context_from_environment", return_value=context()
        ), mock.patch.object(
            hosted, "raw_git", return_value=(SHA + "\n").encode()
        ), mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(
            hosted, "worker_boot_identity", return_value="d" * 64
        ), mock.patch.object(hosted.os, "geteuid", return_value=1001), mock.patch(
            "qa3_native_io.shutil.disk_usage", return_value=SimpleNamespace(free=free)
        ), mock.patch.object(
            hosted, "run_owned", side_effect=command
        ) as commands, mock.patch.object(
            hosted, "extract_archive", side_effect=extract
        ) as extracts, self.assertRaisesRegex(expected, message):
            if role == "producer":
                hosted.produce(args)
            else:
                hosted.consume(inputs, state, SOURCE, context())
        self.assertEqual(commands.call_count, 1 if role == "producer" else 0)
        self.assertEqual(extracts.call_count, 1)
        self.assertEqual(len(budgets), 1)
        self.assertEqual(
            budgets[0].used,
            maximum if mode == "cumulative" else 4 if mode == "available" else 0,
        )

    def test_producer_entry_extracts_with_bounded_real_io(self):
        self.probe("producer", "available")

    def test_producer_entry_rejects_reserved_space_exhaustion(self):
        self.probe("producer", "reserve")

    def test_producer_entry_rejects_cumulative_staging_overflow(self):
        self.probe("producer", "cumulative")

    def test_consumer_entry_extracts_with_bounded_real_io(self):
        self.probe("consumer", "available")

    def test_consumer_entry_rejects_reserved_space_exhaustion(self):
        self.probe("consumer", "reserve")

    def test_consumer_entry_rejects_cumulative_staging_overflow(self):
        self.probe("consumer", "cumulative")


class HostedSourceStamping(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        hosted.raw_git(self.source, "init", "-q", "--initial-branch=qa3")
        hosted.raw_git(
            self.source,
            "-c",
            "user.name=QA3 fixture",
            "-c",
            "user.email=qa3@example.invalid",
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-q",
            "-m",
            "QA3 source fixture",
        )
        self.sha = hosted.raw_git(self.source, "rev-parse", "HEAD").decode().strip()
        self.value = context()
        self.value.update(controllerHead=self.sha, runtimeRecipe=self.sha)
        self.event = self.root / "event.json"
        self.event.write_text(json.dumps({"created": True, "deleted": False}))
        self.github_env = self.root / "github-env"
        self.github_env.write_text("EXISTING=value\n")
        self.environment = {
            "HOME": str(self.root),
            "PATH": os.defpath,
            "GITHUB_WORKSPACE": str(self.source),
            "GITHUB_REPOSITORY": hosted.REPOSITORY,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + hosted.BRANCH,
            "GITHUB_SHA": self.sha,
            "GITHUB_WORKFLOW_SHA": self.sha,
            "GITHUB_WORKFLOW_REF": hosted.REPOSITORY
            + "/"
            + hosted.WORKFLOW
            + "@refs/heads/"
            + hosted.BRANCH,
            "GITHUB_RUN_ID": "10",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_PATH": str(self.event),
            "GITHUB_ENV": str(self.github_env),
            "QA3_PLATFORM": "linux",
            "QA3_ARCH": "x86_64",
            "QA3_DEBUG": "true",
            "QA3_PGO": "false",
            "QA3_PGO_MODE": "",
            "QA3_BUILD_ID": self.value["buildID"],
        }

    def workflow_entry(self, overrides=None):
        workflow = (SOURCE / ".github/workflows/common-build.yml").read_text()
        step = workflow.split("      - name: Validate opt-in Debug test route\n", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        code = step.split("python3.12 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
        code = "\n".join(line[10:] for line in code.splitlines())
        with mock.patch.dict(
            os.environ, {**self.environment, **(overrides or {})}, clear=True
        ):
            exec(
                compile(code, "common-build:Validate opt-in Debug test route", "exec"),
                {},
            )

    def test_workflow_emits_full_verified_checkout_and_canonical_repository(self):
        self.workflow_entry()
        self.assertEqual(
            self.github_env.read_text(),
            "EXISTING=value\nMOZ_SOURCE_REPO=https://github.com/"
            + hosted.REPOSITORY
            + "\nMOZ_SOURCE_CHANGESET="
            + self.sha
            + "\n",
        )

    def test_foreign_checkout_cannot_emit_configure_source_identity(self):
        with self.assertRaisesRegex(ValueError, "checkout differs from original R"):
            self.workflow_entry({"GITHUB_SHA": SHA, "GITHUB_WORKFLOW_SHA": SHA})
        self.assertEqual(self.github_env.read_text(), "EXISTING=value\n")

    def test_conflicting_inherited_stamp_is_rejected_before_environment_write(self):
        for key, value in (
            ("MOZ_SOURCE_REPO", "https://example.invalid/foreign"),
            ("MOZ_SOURCE_CHANGESET", self.sha[:12]),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "conflicting inherited source identity"
            ):
                self.workflow_entry({key: value})
            self.assertEqual(self.github_env.read_text(), "EXISTING=value\n")

    def test_matching_inherited_source_identity_is_preserved(self):
        self.workflow_entry({
            "MOZ_SOURCE_REPO": "https://github.com/" + hosted.REPOSITORY,
            "MOZ_SOURCE_CHANGESET": self.sha,
        })
        self.assertIn(
            "MOZ_SOURCE_CHANGESET=" + self.sha + "\n", self.github_env.read_text()
        )

    def test_producer_command_keeps_source_identity_without_controller_secret(self):
        class ProbeComplete(Exception):
            pass

        def command(argv, cwd, env, logs, name, timeout, **kwargs):
            self.assertEqual(name, "effective-config")
            self.assertEqual(
                env["MOZ_SOURCE_REPO"], "https://github.com/" + hosted.REPOSITORY
            )
            self.assertEqual(env["MOZ_SOURCE_CHANGESET"], self.sha)
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertEqual(env["MOZ_BUILD_DATE"], self.value["buildID"])
            raise ProbeComplete

        args = SimpleNamespace(
            source=self.source,
            objdir=self.source / "obj",
            output=self.root / "output",
            primary=self.root / "primary",
            build_id=self.value["buildID"],
        )
        with mock.patch.dict(
            os.environ,
            {**self.environment, "GITHUB_TOKEN": "synthetic-secret"},
            clear=True,
        ), mock.patch.object(
            hosted, "context_from_environment", return_value=self.value
        ), mock.patch.object(hosted, "host_identity", return_value=HOST), mock.patch(
            "qa3_native_io.shutil.disk_usage",
            return_value=SimpleNamespace(free=100 * GIB),
        ), mock.patch.object(
            hosted, "run_owned", side_effect=command
        ), self.assertRaises(ProbeComplete):
            hosted.produce(args)

    def test_primary_rejects_missing_abbreviated_or_foreign_stamp_in_each_ini(self):
        app = self.root / "primary" / "floorp"
        app.mkdir(parents=True)

        def ini(path, section, stamp):
            text = "[" + section + "]\nBuildID=" + self.value["buildID"] + "\n"
            if stamp is not None:
                text += "SourceStamp=" + stamp + "\n"
            path.write_text(text)

        with mock.patch(
            "qa3_hosted_support.elf_identity", return_value={"fixture": True}
        ):
            for name, section in (
                ("application.ini", "App"),
                ("platform.ini", "Build"),
            ):
                ini(app / name, section, self.sha)
            hosted.verify_primary(app.parent, self.value)
            for name, section in (
                ("application.ini", "App"),
                ("platform.ini", "Build"),
            ):
                for stamp in (None, self.sha[:12], SHA):
                    with self.subTest(name=name, stamp=stamp), self.assertRaisesRegex(
                        ValueError, "packaged source stamp differs from Runtime recipe"
                    ):
                        ini(app / name, section, stamp)
                        hosted.verify_primary(app.parent, self.value)
                    ini(app / name, section, self.sha)


class HostedContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.event = self.root / "event.json"
        self.event.write_text(json.dumps({"created": True, "deleted": False}))
        self.environment = {
            "GITHUB_REPOSITORY": hosted.REPOSITORY,
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/" + hosted.BRANCH,
            "GITHUB_SHA": SHA,
            "GITHUB_WORKFLOW_SHA": SHA,
            "GITHUB_WORKFLOW_REF": hosted.REPOSITORY
            + "/"
            + hosted.WORKFLOW
            + "@refs/heads/"
            + hosted.BRANCH,
            "GITHUB_RUN_ID": "10",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_PATH": str(self.event),
        }

    def validate(self, value):
        with mock.patch.object(
            hosted, "host_identity", return_value=HOST
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            return hosted.validate_producer(value, context())

    def test_original_context(self):
        with mock.patch.dict(os.environ, self.environment, clear=True):
            self.assertEqual(
                hosted.context_from_environment(context()["buildID"]), context()
            )

    def test_foreign_run_source_workflow_attempt_fail_closed(self):
        for key, value in {
            "GITHUB_REPOSITORY": "fork/runtime",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/heads/nora-0.2.0",
            "GITHUB_WORKFLOW_SHA": "e" * 40,
            "GITHUB_WORKFLOW_REF": "foreign",
            "GITHUB_RUN_ID": "0",
            "GITHUB_RUN_ATTEMPT": "2",
        }.items():
            with self.subTest(key=key), mock.patch.dict(
                os.environ, {**self.environment, key: value}, clear=True
            ):
                with self.assertRaises(ValueError):
                    hosted.context_from_environment(context()["buildID"])

    def test_branch_update_and_deletion_are_not_admitted(self):
        for event in (
            {"created": False, "deleted": False},
            {"created": True, "deleted": True},
            {},
        ):
            self.event.write_text(json.dumps(event))
            with self.subTest(event=event), mock.patch.dict(
                os.environ, self.environment, clear=True
            ):
                with self.assertRaises(ValueError):
                    hosted.context_from_environment(context()["buildID"])

    def test_context_has_typed_attempt_and_no_publication(self):
        for key, change in (
            ("run", True),
            ("attempt", True),
            ("attempt", 2),
            ("publicationAuthorized", True),
            ("runtimeRecipe", "e" * 40),
        ):
            value = {**context(), key: change}
            with self.subTest(key=key, change=change), self.assertRaises(ValueError):
                hosted.validate_context(value)

    def test_canonical_debug_only(self):
        hosted.validate_mode("linux", "x86_64", True, False)
        for args in (
            ("linux", "aarch64", True, False, ""),
            ("mac", "x86_64", True, False, ""),
            ("linux", "x86_64", False, False, ""),
            ("linux", "x86_64", True, True, ""),
            ("linux", "x86_64", True, False, "use"),
            ("linux", "x86_64", 1, 0, ""),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                hosted.validate_mode(*args)

    def test_effective_debug_tests_required(self):
        hosted.validate_effective(effective(), Path("/source"), Path("/source/obj"))
        for flag in ("ENABLE_TESTS", "MOZ_DEBUG"):
            value = effective()
            value["substs"][flag] = False
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_effective_pgo_and_artifact_forbidden(self):
        for flag in ("MOZ_PROFILE_USE", "MOZ_PROFILE_GENERATE", "MOZ_ARTIFACT_BUILDS"):
            value = effective()
            value["substs"][flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_effective_objdir_source_target_must_match(self):
        for key in ("source", "objdir"):
            value = {**effective(), key: "/other"}
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.validate_effective(value, Path("/source"), Path("/source/obj"))
        value = effective()
        value["substs"]["TARGET_CPU"] = "aarch64"
        with self.assertRaises(ValueError):
            hosted.validate_effective(value, Path("/source"), Path("/source/obj"))

    def test_producer_preserves_existing_mach_state_and_build_id(self):
        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.root), "MOZBUILD_STATE_PATH": "/existing/state"},
            clear=True,
        ):
            value = hosted.producer_environment(
                self.root, self.root / "obj", context()["buildID"]
            )
        self.assertEqual(value["MOZBUILD_STATE_PATH"], "/existing/state")
        self.assertEqual(value["HOME"], str(self.root))
        self.assertEqual(value["MOZ_BUILD_DATE"], context()["buildID"])

    def test_valid_packaging_is_not_consumer_or_product_pass(self):
        self.assertEqual(self.validate(producer())["consumerVerdict"], "UNVERIFIED")

    def test_missing_failing_retried_producer_phase_rejected(self):
        for change in (
            "missing",
            "retry",
            "exit",
            "stop",
            "cleanup",
            "boolean",
            "cancelled",
        ):
            value = producer()
            if change == "missing":
                value["commands"].pop()
            elif change == "retry":
                value["commands"].append(value["commands"][-1])
            else:
                key, item = {
                    "exit": ("exit", 1),
                    "stop": ("stop", "TIMEOUT"),
                    "cleanup": ("ownedCleanupComplete", False),
                    "boolean": ("exit", False),
                    "cancelled": ("cancelled", True),
                }[change]
                value["commands"][1][key] = item
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)

    def test_missing_test_archive_rejected(self):
        value = producer()
        value["archives"].pop()
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_distribution_source_pin_must_match(self):
        for field in ("upstream", "floorp_patch", "runtime_commit"):
            value = producer()
            value["compiledSource"][field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_packaged_binary_must_match_compiled_build_id(self):
        value = producer()
        value["compiledIdentity"]["floorp"]["gnuBuildID"] = "ef"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_same_boot_is_not_cold_proof(self):
        value = producer()
        value["bootSha256"] = "d" * 64
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_wrong_os_python_abi_rejected(self):
        for field, change in (
            ("version", "22.04"),
            ("machine", "aarch64"),
            ("pythonABI", "cp313"),
        ):
            value = producer()
            value["host"] = {**HOST, field: change}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(value)

    def test_exact_same_run_artifact_metadata(self):
        meta = {
            "id": 12,
            "name": "qa3-support-10-1",
            "expired": False,
            "digest": "sha256:" + DIGEST,
            "size_in_bytes": 1,
            "workflow_run": {"id": 10, "head_sha": SHA},
        }
        self.assertEqual(
            verify_artifact_metadata(meta, context(), 12, "support", DIGEST), 1
        )
        for key, value in (
            ("expired", True),
            ("name", "qa3-support-10-2"),
            ("id", 13),
            ("digest", "sha256:" + "e" * 64),
            ("workflow_run", {"id": 11, "head_sha": SHA}),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_artifact_metadata(
                    {**meta, key: value}, context(), 12, "support", DIGEST
                )

    def test_acquire_uses_pr84_transport_and_original_run_creation(self):
        class TransferReached(Exception):
            pass

        # Preserve the shared function signature available in PR84, before QA334.
        def original_transport(
            ctx, artifact_id, kind, digest, destination, opener=None, budget=None
        ):
            self.assertEqual(ctx, context())
            self.assertEqual((artifact_id, kind, digest), (12, "support", DIGEST))
            raise TransferReached

        payload = {
            "id": 10,
            "head_sha": SHA,
            "run_attempt": 1,
            "event": "push",
            "path": hosted.WORKFLOW,
            "head_branch": hosted.BRANCH,
            "created_at": "2026-10-11T00:00:00Z",
        }
        args = SimpleNamespace(
            build_id=context()["buildID"],
            artifact_id=12,
            artifact_sha256=DIGEST,
            output=self.root / "download",
            recipe=SOURCE,
        )
        for changes in (
            {},
            {"run_attempt": 2},
            {"head_sha": "e" * 40},
            {"created_at": "2026-10-11T00:00:01Z"},
        ):
            with self.subTest(changes=changes), mock.patch.dict(
                os.environ, {**self.environment, "GITHUB_TOKEN": "fixture"}, clear=True
            ), mock.patch.object(
                hosted, "fetch_actions_run", return_value={**payload, **changes}
            ), mock.patch.object(
                hosted, "download_artifact", side_effect=original_transport
            ) as transfer:
                with self.assertRaises(ValueError if changes else TransferReached):
                    hosted.acquire(args)
                self.assertEqual(transfer.call_count, 0 if changes else 1)

    def test_seed_and_wheel_lock_are_exact_and_offline(self):
        lock = read_json(SOURCE / ".github/qa/hosted-consumer-python.lock.json")
        seed = SOURCE / ".github/qa/hosted-consumer-seed.zip"
        self.assertEqual(file_digest(seed), hosted.SEED_SHA)
        self.assertEqual(lock["readiness"], "INPUTS_LOCKED_NOT_TARGET_QUALIFIED")
        self.assertIs(lock["publicationAuthorized"], False)
        self.assertEqual(len(lock["wheels"]), 40)
        with zipfile.ZipFile(seed) as archive:
            raw = archive.read("profiles/consumer/requirements.lock")
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(), lock["requirementsSha256"]
            )
            hashes = set(re.findall(r"sha256:([a-f0-9]{64})", raw.decode()))
            self.assertEqual(hashes, {r["sha256"] for r in lock["wheels"]})
            for row in lock["wheels"]:
                if row["source"].startswith("source-wheels/"):
                    data = archive.read(row["source"])
                    self.assertEqual(len(data), row["bytes"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
                else:
                    self.assertTrue(
                        row["url"].startswith("https://files.pythonhosted.org/")
                    )

    def test_service_has_no_controller_env_network_or_privileges(self):
        argv = boundary.service_command({
            "root": "/var/lib/test",
            "state": "/var/lib/test/state",
            "unit": "qa3.service",
            "controllerPaths": [
                "/home/runner/work/runtime",
                "/home/runner/work/_temp/qa3",
            ],
            "uid": 900,
            "gid": 900,
        })
        for value in (
            "--property=PrivateNetwork=yes",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectHome=yes",
            "--property=ProtectProc=invisible",
            "--property=CapabilityBoundingSet=",
            "--property=KillMode=control-group",
            "--property=MemoryMax=" + str(14 * GIB),
            "--property=MemorySwapMax=0",
            "--property=TasksMax=512",
            "--property=CPUQuota=400%",
            "-i",
        ):
            self.assertIn(value, argv)
        self.assertFalse(any("GITHUB" in a or "TOKEN" in a for a in argv))
        self.assertIn("--property=UMask=0077", argv)

    def test_staged_module_import_closure_is_complete(self):
        copied = {Path(n).stem for n in boundary.FILES}
        for name in boundary.FILES:
            tree = ast.parse((SOURCE / ".github/workflows/scripts" / name).read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.module
                    and node.module.startswith(("qa3_", "runtime_build"))
                ):
                    self.assertIn(node.module, copied)

    def test_existing_build_steps_and_default_route_are_preserved(self):
        current = (SOURCE / ".github/workflows/common-build.yml").read_text()
        current = current.replace(
            "          retention-days: ${{ inputs.qa3-debug-tests && 1 || 0 }}\n", ""
        )

        def steps(text):
            return {
                part.splitlines()[0].strip(): part
                for part in text.split("      - name: ")[1:]
            }

        before = ORIGINAL_BUILD_STEP_DIGESTS
        after = steps(current.split("\n  qa3-consumer:")[0])
        for name, original in before.items():
            # New opt-in steps are inserted only between the original steps.
            self.assertEqual(
                hashlib.sha256(after[name].rstrip().encode()).hexdigest(),
                original,
                name,
            )
        self.assertIn(
            "inputs.qa3-debug-tests && 'ubuntu-24.04' || 'ubuntu-latest'", current
        )
        self.assertIn("qa3-debug-tests:", current)
        caller = (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        self.assertNotIn("workflow_dispatch", caller)
        self.assertNotIn("secrets:", caller)
        self.assertIn("event.get('created') is not True", caller)
        self.assertNotIn("github.run_attempt == 1", caller)


class HostedBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_root_git_uses_exact_safe_directory_and_no_replacements(self):
        with mock.patch.object(
            hosted.subprocess, "check_output", return_value=b"original"
        ) as call:
            hosted.raw_git(self.root, "cat-file", "blob", SHA + ":script.py")
        self.assertIn(
            "safe.directory=" + str(self.root.resolve()), call.call_args.args[0]
        )
        env = call.call_args.kwargs["env"]
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")

    def test_rerun_or_updated_branch_is_failed_instead_of_all_jobs_skipped(self):
        text = (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        start = text.index("          import json, os\n")
        end = text.index("          PY\n", start)
        code = "\n".join(line[10:] for line in text[start:end].splitlines())
        event = self.root / "event.json"
        for created, deleted, attempt in (
            (True, False, "1"),
            (False, False, "1"),
            (True, True, "1"),
            (True, False, "2"),
        ):
            event.write_text(json.dumps({"created": created, "deleted": deleted}))
            with self.subTest(
                created=created, deleted=deleted, attempt=attempt
            ), mock.patch.dict(
                os.environ,
                {"GITHUB_EVENT_PATH": str(event), "GITHUB_RUN_ATTEMPT": attempt},
                clear=True,
            ):
                if created and not deleted and attempt == "1":
                    exec(compile(code, "<controller-gate>", "exec"), {})
                else:
                    with self.assertRaises(ValueError):
                        exec(compile(code, "<controller-gate>", "exec"), {})

    def test_early_acquisition_failure_still_exports_incomplete_receipt(self):
        destination = self.root / "evidence"
        with mock.patch.object(
            boundary, "ROOT", self.root / "missing"
        ), mock.patch.object(
            boundary, "context_from_environment", return_value=context()
        ), mock.patch.object(
            boundary, "protected", side_effect=FileNotFoundError
        ), mock.patch.dict(
            os.environ,
            {"QA3_ACQUIRE_OUTCOME": "failure", "QA3_LAUNCH_OUTCOME": "skipped"},
            clear=True,
        ), mock.patch.object(
            boundary.sys,
            "argv",
            [
                "collect",
                "collect",
                "--output",
                str(destination),
                "--build-id",
                context()["buildID"],
            ],
        ):
            with self.assertRaises(FileNotFoundError):
                boundary.main()
        self.assertEqual(
            read_json(destination / "collection.json")["acquireOutcome"], "failure"
        )
        result = read_json(destination / "collection-result.json")
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertIs(result["publicationAuthorized"], False)

    def test_late_original_step_failure_cannot_emit_pass_verdict(self):
        root = self.root / "native/10-1"
        (root / "evidence").mkdir(parents=True)
        write_json(
            root / "evidence/final.json",
            {
                "schema": "qa3-hosted-root-supervision-v1",
                "context": context(),
                "status": "PASS",
                "reason": None,
                "scopeEmpty": True,
                "serviceExit": 0,
                "publicationAuthorized": False,
                "export": [],
            },
        )
        output = self.root / "github-output"
        output.write_bytes(b"")
        destination = self.root / "evidence"
        from types import SimpleNamespace

        with mock.patch.object(boundary, "ROOT", root.parent), mock.patch.object(
            boundary, "context_from_environment", return_value=context()
        ), mock.patch.object(
            boundary, "protected", side_effect=lambda p: p
        ), mock.patch.dict(
            os.environ,
            {
                "QA3_LAUNCH_OUTCOME": "failure",
                "QA3_ACQUIRE_OUTCOME": "success",
                "GITHUB_OUTPUT": str(output),
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                boundary.collect(
                    SimpleNamespace(output=destination, build_id=context()["buildID"])
                )
        self.assertEqual(output.read_bytes(), b"")

    def test_root_entry_seals_every_module_before_import(self):
        text = (SOURCE / ".github/workflows/common-build.yml").read_text()
        start = text.index("          import os, re, stat, subprocess, sys\n")
        end = text.index("          PY\n", start)
        code = "\n".join(line[10:] for line in text[start:end].splitlines())
        tree = ast.parse(code)
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules.update(
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
        )
        self.assertFalse(any(name.startswith("qa3_") for name in modules))
        names = next(
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "names" for t in n.targets)
        )
        self.assertEqual(ast.literal_eval(names), boundary.FILES)
        self.assertIn("GIT_NO_REPLACE_OBJECTS", code)
        self.assertLess(code.index("raw !="), code.index("os.execve"))
        self.assertIn("sudo -n /usr/bin/python3.12 -I -", text)

    def test_dedicated_inputs_do_not_inherit_private_parent_mode(self):
        source = self.root / "controller"
        source.mkdir(mode=0o700)
        (source / "payload").write_bytes(b"original")
        destination = self.root / "native-inputs"
        previous = os.umask(0o077)
        try:
            boundary.stage_inputs(source, destination)
        finally:
            os.umask(previous)
        self.assertEqual(source.stat().st_mode & 0o777, 0o700)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o555)
        self.assertEqual((destination / "payload").stat().st_mode & 0o777, 0o444)
        destination.chmod(0o700)

    def test_controller_symlink_is_not_staged(self):
        source = self.root / "controller"
        source.mkdir()
        (source / "payload").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            boundary.stage_inputs(source, self.root / "copy")

    def test_compiled_symlink_is_limited_to_same_objdir(self):
        from qa3_hosted_support import verify_primary

        objdir = self.root / "obj"
        app = objdir / "dist/bin"
        app.mkdir(parents=True)
        for name in ("floorp", "libxul.so"):
            (objdir / name).write_bytes(b"compiled")
            (app / name).symlink_to(objdir / name)
        for name, section in (("application.ini", "App"), ("platform.ini", "Build")):
            (app / name).write_text(
                "["
                + section
                + "]\nBuildID="
                + context()["buildID"]
                + "\nSourceStamp="
                + SHA
                + "\n"
            )
        with mock.patch(
            "qa3_hosted_support.elf_identity", side_effect=lambda p: {"path": str(p)}
        ) as call:
            result = verify_primary(objdir, context(), app=app, object_root=objdir)
        self.assertEqual(result["floorp"]["path"], str(objdir / "floorp"))
        self.assertEqual(call.call_count, 2)

    def test_compiled_symlink_escape_rejected(self):
        from qa3_hosted_support import verify_primary

        objdir = self.root / "obj"
        app = objdir / "dist/bin"
        app.mkdir(parents=True)
        (self.root / "outside").write_bytes(b"foreign")
        (app / "floorp").symlink_to(self.root / "outside")
        with self.assertRaises(ValueError):
            verify_primary(objdir, context(), app=app, object_root=objdir)

    def wrapper(self, extra=None):
        archive = self.root / "artifact.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name in sorted(hosted.WRAPPER_FILES):
                output.writestr(name, b"x")
            if extra:
                output.writestr(extra, b"outside")
        destination = self.root / "expanded"
        destination.mkdir()
        return archive, destination

    def test_exact_three_member_wrapper(self):
        archive, destination = self.wrapper()
        hosted.unpack_wrapper(archive, destination)
        self.assertEqual({p.name for p in destination.iterdir()}, hosted.WRAPPER_FILES)

    def test_wrapper_traversal_or_extra_member_rejected(self):
        archive, destination = self.wrapper("../outside")
        with self.assertRaises(ValueError):
            hosted.unpack_wrapper(archive, destination)
        self.assertFalse((self.root / "outside").exists())

    def test_wrapper_declared_expansion_budget_is_enforced(self):
        archive, destination = self.wrapper()
        with mock.patch.object(hosted, "MAX_TRANSFER", 2), self.assertRaises(
            ValueError
        ):
            hosted.unpack_wrapper(archive, destination)

    def test_wrapper_special_member_rejected(self):
        archive = self.root / "special.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name in hosted.WRAPPER_FILES:
                info = zipfile.ZipInfo(name)
                info.external_attr = 0o120777 << 16
                output.writestr(info, b"target")
        destination = self.root / "expanded"
        destination.mkdir()
        with self.assertRaises(ValueError):
            hosted.unpack_wrapper(archive, destination)

    def test_ignored_namespace_property_fails_closed(self):
        spec = {
            "uid": 900,
            "gid": 900,
            "controllerNamespaces": {"mnt": "same", "net": "same", "user": "same"},
        }
        with mock.patch.object(
            boundary.os, "getuid", return_value=900
        ), mock.patch.object(
            boundary.os, "getgid", return_value=900
        ), mock.patch.object(
            Path,
            "read_text",
            return_value="NoNewPrivs:\t1\nCapEff:\t0000000000000000\n",
        ), mock.patch.object(
            boundary.os, "readlink", return_value="same"
        ), self.assertRaises(ValueError):
            boundary.verify_worker(spec)

    def test_whole_run_budget_counts_existing_duplicate_artifacts(self):
        primary = self.root / "bundle"
        primary.mkdir()
        (primary / "floorp-application.ini").write_bytes(b"ini")
        (primary / "dist-host").mkdir()
        (primary / "dist-host/tool").write_bytes(b"host")
        output = self.root / "output"
        output.mkdir()
        for name in ("runtime.tar.xz", "test-support.tar.gz"):
            (output / name).write_bytes(b"payload")
        value = hosted.artifact_storage_budget(primary, output)
        self.assertEqual(value["primaryBundleBytes"], 7)
        self.assertEqual(value["distHostDuplicateBytes"], 4)
        self.assertEqual(value["applicationDuplicateBytes"], 3)
        self.assertEqual(value["retentionDays"], 1)
        with mock.patch.object(hosted, "MAX_ARTIFACT_STORAGE", 1), self.assertRaises(
            ValueError
        ):
            hosted.artifact_storage_budget(primary, output)


class OriginalConsumerEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "logs").mkdir()
        self.support = self.root / "support"
        self.support.mkdir()
        self.plan = {
            "selection": [
                {
                    "suite": "browser-chrome",
                    "id": "browser/test.js",
                    "minimumAssertions": 1,
                },
                {"suite": "xpcshell", "id": "xpcom/test.js", "minimumAssertions": 1},
            ]
        }
        commands, cases = [], []
        for index, name in enumerate(PHASES):
            events = []
            if index >= 3:
                case = self.plan["selection"][(index - 3) // 2]
                canary = name.endswith("assertion-canary")
                test = case["id"]
                events = [
                    {"action": "suite_start", "tests": [test]},
                    {"action": "test_start", "test": test},
                    {
                        "action": "test_status",
                        "test": test,
                        "status": "FAIL" if canary else "PASS",
                        "expected": "PASS",
                        "subtest": "QA3_EXPECTED_ASSERTION" if canary else "assert",
                    },
                    {
                        "action": "test_end",
                        "test": test,
                        "status": "FAIL" if canary else "OK",
                    },
                    {"action": "suite_end"},
                ]
            (self.root / "logs" / (name + ".stdout")).write_text(
                "".join(json.dumps(e) + "\n" for e in events)
            )
            (self.root / "logs" / (name + ".stderr")).write_bytes(b"")
            command = {
                "name": name,
                "exit": 1 if name.endswith("assertion-canary") else 0,
                "stop": None,
                "ownedCleanupComplete": True,
                "stdoutIsData": False,
                "stdoutSha256": file_digest(self.root / "logs" / (name + ".stdout")),
                "stderrSha256": file_digest(self.root / "logs" / (name + ".stderr")),
            }
            write_json(self.root / "logs" / (name + ".process.json"), command)
            commands.append(command)
            if index >= 3:
                cases.append({
                    "name": name,
                    "suite": case["suite"],
                    "canary": canary,
                    "process": command,
                    "mozlog": verify_mozlog(
                        self.root / "logs" / (name + ".stdout"),
                        case,
                        self.support,
                        command,
                        canary=canary,
                    ),
                })
        self.value = {
            "schema": "qa3-hosted-cold-consumer-v1",
            "status": "PASS",
            "context": context(),
            "producerBootSha256": BOOT,
            "consumerBootSha256": "d" * 64,
            "commands": commands,
            "cases": cases,
            "nativeProductQualification": "UNVERIFIED",
            "publicationAuthorized": False,
        }

    def check(self):
        path = self.root / "consumer.json"
        path.unlink(missing_ok=True)
        write_json(path, self.value)
        with mock.patch.object(
            hosted, "verify_support", return_value=self.plan
        ), mock.patch.object(
            hosted, "canary_case", side_effect=lambda case, *_: case
        ), mock.patch.object(hosted, "worker_boot_identity", return_value="d" * 64):
            return hosted.verify_consumer(
                self.root, self.support, producer(), context()
            )

    def test_four_original_pass_and_assertion_canaries(self):
        self.assertEqual(self.check()["status"], "PASS")

    def test_missing_original_case_or_command_rejected(self):
        self.value["cases"].pop()
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_retry_cannot_recover_first_failure(self):
        self.value["commands"].append(self.value["commands"][-1])
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_log_tamper_rejected(self):
        (self.root / "logs/native-0-required.stdout").write_bytes(b"")
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_process_tamper_rejected(self):
        (self.root / "logs/native-0-required.process.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.check()

    def test_required_skip_rejected_after_raw_hashes_are_rejoined(self):
        path = self.root / "logs/native-0-required.stdout"
        events = [json.loads(line) for line in path.read_text().splitlines()]
        events[-2]["status"] = "SKIP"
        path.write_text("".join(json.dumps(e) + "\n" for e in events))
        command = self.value["commands"][3]
        command["stdoutSha256"] = file_digest(path)
        process = self.root / "logs/native-0-required.process.json"
        process.unlink()
        write_json(process, command)
        with self.assertRaises(ValueError):
            self.check()

    def test_internal_retry_rejected_after_raw_hashes_are_rejoined(self):
        path = self.root / "logs/native-0-required.stdout"
        with path.open("a") as stream:
            stream.write(
                json.dumps({
                    "action": "log",
                    "level": "INFO",
                    "message": "retrying original failure",
                })
                + "\n"
            )
        command = self.value["commands"][3]
        command["stdoutSha256"] = file_digest(path)
        process = self.root / "logs/native-0-required.process.json"
        process.unlink()
        write_json(process, command)
        with self.assertRaises(ValueError):
            self.check()

    def test_initial_failure_or_cancel_cannot_become_pass(self):
        self.value["commands"][0]["exit"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_canary_must_fail_with_original_normal_exit(self):
        self.value["commands"][4]["exit"] = 0
        with self.assertRaises(ValueError):
            self.check()

    def test_product_or_publication_claim_rejected(self):
        self.value["publicationAuthorized"] = True
        with self.assertRaises(ValueError):
            self.check()


class HostedPackagingDependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_scrubbed_producer_selects_pip_without_controller_secrets(self):
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.root),
                "MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE": "system",
                "GITHUB_TOKEN": "private-controller-token",
                "PIP_REQUIREMENT": "/private/lock",
                "SCCACHE_GHA_RW_MODE": "READ_WRITE",
                "QA3_KEEP_CARGO_FOR_TEST_PACKAGING": "1",
            },
            clear=True,
        ):
            env = hosted.producer_environment(
                self.root, self.root / "obj", context()["buildID"]
            )
            consumer = hosted.child_environment(self.root)
        self.assertEqual(env["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"], "pip")
        self.assertEqual(env["MOZ_AUTOMATION"], "1")
        self.assertEqual(env["SCCACHE_GHA_RW_MODE"], "READ_ONLY")
        for name in ("GITHUB_TOKEN", "PIP_REQUIREMENT"):
            self.assertNotIn(name, env)
        self.assertNotIn("MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE", consumer)
        self.assertNotIn("SCCACHE_GHA_RW_MODE", consumer)
        self.assertNotIn("QA3_KEEP_CARGO_FOR_TEST_PACKAGING", env)
        self.assertNotIn("QA3_KEEP_CARGO_FOR_TEST_PACKAGING", consumer)

    def material(self):
        support = self.root / "support"
        for name in (
            "modules",
            *("mozbase/" + name for name in hosted.MOZBASE_MODULES),
            "tools/geckoprocesstypes_generator/geckoprocesstypes",
        ):
            (support / name).mkdir(parents=True)
        (support / "plan.json").write_bytes(
            (SOURCE / ".github/qa/linux-proof-plan.json").read_bytes()
        )
        (support / "mozbase/setup_development.py").write_bytes(
            (SOURCE / "testing/mozbase/setup_development.py").read_bytes()
        )
        (
            support / "tools/geckoprocesstypes_generator/geckoprocesstypes/__init__.py"
        ).write_text("process_types = ['fixed-packaged-fixture']\n")
        return support

    def test_fixed_common_tools_path_imports_in_scrubbed_child(self):
        import subprocess
        import sys

        support = self.material()
        roots = hosted.consumer_module_roots(support)
        env = hosted.child_environment(
            self.root, {"PYTHONPATH": ":".join(map(str, roots))}
        )
        original = dict(env, PYTHONPATH=":".join(map(str, roots[:-1])))
        argv = [
            sys.executable,
            "-s",
            "-c",
            "import geckoprocesstypes; print(geckoprocesstypes.process_types)",
        ]
        before = subprocess.run(
            argv,
            cwd=self.root,
            env=original,
            capture_output=True,
            timeout=20,
            check=False,
        )
        after = subprocess.run(
            argv, cwd=self.root, env=env, capture_output=True, timeout=20, check=False
        )
        self.assertEqual(before.returncode, 1)
        self.assertIn(b"ModuleNotFoundError", before.stderr)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(after.stdout, b"['fixed-packaged-fixture']\n")

    def test_missing_or_linked_common_tools_module_is_rejected(self):
        support = self.material()
        module = (
            support / "tools/geckoprocesstypes_generator/geckoprocesstypes/__init__.py"
        )
        original = module.read_bytes()
        module.unlink()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(support)
        outside = self.root / "outside.py"
        outside.write_bytes(original)
        module.symlink_to(outside)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(support)

    def test_actual_nonzero_process_retains_failure_and_safe_typed_diagnostics(self):
        import contextlib
        import sys

        logs = self.root / "logs"
        logs.mkdir()
        env = hosted.child_environment(self.root)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ValueError):
            hosted.run_diagnosed(
                [
                    sys.executable,
                    "-c",
                    "print('::error::private-token-value'); raise ModuleNotFoundError(\"No module named 'qa3_missing_fixture'\")",
                ],
                self.root,
                env,
                logs,
                "diagnostic-fixture",
                20,
                memory=GIB,
                log_limit=1024**2,
            )
        value = json.loads(output.getvalue())
        self.assertEqual(value["exit"], 1)
        self.assertTrue(value["ownedCleanupComplete"])
        self.assertNotIn("private-token-value", output.getvalue())
        self.assertNotIn("::error::", output.getvalue())
        stderr = next(v for v in value["boundedTypedTails"] if v["stream"] == "stderr")
        self.assertEqual(stderr["missingModules"], ["qa3_missing_fixture"])
        self.assertEqual(stderr["exceptionClasses"], ["ModuleNotFoundError"])
        self.assertIn(
            b"private-token-value", (logs / "diagnostic-fixture.stdout").read_bytes()
        )
        self.assertEqual(read_json(logs / "diagnostic-fixture.process.json")["exit"], 1)

    def test_diagnostic_output_failure_does_not_replace_original_process_failure(self):
        import sys

        logs = self.root / "logs"
        logs.mkdir()
        env = hosted.child_environment(self.root)
        with mock.patch.object(
            hosted, "emit_owned_failure", side_effect=BrokenPipeError
        ), mock.patch("builtins.print", side_effect=BrokenPipeError):
            with self.assertRaisesRegex(
                ValueError, "diagnostic-broken-output failed: NONZERO_EXIT"
            ):
                hosted.run_diagnosed(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    self.root,
                    env,
                    logs,
                    "diagnostic-broken-output",
                    20,
                    memory=GIB,
                    log_limit=1024**2,
                )
        self.assertEqual(
            read_json(logs / "diagnostic-broken-output.process.json")["exit"], 7
        )

    def test_data_stdout_is_never_inspected_as_text_diagnostics(self):
        import contextlib

        logs = self.root / "logs"
        logs.mkdir()
        write_json(
            logs / "decode-fixture.process.json",
            {
                "name": "decode-fixture",
                "exit": 1,
                "stop": None,
                "stdoutIsData": True,
                "ownedCleanupComplete": True,
            },
        )
        (logs / "decode-fixture.stdout").write_bytes(
            b"No module named 'binary_data_must_not_be_read'"
        )
        (logs / "decode-fixture.stderr").write_bytes(
            b"ModuleNotFoundError: No module named 'stderr_fixture'\n"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            hosted.emit_owned_failure(logs, "decode-fixture")
        value = json.loads(output.getvalue())
        self.assertEqual([v["stream"] for v in value["boundedTypedTails"]], ["stderr"])
        self.assertNotIn("binary_data_must_not_be_read", output.getvalue())

    def test_preflight_is_scoped_before_build_with_original_diagnostics(self):
        import yaml

        workflow = yaml.safe_load(
            (SOURCE / ".github/workflows/common-build.yml").read_text()
        )
        steps = workflow["jobs"]["build"]["steps"]
        name = "Check scoped Debug packaging Python before build"
        preflight = next(v for v in steps if v.get("name") == name)
        self.assertEqual(preflight["if"], "inputs.qa3-debug-tests")
        self.assertLess(
            next(
                i
                for i, v in enumerate(steps)
                if v.get("name") == "Setup floorp configuration"
            ),
            steps.index(preflight),
        )
        self.assertLess(
            steps.index(preflight),
            next(
                i for i, v in enumerate(steps) if v.get("name") == "Build and package"
            ),
        )
        diagnostics = next(
            v
            for v in steps
            if v.get("name") == "Preserve original Debug packaging diagnostics"
        )
        self.assertIn(
            "qa3-packaging-preflight/logs/*.process.json", diagnostics["with"]["path"]
        )
        self.assertEqual(diagnostics["with"]["retention-days"], 1)


class HostedMozbaseArchiveShape(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.support = HostedPackagingDependencies.material(self)

    def test_contract_checkout_covers_exact_pinned_archive_shape_sources(self):
        import yaml

        workflow = yaml.safe_load(
            (SOURCE / ".github/workflows/qa3-hosted-linux-debug.yml").read_text()
        )
        checkout = next(
            step["with"]
            for step in workflow["jobs"]["contracts"]["steps"]
            if step.get("uses") == "actions/checkout@v4"
        )
        self.assertIs(checkout["sparse-checkout-cone-mode"], False)
        source_hashes = {
            row["path"]: row["sha256"]
            for row in read_json(self.support / "plan.json")["sourceMaterials"]
        }
        metadata = {"testing/mozbase/moz.build", "testing/mozbase/setup_development.py"}
        self.assertTrue(metadata <= source_hashes.keys())
        self.assertEqual(
            set(checkout["sparse-checkout"].splitlines()),
            {"/.github/**", *("/" + name for name in metadata)},
        )

    def test_registered_roots_match_source_and_packaged_metadata_is_not_a_root(self):
        build = ast.parse((SOURCE / "testing/mozbase/moz.build").read_bytes())
        registered = next(
            ast.literal_eval(node.value)
            for node in build.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "python_modules"
                for target in node.targets
            )
        )
        self.assertEqual(list(hosted.MOZBASE_MODULES), registered)
        plan = read_json(self.support / "plan.json")
        source_hashes = {row["path"]: row["sha256"] for row in plan["sourceMaterials"]}
        for name in ("moz.build", "setup_development.py"):
            self.assertEqual(
                file_digest(SOURCE / "testing/mozbase" / name),
                source_hashes["testing/mozbase/" + name],
            )
        roots = hosted.consumer_module_roots(self.support)
        self.assertEqual(
            roots[2:-1], [self.support / "mozbase" / name for name in registered]
        )
        self.assertNotIn(self.support / "mozbase/setup_development.py", roots)

    def test_unknown_root_file_and_directory_are_rejected(self):
        unknown = self.support / "mozbase/unknown"
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                if kind == "file":
                    unknown.write_text("unexpected")
                else:
                    unknown.mkdir()
                with self.assertRaises(ValueError):
                    hosted.consumer_module_roots(self.support)
                if kind == "file":
                    unknown.unlink()
                else:
                    unknown.rmdir()

    def test_missing_module_and_linked_module_are_rejected(self):
        module = self.support / "mozbase/manifestparser"
        module.rmdir()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        outside = self.root / "outside"
        outside.mkdir()
        module.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)

    def test_missing_changed_or_linked_metadata_is_rejected(self):
        metadata = self.support / "mozbase/setup_development.py"
        original = metadata.read_bytes()
        metadata.unlink()
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        metadata.write_bytes(original + b"\nchanged = True\n")
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)
        metadata.unlink()
        outside = self.root / "setup_development.py"
        outside.write_bytes(original)
        metadata.symlink_to(outside)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)

    def test_linked_mozbase_root_is_rejected(self):
        root = self.support / "mozbase"
        outside = self.root / "outside"
        root.rename(outside)
        root.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            hosted.consumer_module_roots(self.support)


class HostedCargoPackagingClosure(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, directory, platform, arch, pgo, flag):
        import subprocess

        directory.mkdir()
        home = directory / "home"
        cargo = home / ".cargo"
        cargo.mkdir(parents=True)
        (cargo / "configured-tool-fixture").write_text("retained tool fixture")
        commands = directory / "bin"
        commands.mkdir()
        helpers = {
            "nproc": "printf '4\\n'\n",
            "sudo": "exit 0\n",
            "xvfb-run": 'shift 3\nexec "$@"\n',
        }
        for name, body in helpers.items():
            target = commands / name
            target.write_text("#!/usr/bin/env bash\n" + body)
            target.chmod(0o755)
        mach = directory / "mach"
        mach.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$1" >> fixture-mach-invocations\n'
            'if [[ "$1" == "package" ]]; then\n'
            "  mkdir -p obj-x86_64-pc-linux-gnu/dist/{bin,host}\n"
            "  printf 'fixture' > obj-x86_64-pc-linux-gnu/dist/floorp-fixture.tar.xz\n"
            "  printf 'fixture' > obj-x86_64-pc-linux-gnu/dist/host/fixture\n"
            '  printf "BuildID=%s\\n" "$MOZ_BUILD_DATE" > obj-x86_64-pc-linux-gnu/dist/bin/application.ini\n'
            '  printf \'#!/usr/bin/env bash\\nprintf "%%s %%s\\\\n" "$MOZ_BUILD_DATE" "$MOZ_BUILD_DATE"\\n\' > obj-x86_64-pc-linux-gnu/dist/bin/floorp\n'
            "  chmod +x obj-x86_64-pc-linux-gnu/dist/bin/floorp\n"
            "fi\n"
        )
        mach.chmod(0o755)
        env = {
            "HOME": str(home),
            "PATH": str(commands) + ":/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        if flag is not None:
            env["QA3_KEEP_CARGO_FOR_TEST_PACKAGING"] = flag
        result = subprocess.run(
            [
                "/bin/bash",
                str(SOURCE / ".github/workflows/scripts/build-and-package.sh"),
                platform,
                arch,
                "20261011000000",
                pgo,
            ],
            cwd=directory,
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
        return result, cargo

    def test_actual_shell_keeps_only_opt_in_tools_and_default_cleanup_is_preserved(
        self,
    ):
        for index, flag in enumerate((None, "0", "1")):
            with self.subTest(flag=flag):
                directory = self.root / str(index)
                result, cargo = self.invoke(directory, "linux", "x86_64", "", flag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(cargo.exists(), flag == "1")
                self.assertEqual(
                    (directory / "fixture-mach-invocations").read_text(),
                    "configure\nbuild\npackage\n",
                )
                self.assertTrue(
                    (
                        directory
                        / "home/output/floorp-linux-x86_64-moz-artifact-bundle/floorp-linux-x86_64-moz-artifact.tar.xz"
                    ).is_file()
                )

    def test_invalid_opt_in_routes_are_rejected_before_any_mach_command(self):
        for index, (platform, arch, pgo, flag) in enumerate((
            ("mac", "x86_64", "", "1"),
            ("windows", "x86_64", "", "1"),
            ("linux", "aarch64", "", "1"),
            ("linux", "x86_64", "generate", "1"),
            ("linux", "x86_64", "use", "1"),
            ("linux", "x86_64", "", "true"),
        )):
            with self.subTest(platform=platform, arch=arch, pgo=pgo, flag=flag):
                directory = self.root / str(index)
                result, cargo = self.invoke(directory, platform, arch, pgo, flag)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(cargo.is_dir())
                self.assertFalse((directory / "fixture-mach-invocations").exists())


if __name__ == "__main__":
    unittest.main()
