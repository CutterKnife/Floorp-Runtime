# SPDX-License-Identifier: MPL-2.0

import argparse
import ast
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import qa3_browser_entry as browser_entry
import qa3_xpcshell_entry as xpcshell_entry
from qa3_hosted_support import harness_argv, stage_mochitest
from qa3_mozlog import verify_mozlog
from qa3_native_io import IOBudget, capture_material_tree

SOURCE = Path(__file__).resolve().parents[3]


def frozen_harness(relative):
    source = SOURCE / relative
    if source.is_file():
        raw = source.read_bytes()
    else:
        result = subprocess.run(
            ["git", "-C", str(SOURCE), "show", "HEAD:" + relative],
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise unittest.SkipTest(
                "frozen Mozilla harness blob is unavailable locally"
            )
        raw = result.stdout
    plan = json.loads((SOURCE / ".github/qa/linux-proof-plan.json").read_text())
    expected = next(
        row["sha256"] for row in plan["sourceMaterials"] if row["path"] == relative
    )
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Mozilla harness differs from pinned proof plan")
    return ast.parse(raw)


class ColdHarnessSupport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.support = self.root / "support"
        self.case = {
            "suite": "browser-chrome",
            "archivePath": (
                "mochitest/browser/browser/base/content/test/performance/"
                "browser_hiddenwindow_existence.js"
            ),
            "manifest": "browser/base/content/test/performance/browser.toml",
        }
        test = self.support / self.case["archivePath"]
        test.parent.mkdir(parents=True)
        test.write_text("frozen required test\n")
        (test.parent / "browser.toml").write_text(
            '["browser_hiddenwindow_existence.js"]\n'
        )
        (self.support / "mochitest/runtests.py").write_text("frozen harness\n")
        plugin = self.support / "bin/plugins/gmp-fake/1.0/libfake.so"
        plugin.parent.mkdir(parents=True)
        plugin.write_bytes(b"same-build test plugin")
        self.budget = IOBudget(self.root, maximum=1024**2, minimum_free=0)

    def argv(self, copy):
        return harness_argv(
            "/venv/bin/python",
            self.support,
            self.root / "primary/floorp",
            self.case,
            self.root / "profile",
            raw_log=self.root / "native-required.mozlog",
            mochitest_root=copy,
        )

    def test_runtime_server_and_manifest_writes_preserve_frozen_materials(self):
        before = capture_material_tree(self.support)
        copy = stage_mochitest(
            self.support, self.root / "native-required/mochitest", self.budget
        )
        self.assertEqual(
            capture_material_tree(copy),
            capture_material_tree(self.support / "mochitest"),
        )
        self.assertGreater(self.budget.used, 0)
        (copy / "tests.json").write_text('{"tests": []}\n')
        (copy / "websock.log").write_text("websocket server started\n")
        self.assertEqual(capture_material_tree(self.support), before)
        self.assertNotEqual(
            capture_material_tree(copy),
            capture_material_tree(self.support / "mochitest"),
        )

    def test_copied_browser_invocation_uses_frozen_helpers_and_plugins(self):
        copy = stage_mochitest(
            self.support, self.root / "native-required/mochitest", self.budget
        )
        argv = self.argv(copy)
        self.assertEqual(
            argv[2], str(SOURCE / ".github/workflows/scripts/qa3_browser_entry.py")
        )
        selected = copy / Path(self.case["archivePath"]).relative_to("mochitest")
        self.assertEqual(argv[-1], selected.name)
        self.assertTrue(selected.is_file())
        self.assertEqual(
            argv[argv.index("--manifest") + 1], str(selected.parent / "browser.toml")
        )
        for option, relative in (
            ("--utility-path", "bin"),
            ("--testing-modules-dir", "modules"),
            ("--certificate-path", "certs"),
            ("--extra-profile-file", "bin/plugins"),
        ):
            self.assertEqual(argv[argv.index(option) + 1], str(self.support / relative))

    def test_mutable_copy_cannot_be_nested_in_frozen_support(self):
        before = capture_material_tree(self.support)
        with self.assertRaisesRegex(ValueError, "outside frozen support"):
            stage_mochitest(self.support, self.support / "runtime-copy", self.budget)
        self.assertEqual(capture_material_tree(self.support), before)

    def test_required_and_canary_select_names_relative_to_explicit_manifest(self):
        for name in ("browser_hiddenwindow_existence.js", "browser_qa3_assertion.js"):
            case = {
                **self.case,
                "archivePath": self.case["archivePath"].rsplit("/", 1)[0] + "/" + name,
            }
            raw_log = self.root / (name + ".mozlog.jsonl")
            argv = harness_argv(
                "/venv/bin/python",
                self.support,
                self.root / "primary/floorp",
                case,
                self.root / "profile",
                raw_log=raw_log,
            )
            self.assertEqual(argv[-1], name)
            self.assertEqual(argv[argv.index("--log-raw") + 1], str(raw_log))
            self.assertEqual(
                argv[argv.index("--manifest") + 1],
                str((self.support / case["archivePath"]).parent / "browser.toml"),
            )

    def test_frozen_browser_normalization_preserves_manifest_relative_selector(self):
        normalize = next(
            node
            for node in ast.walk(frozen_harness("testing/mochitest/runtests.py"))
            if isinstance(node, ast.FunctionDef) and node.name == "normalize_paths"
        )
        namespace = {"os": os}
        exec(
            compile(
                ast.Module(body=[normalize], type_ignores=[]),
                "frozen-runtests.py",
                "exec",
            ),
            namespace,
        )
        harness = SimpleNamespace(
            oldcwd=str(self.root),
            testRootAbs=str(self.support / "mochitest/browser"),
        )
        absolute = str(self.support / self.case["archivePath"])
        self.assertEqual(
            namespace["normalize_paths"](harness, [absolute]),
            ["browser/base/content/test/performance/browser_hiddenwindow_existence.js"],
        )
        self.assertEqual(
            namespace["normalize_paths"](harness, [self.argv(None)[-1]]),
            ["browser_hiddenwindow_existence.js"],
        )

    def test_frozen_mozilla_profile_staging_discovers_same_build_gmp(self):
        wanted = {"copyExtraFilesToProfile", "getGMPPluginPath"}
        methods = {
            node.name: node
            for node in ast.walk(frozen_harness("testing/mochitest/runtests.py"))
            if isinstance(node, ast.FunctionDef) and node.name in wanted
        }
        self.assertEqual(set(methods), wanted)
        namespace = {"os": os, "shutil": shutil}
        exec(
            compile(
                ast.Module(body=list(methods.values()), type_ignores=[]),
                "frozen-runtests.py",
                "exec",
            ),
            namespace,
        )
        harness_type = type(
            "FrozenMozillaProfile",
            (),
            {
                **{name: namespace[name] for name in wanted},
                "getFullPath": staticmethod(os.path.abspath),
            },
        )
        harness = harness_type()
        profile = self.root / "profile"
        profile.mkdir()
        harness.profile = SimpleNamespace(profile=str(profile))
        argv = self.argv(self.support / "mochitest")
        options = SimpleNamespace(
            gmp_path=None,
            xrePath=str(self.root / "primary/floorp"),
            profilePath=str(profile),
            extraProfileFiles=[argv[argv.index("--extra-profile-file") + 1]],
        )
        with self.assertRaisesRegex(OSError, "test gmp plugins"):
            harness.getGMPPluginPath(options)
        before = capture_material_tree(self.support)
        harness.copyExtraFilesToProfile(options)
        self.assertEqual(
            harness.getGMPPluginPath(options),
            str(profile / "plugins/gmp-fake/1.0"),
        )
        self.assertEqual(
            (profile / "plugins/gmp-fake/1.0/libfake.so").read_bytes(),
            b"same-build test plugin",
        )
        self.assertEqual(capture_material_tree(self.support), before)

    def test_frozen_xpcshell_emits_assertions_before_test_completion(self):
        method = next(
            node
            for node in ast.walk(frozen_harness("testing/xpcshell/runxpcshelltests.py"))
            if isinstance(node, ast.FunctionDef) and node.name == "report_message"
        )
        namespace = {}
        exec(
            compile(
                ast.Module(body=[method], type_ignores=[]),
                "frozen-runxpcshelltests.py",
                "exec",
            ),
            namespace,
        )
        case = {
            "suite": "xpcshell",
            "id": "xpcom/tests/unit/test_nsIMutableArray.js",
            "archivePath": "xpcshell/tests/xpcom/tests/unit/test_nsIMutableArray.js",
            "manifest": "xpcom/tests/unit/xpcshell.toml",
            "minimumAssertions": 1,
        }
        argv = harness_argv(
            "/venv/bin/python",
            self.support,
            self.root / "primary/floorp",
            case,
            self.root / "profile",
            raw_log=self.root / "xpcshell-required.mozlog",
        )
        emitted = []
        thread = SimpleNamespace(
            verbose=False, output_lines=[], log_line=emitted.append
        )
        assertion = {
            "action": "test_status",
            "test": case["id"],
            "status": "PASS",
            "subtest": "required mutable array assertion",
        }
        report_message = namespace["report_message"]
        report_message(thread, assertion)
        self.assertFalse(emitted)
        self.assertEqual(len(thread.output_lines), 1)
        thread.verbose = "--verbose" in argv
        report_message(thread, assertion)
        self.assertEqual(emitted, [assertion])
        raw = self.root / "xpcshell.stdout"
        events = [
            {"action": "suite_start", "tests": [case["id"]]},
            {"action": "test_start", "test": case["id"]},
            *emitted,
            {"action": "test_end", "test": case["id"], "status": "PASS"},
            {"action": "suite_end"},
        ]
        raw.write_text("".join(json.dumps(event) + "\n" for event in events))
        verdict = verify_mozlog(
            raw,
            case,
            self.support,
            {"exit": 0, "stop": None, "ownedCleanupComplete": True},
        )
        self.assertEqual(verdict["assertions"], 1)


class BrowserSingleExecution(unittest.TestCase):
    def test_empty_subclass_preserves_public_run_sequence_and_automation(self):
        order = []
        observed = {}
        options = SimpleNamespace(
            flavor="browser",
            test_paths=["browser_qa3_assertion.js"],
            repeat=0,
            verify=False,
            verify_fission=False,
            runUntilFailure=False,
            restartAfterFailure=False,
            stagedAddons=[],
            quiet=False,
            log_raw=["/state/canary.mozlog"],
            valgrind=None,
        )
        parser = SimpleNamespace(
            parse_args=lambda: options,
            validate=lambda value: order.append("validate"),
        )

        class Desktop:
            def __init__(self, flavor, logger_options, addons, quiet):
                order.append("construct")
                observed.update(runner=self, flavor=flavor, logger=logger_options)
                self.message_logger = SimpleNamespace(
                    finish=lambda: order.append("finish")
                )

            def runTests(self, value):
                order.append("run")
                observed["options"] = value
                observed["automation"] = os.environ.get("MOZ_AUTOMATION")
                return 1

            def archiveMozLogs(self):
                order.append("archive")

        harness = SimpleNamespace(
            MochitestArgumentParser=lambda app: parser, MochitestDesktop=Desktop
        )
        with mock.patch.dict(os.environ, {"MOZ_AUTOMATION": "1"}):
            self.assertEqual(browser_entry.run(harness), 1)
        self.assertEqual(order, ["validate", "construct", "run", "archive", "finish"])
        self.assertIs(harness.MochitestDesktop, Desktop)
        self.assertIsInstance(observed["runner"], Desktop)
        self.assertIs(type(observed["runner"]).runTests, Desktop.runTests)
        self.assertIs(observed["options"], options)
        self.assertEqual(observed["automation"], "1")
        self.assertEqual(observed["logger"]["log_raw"], ["/state/canary.mozlog"])
        self.assertIs(options.runByManifest, True)

        method = next(
            node
            for node in ast.walk(frozen_harness("testing/mochitest/runtests.py"))
            if isinstance(node, ast.FunctionDef) and node.name == "runMochitests"
        )
        retry = next(
            node.value
            for node in ast.walk(method)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "retry"
                for target in node.targets
            )
        )
        expression = compile(ast.Expression(body=retry), "frozen-runtests.py", "eval")
        single_pass = observed["runner"]
        with mock.patch.dict(os.environ, {"MOZ_AUTOMATION": "1"}):
            namespace = {"os": os, "MochitestDesktop": Desktop}
            self.assertIs(
                eval(
                    expression, namespace, {"self": Desktop("browser", {}, [], False)}
                ),
                True,
            )
            self.assertIs(eval(expression, namespace, {"self": single_pass}), False)


class XpcshellManifestIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.support = Path(self.temp.name) / "support"
        self.root = self.support / "xpcshell/tests"
        self.directory = self.root / "xpcom/tests/unit"
        self.directory.mkdir(parents=True)
        self.manifest = self.directory / "xpcshell.toml"
        self.manifest.write_text('["test_nsIMutableArray.js"]\n')

    def test_frozen_parser_exposes_actual_installed_selector_destination(self):
        argument = next(
            node
            for node in ast.walk(
                frozen_harness("testing/xpcshell/xpcshellcommandline.py")
            )
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "testPaths"
        )
        parser = argparse.ArgumentParser()
        statement = ast.fix_missing_locations(
            ast.Module(body=[ast.Expr(value=argument)], type_ignores=[])
        )
        exec(
            compile(statement, "frozen-xpcshellcommandline.py", "exec"),
            {"parser": parser},
        )
        options = parser.parse_args(["/installed/test_nsIMutableArray.js"])
        self.assertEqual(options.testPaths, ["/installed/test_nsIMutableArray.js"])

    def invocation(self, name):
        selected = self.directory / name
        selected.write_text("frozen selected test\n")
        options = SimpleNamespace(
            xpcshell="/same-build/xpcshell",
            app_binary=None,
            interactive=False,
            manifest=str(self.manifest),
            testPaths=[str(selected)],
            retry=True,
        )
        factory = mock.Mock(
            side_effect=lambda manifests, **kwargs: SimpleNamespace(
                manifests=manifests, **kwargs
            )
        )
        run_tests = mock.Mock(return_value=True)
        harness = SimpleNamespace(
            parser_desktop=lambda: SimpleNamespace(parse_args=lambda: options),
            TestManifest=factory,
            commandline=SimpleNamespace(setup_logging=mock.Mock(return_value=object())),
            XPCShellTests=lambda log: SimpleNamespace(runTests=run_tests),
            TBPL_RETRY=4,
            symbolicate_profiles=mock.Mock(),
        )
        return options, factory, run_tests, harness

    def test_required_and_canary_bind_installed_root_without_rewriting_ids(self):
        normalize = next(
            node
            for node in ast.walk(frozen_harness("testing/xpcshell/runxpcshelltests.py"))
            if isinstance(node, ast.FunctionDef) and node.name == "normalizeTest"
        )
        namespace = {"os": os}
        exec(
            compile(
                ast.Module(body=[normalize], type_ignores=[]),
                "frozen-runxpcshelltests.py",
                "exec",
            ),
            namespace,
        )
        for name in ("test_nsIMutableArray.js", "test_qa3_assertion.js"):
            options, factory, run_tests, harness = self.invocation(name)
            with mock.patch.dict(
                os.environ, {"QA3_XPCSHELL_SUPPORT": str(self.support)}, clear=True
            ):
                self.assertEqual(xpcshell_entry.run(harness), 0)
            factory.assert_called_once_with(
                [str(self.manifest)], strict=True, rootdir=str(self.root)
            )
            self.assertIs(options.retry, False)
            run_tests.assert_called_once_with(options)
            original = {
                "relpath": str(Path(options.testPaths[0]).relative_to(self.root)),
                "manifest": str(self.manifest),
            }
            normalized = namespace["normalizeTest"](
                object(), options.manifest.rootdir, original
            )
            self.assertEqual(normalized["id"], "xpcom/tests/unit/" + name)
            self.assertEqual(normalized["manifest"], "xpcom/tests/unit/xpcshell.toml")

    def test_missing_extra_relative_and_foreign_selectors_are_rejected(self):
        for change in ("missing", "extra", "relative", "foreign"):
            options, factory, run_tests, harness = self.invocation(
                "test_nsIMutableArray.js"
            )
            if change == "missing":
                options.manifest = None
            elif change == "extra":
                options.testPaths.append(options.testPaths[0])
            elif change == "relative":
                options.testPaths = ["test_nsIMutableArray.js"]
            else:
                options.manifest = str(Path(self.temp.name) / "foreign.toml")
                Path(options.manifest).write_text('["test_nsIMutableArray.js"]\n')
            with self.subTest(change=change), mock.patch.dict(
                os.environ, {"QA3_XPCSHELL_SUPPORT": str(self.support)}, clear=True
            ), self.assertRaises(ValueError):
                xpcshell_entry.run(harness)
            factory.assert_not_called()
            run_tests.assert_not_called()


if __name__ == "__main__":
    unittest.main()
