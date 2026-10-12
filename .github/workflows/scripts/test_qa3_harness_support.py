# SPDX-License-Identifier: MPL-2.0

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
        self.assertEqual(argv[2], str(copy / "runtests.py"))
        selected = copy / Path(self.case["archivePath"]).relative_to("mochitest")
        self.assertEqual(argv[-1], str(selected))
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
        harness_type = type("FrozenMozillaProfile", (), {
            **{name: namespace[name] for name in wanted},
            "getFullPath": staticmethod(os.path.abspath),
        })
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


if __name__ == "__main__":
    unittest.main()
