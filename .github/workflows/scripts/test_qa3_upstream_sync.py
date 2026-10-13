# SPDX-License-Identifier: MPL-2.0

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from upstream_sync import check_patches, git, sync_action


def save(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def commit(root):
    git(root, "add", "--all")
    git(
        root,
        "-c",
        "user.name=Sync fixture",
        "-c",
        "user.email=sync@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "-qm",
        "fixture",
    )
    return git(root, "rev-parse", "HEAD")


class UpstreamSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runtime = self.root / "runtime"
        self.upstream = self.root / "upstream"
        for repo in (self.runtime, self.upstream):
            git(self.root, "init", "-q", str(repo))
            save(repo, "source.txt", "old\n")
            commit(repo)

    def pin(self, commit_id):
        return save(
            self.runtime,
            ".github/runtime-upstream.json",
            json.dumps({"upstream": {"commit": commit_id}}),
        )

    def patch(self, name, before, after, source="source.txt"):
        return save(
            self.runtime,
            ".github/patches/upstream/" + name + ".patch",
            f"--- a/{source}\n+++ b/{source}\n@@ -1 +1 @@\n-{before}\n+{after}\n",
        )

    def policy(self, patches):
        return save(
            self.runtime,
            ".github/qa/source-policy.json",
            json.dumps({
                "commonPatches": [
                    {
                        "path": patch.relative_to(self.runtime).as_posix(),
                        "sha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
                    }
                    for patch in patches
                ]
            }),
        )

    def cli(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("upstream_sync.py")), *args],
            cwd=self.runtime,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def snapshot(self):
        return {
            "files": {
                path.relative_to(self.runtime).as_posix(): path.read_bytes()
                for path in self.runtime.rglob("*")
                if path.is_file() and ".git" not in path.relative_to(self.runtime).parts
            },
            "index": (self.runtime / ".git/index").read_bytes(),
            "head": git(self.runtime, "rev-parse", "HEAD"),
        }

    def test_identical_upstream_preserves_integrated_source_and_metadata(self):
        self.pin(git(self.upstream, "rev-parse", "HEAD"))
        save(self.runtime, "widget/cocoa/appshim/backend.mm", "native backend\n")
        self.policy([self.patch("native", "old", "new")])
        commit(self.runtime)
        before = self.snapshot()
        output = self.root / "github-output"
        result = self.cli(
            "guard", "--upstream", str(self.upstream), "--output", str(output)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "action=skip\n")
        self.assertEqual(self.snapshot(), before)

    def test_recorded_cohort_rejects_true_upstream_advancement(self):
        self.pin(git(self.upstream, "rev-parse", "HEAD"))
        save(self.upstream, "source.txt", "advanced\n")
        commit(self.upstream)
        before = self.snapshot()
        output = self.root / "github-output"
        result = self.cli(
            "guard", "--upstream", str(self.upstream), "--output", str(output)
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("deliberate reintegration", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.snapshot(), before)

    def switch_to_unrecorded_pr(self):
        unrecorded = git(self.runtime, "rev-parse", "HEAD")
        manifest = self.pin(git(self.upstream, "rev-parse", "HEAD"))
        commit(self.runtime)
        saved = self.root / "base-manifest.json"
        saved.write_bytes(manifest.read_bytes())
        git(self.runtime, "checkout", "-qb", "legacy-pr", unrecorded)
        save(self.runtime, "widget/cocoa/appshim/backend.mm", "native backend\n")
        commit(self.runtime)
        return saved

    def test_recorded_base_survives_switch_to_unrecorded_pr(self):
        saved = self.switch_to_unrecorded_pr()
        self.assertFalse((self.runtime / ".github/runtime-upstream.json").exists())
        before = self.snapshot()
        output = self.root / "github-output"
        result = self.cli(
            "guard",
            "--upstream",
            str(self.upstream),
            "--base-manifest",
            str(saved),
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "action=skip\n")
        self.assertEqual(self.snapshot(), before)

    def test_recorded_base_rejects_advancement_after_branch_switch(self):
        saved = self.switch_to_unrecorded_pr()
        save(self.upstream, "source.txt", "advanced\n")
        commit(self.upstream)
        before = self.snapshot()
        output = self.root / "github-output"
        result = self.cli(
            "guard",
            "--upstream",
            str(self.upstream),
            "--base-manifest",
            str(saved),
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("deliberate reintegration", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.snapshot(), before)

    def test_selected_recorded_pr_takes_precedence_over_base(self):
        manifest = self.pin(git(self.upstream, "rev-parse", "HEAD"))
        commit(self.runtime)
        saved = self.root / "base-manifest.json"
        saved.write_bytes(manifest.read_bytes())
        git(self.runtime, "checkout", "-qb", "integrated-pr")
        save(self.upstream, "source.txt", "advanced\n")
        self.pin(commit(self.upstream))
        commit(self.runtime)
        before = self.snapshot()
        output = self.root / "github-output"
        result = self.cli(
            "guard",
            "--upstream",
            str(self.upstream),
            "--base-manifest",
            str(saved),
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "action=skip\n")
        self.assertEqual(self.snapshot(), before)

    def test_invalid_selected_pin_does_not_fall_back_to_valid_base(self):
        saved = self.switch_to_unrecorded_pr()
        self.pin("invalid")
        result = self.cli(
            "guard", "--upstream", str(self.upstream), "--base-manifest", str(saved)
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid recorded", result.stderr)

    def test_unintegrated_checkout_can_sync(self):
        self.assertEqual(
            sync_action(self.runtime, self.upstream, self.root / "absent-base.json"),
            "sync",
        )

    def test_workflow_output_environment_is_supported(self):
        output = self.root / "github-output"
        result = self.cli(
            "guard",
            "--upstream",
            str(self.upstream),
            "--base-manifest",
            str(self.root / "absent-base.json"),
            env={**os.environ, "GITHUB_OUTPUT": str(output)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), "action=sync\n")

    def test_invalid_recorded_commit_fails_closed(self):
        self.pin("release")
        with self.assertRaisesRegex(ValueError, "immutable"):
            sync_action(self.runtime, self.upstream)

    def test_required_patches_apply_sequentially_without_modifying_checkout(self):
        first = self.patch("first", "synced", "middle")
        second = self.patch("second", "middle", "patched")
        self.policy([first, second])
        commit(self.runtime)
        save(self.runtime, "source.txt", "synced\n")
        before = self.snapshot()
        self.assertEqual(check_patches(self.runtime), 2)
        self.assertEqual(self.snapshot(), before)

    def test_unintegrated_legacy_patches_are_checked(self):
        self.patch("legacy", "old", "new")
        before = self.snapshot()
        self.assertEqual(check_patches(self.runtime), 1)
        self.assertEqual(self.snapshot(), before)

    def test_incompatible_required_patch_is_fatal(self):
        self.policy([self.patch("native", "missing baseline", "fixed")])
        before = self.snapshot()
        result = self.cli("check-patches")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Required upstream patch native.patch", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_required_patch_order_is_enforced(self):
        first = self.patch("first", "old", "middle")
        second = self.patch("second", "middle", "fixed")
        self.policy([second, first])
        with self.assertRaisesRegex(ValueError, "Required upstream patch second.patch"):
            check_patches(self.runtime)

    def test_required_patch_whitespace_errors_are_fatal(self):
        self.policy([self.patch("native", "old", "fixed ")])
        with self.assertRaisesRegex(ValueError, "whitespace"):
            check_patches(self.runtime)

    def test_empty_recorded_patch_inventory_fails_closed(self):
        self.policy([])
        with self.assertRaisesRegex(ValueError, "Missing required"):
            check_patches(self.runtime)

    def test_deleted_native_baseline_is_fatal(self):
        save(self.runtime, "widget/cocoa/appshim/backend.mm", "native\n")
        self.policy([
            self.patch("native", "native", "fixed", "widget/cocoa/appshim/backend.mm")
        ])
        commit(self.runtime)
        (self.runtime / "widget/cocoa/appshim/backend.mm").unlink()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "Required upstream patch native.patch"):
            check_patches(self.runtime)
        self.assertEqual(self.snapshot(), before)

    def test_missing_changed_or_undeclared_required_patch_is_fatal(self):
        patch = self.patch("native", "old", "fixed")
        self.policy([patch])
        original = patch.read_bytes()
        patch.unlink()
        with self.assertRaises(FileNotFoundError):
            check_patches(self.runtime)
        patch.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            check_patches(self.runtime)
        patch.write_bytes(original)
        self.patch("extra", "old", "fixed")
        with self.assertRaisesRegex(ValueError, "inventory"):
            check_patches(self.runtime)


if __name__ == "__main__":
    unittest.main()
