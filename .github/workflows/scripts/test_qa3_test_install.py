# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import tempfile
import unittest
from pathlib import Path

from qa3_test_install import _fixture, exercise_test_install, prepare_test_install


class TestTestInstallManifest(unittest.TestCase):
    def test_real_repeated_install_and_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = exercise_test_install(Path(temporary))
        self.assertGreater(result["fixtureManifestEntries"], 100)
        self.assertEqual(result["expandedFiles"], 4)
        for name, value in result.items():
            if isinstance(value, bool):
                self.assertTrue(value, name)

    def test_real_repeated_install_with_objdir_inside_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = exercise_test_install(Path(temporary), nested_objdir=True)
        self.assertTrue(result["repeatInstallPreservesSource"])
        self.assertTrue(result["obsoleteExpandedLinksPreserveSource"])

    def test_conflicting_pattern_alias_refused_without_write(self):
        from mozpack.manifests import InstallManifest

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            different = source / "different"
            different.mkdir()
            (different / "parent-one.txt").write_bytes(b"conflicting content")
            manifest = InstallManifest(path=str(path))
            manifest.add_pattern_link(
                str(different), "*.txt", "another/../shared"
            )
            manifest.write(path=str(path))
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "conflicting.*alias"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse((root / "receipt.json").exists())

    def test_escaping_pattern_output_refused_without_write(self):
        from mozpack.manifests import InstallManifest

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            manifest = InstallManifest(path=str(path))
            manifest.add_pattern_copy(str(source / "pattern-copy"), "*.txt", "..")
            manifest.write(path=str(path))
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "type='File', key="):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse((root / "receipt.json").exists())

    def test_external_directory_refused_without_write(self):
        from mozpack.manifests import InstallManifest

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            outside = root / "outside"
            outside.mkdir()
            (outside / "file").write_bytes(b"outside")
            manifest = InstallManifest(path=str(path))
            manifest.add_link(str(outside), "external")
            manifest.write(path=str(path))
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "escapes source"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse((root / "receipt.json").exists())

    def test_symlink_manifest_refused_without_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            original = root / "original-manifest"
            path.rename(original)
            try:
                path.symlink_to(original)
            except OSError:
                self.skipTest("fixture filesystem does not support symlinks")
            before = original.read_bytes()
            with self.assertRaisesRegex(ValueError, "symlink"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(original.read_bytes(), before)

    def test_empty_directory_refused_without_write(self):
        from mozpack.manifests import InstallManifest

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            empty = source / "empty"
            empty.mkdir()
            manifest = InstallManifest(path=str(path))
            manifest.add_link(str(empty), "empty")
            manifest.write(path=str(path))
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "no installable files"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)

    def test_external_symlink_file_refused_without_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            outside = root / "outside.txt"
            outside.write_bytes(b"outside")
            try:
                (source / "resources/external.txt").symlink_to(outside)
            except OSError:
                self.skipTest("fixture filesystem does not support symlinks")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "escapes source"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse((root / "receipt.json").exists())

    def test_directory_symlink_refused_without_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, objdir, path, _ = _fixture(root)
            try:
                (source / "resources/loop").symlink_to(
                    source / "resources", target_is_directory=True
                )
            except OSError:
                self.skipTest("fixture filesystem does not support symlinks")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "directory symlink"):
                prepare_test_install(source, objdir, root / "receipt.json")
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse((root / "receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
