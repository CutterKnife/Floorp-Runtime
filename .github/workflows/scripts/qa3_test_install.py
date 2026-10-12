# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import hashlib
import io
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath

MAX_MANIFEST_BYTES = 64 * 1024**2
MAX_EXPANDED_DIRECTORIES = 1024
MAX_EXPANDED_FILES = 100000
MAX_SOURCE_TREE_ENTRIES = 200000
MAX_RECEIPT_BYTES = 64 * 1024**2


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _destination(path):
    value = PurePosixPath(path)
    if (
        not path
        or value.is_absolute()
        or "\\" in path
        or str(value) != path
        or ".." in value.parts
    ):
        raise ValueError("test install destination escapes its manifest root")
    return path


def _output_path(output, source):
    output = Path(output).absolute()
    parent = output.parent.resolve(strict=True)
    if parent.is_relative_to(source) or output.exists() or output.is_symlink():
        raise ValueError("test install receipt must be fresh and outside source")
    return output


def _receipt_text(value):
    text = json.dumps(value, indent=2) + "\n"
    if len(text.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise ValueError("test install receipt budget exceeded")
    return text


def _write_receipt(output, value, text=None):
    with output.open("x", encoding="utf-8") as stream:
        stream.write(_receipt_text(value) if text is None else text)


def prepare_test_install(source, objdir, output):
    from mozpack.copier import FileRegistry
    from mozpack.files import FileFinder
    from mozpack.manifests import InstallManifest

    source = Path(source).resolve(strict=True)
    objdir = Path(objdir).absolute()
    if not source.is_dir() or objdir.is_symlink():
        raise ValueError("test install source or OBJDIR is invalid")
    objdir = objdir.resolve(strict=True)
    if objdir == source or source.is_relative_to(objdir):
        raise ValueError("test install OBJDIR must not contain source")
    output = _output_path(output, source)
    manifest_path = objdir / "_build_manifests/install/_test_files"
    for path in (manifest_path, *manifest_path.parents):
        if path.is_symlink():
            raise ValueError("generated test manifest traverses a symlink")
        if path == objdir:
            break
    if not manifest_path.is_file():
        raise ValueError("generated test manifest is missing")
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("generated test manifest budget exceeded")
    before = manifest_path.read_bytes()
    if len(before) > MAX_MANIFEST_BYTES:
        raise ValueError("generated test manifest budget exceeded")
    manifest = InstallManifest(path=str(manifest_path))
    directories = []
    file_count = 0
    tree_entries = 0
    replacement = InstallManifest()
    for destination, entry in sorted(manifest._dests.items()):
        _destination(destination)
        if entry[0] != InstallManifest.LINK or not Path(entry[1]).is_dir():
            replacement._add_entry(destination, entry)
            continue
        original = Path(entry[1])
        directory = original.resolve(strict=True)
        if not original.is_absolute() or not directory.is_relative_to(source):
            raise ValueError("test support directory escapes source")
        if len(directories) >= MAX_EXPANDED_DIRECTORIES:
            raise ValueError("test support directory budget exceeded")
        for current, children, leaves in os.walk(directory, followlinks=False):
            tree_entries += len(children) + len(leaves)
            if tree_entries > MAX_SOURCE_TREE_ENTRIES:
                raise ValueError("test support source tree budget exceeded")
            for child in children:
                if (Path(current) / child).is_symlink():
                    raise ValueError(
                        "test support directory contains a directory symlink"
                    )
        files = []
        for relative, _ in FileFinder(str(directory), find_dotfiles=True):
            file_count += 1
            if file_count > MAX_EXPANDED_FILES:
                raise ValueError("test support expansion budget exceeded")
            target = directory / relative
            resolved = target.resolve(strict=True)
            if not resolved.is_relative_to(source) or not resolved.is_file():
                raise ValueError(
                    "test support file escapes source or is not regular"
                )
            dest = _destination(destination + "/" + relative)
            replacement.add_link(str(target), dest)
            files.append({
                "source": target.relative_to(source).as_posix(),
                "destination": dest,
            })
        if not files:
            raise ValueError("test support directory has no installable files")
        directories.append({
            "source": directory.relative_to(source).as_posix(),
            "destination": destination,
            "files": files,
        })
    registry = FileRegistry()
    replacement.populate_registry(registry)
    value = io.StringIO()
    replacement.write(fileobj=value)
    after = value.getvalue().encode("utf-8") if directories else before
    if len(after) > MAX_MANIFEST_BYTES:
        raise ValueError("normalized test manifest budget exceeded")
    receipt = {
        "schema": "qa3-test-install-manifest-v1",
        "verdict": "PASS_GENERATED_MANIFEST_NORMALIZATION",
        "nativeExecuted": False,
        "manifest": str(manifest_path),
        "beforeSha256": _digest(before),
        "afterSha256": _digest(after),
        "manifestEntriesBefore": len(manifest),
        "manifestEntriesAfter": len(replacement),
        "expandedDirectoryCount": len(directories),
        "expandedFileCount": file_count,
        "expandedDirectories": directories,
    }
    receipt_text = _receipt_text(receipt)
    if directories:
        mode = stat.S_IMODE(manifest_path.stat().st_mode)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".qa3-test-install-", dir=manifest_path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(after)
            os.chmod(temporary, mode)
            os.replace(temporary, manifest_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    _write_receipt(output, receipt, receipt_text)
    return receipt


def _fixture(root, nested_objdir=False):
    from mozpack.manifests import InstallManifest

    source = root / "source"
    resources = source / "resources"
    (resources / ".hidden").mkdir(parents=True)
    payloads = {
        "simple.html": b"qa3-repeat-install-source\n",
        ".hidden.txt": b"qa3-dotfile\n",
        ".hidden/secret.txt": b"qa3-hidden-directory\n",
    }
    for relative, data in payloads.items():
        (resources / relative).write_bytes(data)
    (source / "unrelated.js").write_bytes(b"qa3-unrelated\n")
    objdir = (source if nested_objdir else root) / "objdir"
    manifest_path = objdir / "_build_manifests/install/_test_files"
    manifest_path.parent.mkdir(parents=True)
    manifest = InstallManifest()
    manifest.add_link(str(resources), "browser/resources")
    manifest.add_link(str(source / "unrelated.js"), "unrelated.js")
    for i in range(101):
        manifest.add_content("filler", "filler/" + str(i))
    manifest.write(path=str(manifest_path))
    return source, objdir, manifest_path, payloads


def exercise_test_install(root, nested_objdir=False):
    from mozbuild.action.process_install_manifest import process_manifest
    from mozpack.manifests import InstallManifest

    root = Path(root)
    source, objdir, manifest_path, payloads = _fixture(root, nested_objdir)
    dest = objdir / "_tests"
    track = objdir / "track"
    process_manifest(str(dest), [str(manifest_path)], str(track))
    if not (dest / "browser/resources").is_symlink():
        raise ValueError("fixture did not exercise the direct directory symlink")
    normalized = prepare_test_install(source, objdir, root / "normalization.json")
    for _ in range(2):
        process_manifest(str(dest), [str(manifest_path)], str(track))
        if (dest / "browser/resources").is_symlink():
            raise ValueError("normalized directory remains a directory symlink")
        for relative, data in payloads.items():
            installed = dest / "browser/resources" / relative
            if (
                installed.read_bytes() != data
                or (source / "resources" / relative).read_bytes() != data
            ):
                raise ValueError(
                    "repeated install changed source or installed contents"
                )
    unchanged = prepare_test_install(source, objdir, root / "unchanged.json")
    if (
        unchanged["beforeSha256"] != unchanged["afterSha256"]
        or unchanged["expandedFileCount"]
    ):
        raise ValueError("normalized manifest is not idempotent")
    manifest = InstallManifest(path=str(manifest_path))
    manifest._dests = {
        p: entry
        for p, entry in manifest._dests.items()
        if not p.startswith("browser/resources/")
    }
    manifest.write(path=str(manifest_path))
    process_manifest(str(dest), [str(manifest_path)], str(track))
    if (
        (dest / "browser").exists()
        or (dest / "unrelated.js").read_bytes() != b"qa3-unrelated\n"
    ):
        raise ValueError("obsolete normalized support cleanup differs")
    for relative, data in payloads.items():
        if (source / "resources" / relative).read_bytes() != data:
            raise ValueError("obsolete support cleanup changed source")
    collision_root = root / "collision"
    collision_source, collision_objdir, collision_manifest, _ = _fixture(
        collision_root
    )
    collision = InstallManifest(path=str(collision_manifest))
    collision.add_link(
        str(collision_source / "unrelated.js"), "browser/resources/simple.html"
    )
    collision.write(path=str(collision_manifest))
    before = collision_manifest.read_bytes()
    try:
        prepare_test_install(
            collision_source, collision_objdir, collision_root / "receipt.json"
        )
    except ValueError:
        pass
    else:
        raise ValueError("test support collision was accepted")
    if (
        collision_manifest.read_bytes() != before
        or (collision_root / "receipt.json").exists()
    ):
        raise ValueError("collision refusal modified its manifest or wrote a receipt")
    return {
        "fixtureManifestEntries": normalized["manifestEntriesBefore"],
        "expandedDirectories": normalized["expandedDirectoryCount"],
        "expandedFiles": normalized["expandedFileCount"],
        "initialDirectorySymlink": True,
        "repeatInstallPreservesSource": True,
        "dotfilesPreserved": True,
        "obsoleteExpandedLinksPreserveSource": True,
        "normalizationIdempotent": True,
        "collisionRefusedWithoutWrite": True,
    }


def probe_test_install(source, output):
    import mozbuild.action.process_install_manifest as action
    import mozpack.copier as copier
    import mozpack.files as files
    import mozpack.manifests as manifests

    source = Path(source).resolve(strict=True)
    output = _output_path(output, source)
    modules = {}
    for module, relative in (
        (action, "mozbuild/action/process_install_manifest.py"),
        (copier, "mozpack/copier.py"),
        (files, "mozpack/files.py"),
        (manifests, "mozpack/manifests.py"),
    ):
        path = Path(module.__file__).resolve(strict=True)
        if path != source / "python/mozbuild" / relative:
            raise ValueError("test install probe differs from the Runtime source")
        modules[relative] = _digest(path.read_bytes())
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        results = exercise_test_install(Path(temporary))
    receipt = {
        "schema": "qa3-test-install-probe-v1",
        "verdict": "PASS_REAL_INSTALL_MANIFEST_FIXTURE",
        "nativeExecuted": False,
        "modules": modules,
        **results,
    }
    _write_receipt(output, receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--objdir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prepare_test_install(args.source, args.objdir, args.output)
