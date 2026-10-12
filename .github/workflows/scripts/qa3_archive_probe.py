# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from qa3_native_io import IOBudget, extract_archive


def probe_archive_members(source, output):
    import mozpack.archive
    from mozpack.archive import create_tar_from_files
    from mozpack.files import GeneratedFile

    source = source.resolve(strict=True)
    archiver = Path(mozpack.archive.__file__).resolve(strict=True)
    if archiver != source / "python/mozbuild/mozpack/archive.py":
        raise ValueError("archive member probe uses a foreign Mozilla writer")
    if (
        output.exists()
        or output.is_symlink()
        or output.parent.resolve(strict=True).is_relative_to(source)
    ):
        raise ValueError("archive member probe output must be fresh outside source")

    class FixtureFile(GeneratedFile):
        def __init__(self, content, mode):
            super().__init__(content)
            self._mode = mode

        @property
        def mode(self):
            return self._mode

    fixtures = [
        (
            "mozbase//probe/readable.txt",
            "mozbase/probe/readable.txt",
            b"mozbase",
            0o644,
        ),
        (
            "mochitest/browser/./fixture.js",
            "mochitest/browser/fixture.js",
            b"mochitest",
            0o755,
        ),
        (
            "xpcshell/tests/unit/../probe.js",
            "xpcshell/tests/probe.js",
            b"xpcshell",
            0o644,
        ),
    ]

    def write_archive(path, entries):
        with path.open("xb") as stream:
            create_tar_from_files(
                stream,
                {name: FixtureFile(data, mode) for name, data, mode in entries},
            )
        if path.stat().st_size > 65536:
            raise ValueError("archive member fixture exceeds byte budget")

    def reject(path, destination, normalized):
        try:
            extract_archive(path, destination, normalize_member_paths=normalized)
        except ValueError:
            return
        raise ValueError("archive member negative fixture was accepted")

    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        root = Path(temporary)
        archive = root / "mozilla-members.tar"
        write_archive(archive, [(raw, data, mode) for raw, _, data, mode in fixtures])
        with tarfile.open(archive, "r:") as reader:
            members = reader.getmembers()
            if (
                [member.name for member in members]
                != sorted(row[0] for row in fixtures)
                or not all(member.isreg() for member in members)
            ):
                raise ValueError("Mozilla writer changed fixture member spelling")
        reject(archive, root / "strict", False)
        destination = root / "normalized"
        result = extract_archive(
            archive,
            destination,
            budget=IOBudget(root, maximum=65536, minimum_free=0),
            normalize_member_paths=True,
        )
        if result != {
            "members": len(fixtures),
            "expandedBytes": sum(len(row[2]) for row in fixtures),
        }:
            raise ValueError("normalized archive member receipt differs")
        for _, canonical, data, mode in fixtures:
            path = destination / canonical
            if path.read_bytes() != data or bool(path.stat().st_mode & 0o111) != bool(
                mode & 0o111
            ):
                raise ValueError("normalized archive file bytes or mode differ")
        negative_cases = 0
        for index, name in enumerate((
            "/absolute",
            "//absolute",
            "../outside",
            "parent/../../outside",
            "parent/\\outside",
            "parent/\noutside",
            ".",
            "parent/..",
        )):
            path = root / f"negative-{index}.tar"
            write_archive(path, [(name, b"rejected", 0o644)])
            reject(path, root / f"negative-{index}", True)
            negative_cases += 1
        duplicate = root / "duplicate.tar"
        write_archive(
            duplicate,
            [("payload", b"first", 0o644), ("parent/../payload", b"second", 0o644)],
        )
        reject(duplicate, root / "duplicate", True)
        negative_cases += 1
        special_types = (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE)
        for index, kind in enumerate(special_types):
            path = root / f"special-{index}.tar"
            with tarfile.open(path, "w") as writer:
                member = tarfile.TarInfo("alias")
                member.type = kind
                member.linkname = "payload"
                writer.addfile(member)
                if kind == tarfile.SYMTYPE:
                    member = tarfile.TarInfo("parent/../alias/child")
                    member.size = 0
                    writer.addfile(member)
            reject(path, root / f"special-{index}", True)
            negative_cases += 1
        value = {
            "schema": "qa3-archive-member-probe-v1",
            "verdict": "PASS_TEST_ARCHIVE_NORMALIZATION_ONLY",
            "nativeExecuted": False,
            "publicationAuthorized": False,
            "archiverSha256": hashlib.sha256(archiver.read_bytes()).hexdigest(),
            "fixtureTarSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "fixtureTarBytes": archive.stat().st_size,
            "normalizedMembers": len(fixtures),
            "negativeCases": negative_cases,
            "strictDefaultRejected": True,
        }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    probe_archive_members(args.source, args.output)
