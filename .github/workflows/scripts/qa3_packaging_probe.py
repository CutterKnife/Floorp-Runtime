# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
from pathlib import Path


def probe(source, output):
    if (
        os.environ.get("MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE") != "pip"
        or os.environ.get("MOZ_AUTOMATION") != "1"
    ):
        raise ValueError("packaging requires scoped automated Mach pip mode")
    if sys.version_info[:2] != (3, 12):
        raise ValueError("packaging Python ABI differs")
    import mozpack.archive
    import zstandard
    from mach.site import MozSiteMetadata
    from mozpack.archive import create_tar_zst_from_files
    from mozpack.files import GeneratedFile

    version = zstandard.__version__
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not (0, 11, 1) <= tuple(
        map(int, version.split("."))
    ) <= (0, 25, 0):
        raise ValueError("zstandard version is outside the pinned Mach requirement")
    module = Path(zstandard.__file__).resolve(strict=True)
    state = Path(os.environ["MOZBUILD_STATE_PATH"]).resolve(strict=True)
    build_root = Path(sys.prefix).resolve(strict=True)
    mach_root = (build_root.parent / "mach").resolve(strict=True)
    runtime_site = MozSiteMetadata.from_runtime()
    build_site = MozSiteMetadata.from_path(str(build_root))
    mach_site = MozSiteMetadata.from_path(str(mach_root))
    if (
        build_root.name != "build"
        or build_root.parent.name != "_virtualenvs"
        or not build_root.is_relative_to(state)
        or mach_root.parent != build_root.parent
    ):
        raise ValueError("packaging command site escapes its managed scope")
    for metadata, name in (
        (runtime_site, "build"),
        (build_site, "build"),
        (mach_site, "mach"),
    ):
        if (
            metadata is None
            or metadata.site_name != name
            or metadata.mach_site_packages_source.value != "pip"
            or metadata.hex_version != sys.hexversion
        ):
            raise ValueError("packaging Mach/build metadata differs")
    if not module.is_relative_to(mach_root):
        raise ValueError("packaging dependency escapes the managed Mach environment")
    archiver = Path(mozpack.archive.__file__).resolve(strict=True)
    if archiver != source.resolve() / "python/mozbuild/mozpack/archive.py":
        raise ValueError("packaging archiver differs from the Runtime source")
    payload = b"QA3_SOURCE_ARCHIVE_DEPENDENCY_PROBE\n"
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        archive = Path(temporary) / "fixture.tar.zst"
        with archive.open("wb") as stream:
            create_tar_zst_from_files(
                stream, {"qa3-packaging-probe.txt": GeneratedFile(payload)}, threads=1
            )
        if archive.stat().st_size > 65536:
            raise ValueError("packaging probe archive budget exceeded")
        compressed = archive.read_bytes()
        with zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(compressed)
        ) as reader:
            decoded = reader.read(16385)
            if len(decoded) > 16384 or reader.read(1):
                raise ValueError("packaging probe decode budget exceeded")
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as tar:
            members = tar.getmembers()
            if (
                len(members) != 1
                or members[0].name != "qa3-packaging-probe.txt"
                or not members[0].isreg()
                or tar.extractfile(members[0]).read() != payload
            ):
                raise ValueError("actual Mozilla tar.zst writer roundtrip differs")
    with (output.parent / "probe-fixture.tar.zst").open("xb") as stream:
        stream.write(compressed)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from qa3_archive_probe import probe_archive_members
    from qa3_test_install import probe_test_install

    test_install = probe_test_install(source, output.parent / "test-install-probe.json")
    archive_members = probe_archive_members(
        source, output.parent / "archive-member-probe.json"
    )
    value = {
        "schema": "qa3-packaging-python-probe-v1",
        "verdict": "PASS_SOURCE_ARCHIVE_ONLY",
        "nativeExecuted": False,
        "nativePackageSource": "pip",
        "commandSiteRoot": str(build_root),
        "machSiteRoot": str(mach_root),
        "buildSiteMetadataSha256": hashlib.sha256(
            Path(build_site.prefix).read_bytes()
        ).hexdigest(),
        "machSiteMetadataSha256": hashlib.sha256(
            Path(mach_site.prefix).read_bytes()
        ).hexdigest(),
        "pythonVersion": sys.version,
        "zstandardVersion": version,
        "zstandardModule": str(module),
        "zstandardModuleSha256": hashlib.sha256(module.read_bytes()).hexdigest(),
        "archiverSha256": hashlib.sha256(archiver.read_bytes()).hexdigest(),
        "probeArchiveSha256": hashlib.sha256(compressed).hexdigest(),
        "probeArchiveBytes": len(compressed),
        "probeTarSha256": hashlib.sha256(decoded).hexdigest(),
        "testInstallProbe": test_install,
        "archiveMemberProbe": archive_members,
    }
    with output.open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    probe(args.source, args.output)
