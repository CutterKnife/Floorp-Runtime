# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
from pathlib import Path


def run(harness):
    parser = harness.parser_desktop()
    options = parser.parse_args()
    if (
        options.xpcshell is None
        or options.app_binary is not None
        or options.interactive
    ):
        raise ValueError("fixed proof requires explicit noninteractive xpcshell helper")
    root = (Path(os.environ["QA3_XPCSHELL_SUPPORT"]) / "xpcshell/tests").resolve(
        strict=True
    )
    if options.manifest is None or len(options.testPaths) != 1:
        raise ValueError("fixed proof requires one explicit xpcshell test and manifest")
    manifest = Path(options.manifest).resolve(strict=True)
    selected = Path(options.testPaths[0])
    if not selected.is_absolute():
        raise ValueError("fixed proof requires an absolute installed xpcshell test")
    selected = selected.resolve(strict=True)
    if (
        not manifest.is_relative_to(root)
        or not manifest.is_file()
        or not selected.is_file()
        or selected.parent != manifest.parent
    ):
        raise ValueError("xpcshell test and manifest differ from installed suite root")
    options.manifest = harness.TestManifest(
        [str(manifest)], strict=True, rootdir=str(root)
    )
    options.retry = False
    log = harness.commandline.setup_logging("XPCShell", options, {"raw": sys.stdout})
    tests = harness.XPCShellTests(log)
    result = tests.runTests(options)
    if "MOZ_AUTOMATION" in os.environ:
        harness.symbolicate_profiles()
    if result == harness.TBPL_RETRY:
        return 4
    return 0 if result else 1


if __name__ == "__main__":
    support = Path(os.environ["QA3_XPCSHELL_SUPPORT"])
    sys.path.insert(0, str(support / "xpcshell"))
    import runxpcshelltests

    sys.exit(run(runxpcshelltests))
