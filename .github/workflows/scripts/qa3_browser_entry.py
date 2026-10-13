# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
from pathlib import Path


def run(harness):
    parser = harness.MochitestArgumentParser(app="generic")
    options = parser.parse_args()
    parser.validate(options)
    if (
        options.flavor != "browser" or len(options.test_paths) != 1
        or options.repeat or options.verify or options.verify_fission
        or options.runUntilFailure or options.restartAfterFailure
    ):
        raise ValueError("fixed browser proof requires one execution of one test")

    class SinglePassMochitest(harness.MochitestDesktop):
        """Upstream retries failures only for its exact base class in automation."""

    logger_options = {
        key: value for key, value in vars(options).items()
        if key.startswith("log") or key == "valgrind"
    }
    runner = SinglePassMochitest(
        options.flavor, logger_options, options.stagedAddons, quiet=options.quiet
    )
    options.runByManifest = True
    result = runner.runTests(options)
    runner.archiveMozLogs()
    runner.message_logger.finish()
    return result


if __name__ == "__main__":
    root = Path(os.environ["QA3_MOCHITEST_ROOT"])
    sys.path.insert(0, str(root))
    import runtests

    sys.exit(run(runtests))
