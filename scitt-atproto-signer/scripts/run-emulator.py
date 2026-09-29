#!/usr/bin/env python3
"""Run the SCITT API Emulator for the integration tests.

The stock entry point (`scitt-emulator server`) starts Flask in debug mode,
which turns on the reloader: the process forks, readiness has to be detected
against the child, and a signal to the parent leaves the child holding the
port. It also defaults `--error-rate` to 0.01, so one request in a hundred is
answered 503 and a test that mostly passes is a test that will flake.

Both are fine for a person at a terminal and wrong for a test. This starts the
same application without either.

Usage: run-emulator.py <workspace> <port> [--verify-signature]
"""

import argparse
import sys
from pathlib import Path

from scitt_emulator.server import create_flask_app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--verify-signature",
        action="store_true",
        help="Check each Signed Statement's signature at registration, per "
        "Section 6.3 of RFC 9943.",
    )
    args = parser.parse_args()

    app = create_flask_app(
        {
            "middleware": [],
            "middleware_config_path": [],
            "workspace": args.workspace,
            "error_rate": 0.0,
            "use_lro": False,
            "rate_limit_requests": 0,
            "rate_limit_period": 1.0,
            "verify_signature": args.verify_signature,
        }
    )
    app.debug = False
    app.run(
        host="127.0.0.1",
        port=args.port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
