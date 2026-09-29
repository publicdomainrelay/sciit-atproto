#!/usr/bin/env bash
#
# Set up the Python environment the integration tests drive.
#
# The tests reach a real SCITT API Emulator rather than a mock, because the
# thing being tested is whether this service speaks SCRAPI: a mock would be a
# second implementation of the same reading of the draft, and agreement between
# two readings is not evidence.
#
# The emulator lives in ../scitt-api-emulator and is installed into a virtual
# environment beside this script's crate, so nothing outside this directory is
# modified.
#
# Usage: scripts/setup-emulator.sh [python]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(dirname "$here")"
emulator="${SCITT_EMULATOR_PATH:-$crate/../scitt-api-emulator}"
venv="$crate/.emulator-venv"
python="${1:-python3}"

if [ ! -d "$emulator" ]; then
    echo "no SCITT API Emulator at $emulator" >&2
    echo "set SCITT_EMULATOR_PATH to its checkout" >&2
    exit 1
fi

if [ ! -x "$venv/bin/python" ]; then
    echo "creating $venv"
    "$python" -m venv "$venv"
fi

"$venv/bin/pip" install --quiet --upgrade pip
# `setup.py` lists the emulator's own dependencies, but the entry point it
# installs imports PyJWT, which is not among them; without it the server
# fails at import.
"$venv/bin/pip" install --quiet --editable "$emulator" PyJWT

"$venv/bin/python" - <<'PY'
import flask  # noqa: F401
import jwt  # noqa: F401
import pycose  # noqa: F401
import scitt_emulator  # noqa: F401

print("the emulator and its dependencies are installed")
PY

echo
echo "run the tests with:"
echo "  cargo test --test integration -- --nocapture"
