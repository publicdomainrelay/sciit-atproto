#!/usr/bin/env bash
#
# Set up the Python environment the integration tests drive.
#
# The tests reach a real SCITT API Emulator rather than a mock, because the
# thing being tested is whether this service speaks SCRAPI: a mock would be a
# second implementation of the same reading of the draft, and agreement between
# two readings is not evidence.
#
# The emulator is installed from a GitHub zip archive pinned to a commit SHA,
# into a virtual environment beside this crate, so nothing outside this
# directory is modified. Set SCITT_EMULATOR_PATH to install a local checkout
# in editable mode instead.
#
# Usage: scripts/setup-emulator.sh [python]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(dirname "$here")"
sha="3e66d71d08c5a314f6175b7bafb1d03de770661a"
archive="https://github.com/publicdomainrelay/scitt-api-emulator/archive/$sha.zip"
venv="$crate/.emulator-venv"
python="${1:-python3}"

if [ ! -x "$venv/bin/python" ]; then
    echo "creating $venv"
    "$python" -m venv "$venv"
fi

"$venv/bin/pip" install --quiet --upgrade pip
# `setup.py` lists the emulator's own dependencies, but the entry point it
# installs imports PyJWT, which is not among them; without it the server
# fails at import.
if [ -n "${SCITT_EMULATOR_PATH:-}" ]; then
    "$venv/bin/pip" install --quiet --editable "$SCITT_EMULATOR_PATH" PyJWT
else
    "$venv/bin/pip" install --quiet "$archive" PyJWT
fi

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
