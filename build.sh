#!/usr/bin/env bash
# Build a standalone PacketBender executable - no Python install, venv
# activation, or terminal needed to run the result.
#
# Output: dist/packetbender (run it directly, e.g. double-click in a
# file manager or `./dist/packetbender` from a terminal).
#
# The build itself still needs Python + a venv (one-time setup for
# whoever is building it); this script creates one if missing.
# Windows counterpart: build.ps1 - keep both in sync when changing.
set -euo pipefail
cd "$(dirname "$0")"

# Not just "does .venv exist" - a .venv carried over from a Windows
# checkout (Scripts/ instead of bin/) would exist as a directory but have
# no bin/python, silently breaking every step below.
if [ ! -x .venv/bin/python ]; then
    echo "Creating build virtual environment..."
    python3 -m venv .venv
fi

.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt
.venv/bin/pip install -q pyinstaller

.venv/bin/pyinstaller packetbender.spec --noconfirm

echo
echo "Build complete: dist/packetbender"
