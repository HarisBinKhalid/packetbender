# Build a standalone PacketBender executable - no Python install, venv
# activation, or terminal needed to run the result.
#
# Output: dist\packetbender.exe (run it directly, e.g. double-click in
# File Explorer or `.\dist\packetbender.exe` from a terminal).
#
# The build itself still needs Python + a venv (one-time setup for
# whoever is building it); this script creates one if missing.
# Windows counterpart to build.sh - keep both in sync when changing.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$venvPython = ".venv\Scripts\python.exe"

# Not just "does .venv exist" - a .venv carried over from a Linux/macOS
# checkout (bin/ instead of Scripts/) would exist as a directory but have
# no Scripts\python.exe, silently breaking every step below.
if (-not (Test-Path $venvPython)) {
    Write-Output "Creating build virtual environment..."
    python -m venv .venv
}

& $venvPython -m pip install -q --upgrade pip
& $venvPython -m pip install -q -r requirements.txt
& $venvPython -m pip install -q pyinstaller

& ".venv\Scripts\pyinstaller.exe" packetbender.spec --noconfirm

Write-Output ""
Write-Output "Build complete: dist\packetbender.exe"
