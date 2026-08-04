# -*- mode: python ; coding: utf-8 -*-
#
# Builds a self-contained executable: `pyinstaller packetbender.spec`
# (or just run build.sh). scapy dynamically imports its layer modules at
# runtime rather than via top-level imports PyInstaller's static
# analysis can see, so every scapy submodule is force-included below -
# without it, the packaged binary loads fine but fails to dissect most
# non-trivial protocols.
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('scapy')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='packetbender',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
