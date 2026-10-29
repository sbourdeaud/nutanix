# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for get_vm_stats.

Build on the platform you want a binary for (PyInstaller does not cross-compile):

    pyinstaller --noconfirm --clean get_vm_stats.spec
"""
from PyInstaller.utils.hooks import collect_data_files, collect_submodules


def _try_submodules(package):
    try:
        return collect_submodules(package)
    except Exception:
        return []


hiddenimports = []
for package in (
    "keyring.backends",
    "ntnx_aiops_py_client",
    "ntnx_clustermgmt_py_client",
    "ntnx_networking_py_client",
    "ntnx_vmm_py_client",
    "certifi",
):
    hiddenimports += _try_submodules(package)

datas = []
datas += collect_data_files("certifi")
datas += collect_data_files("plotly")

a = Analysis(
    ["get_vm_stats.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "IPython",
        "jupyter",
        "jupyter_client",
        "pytest",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
    ],
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
    name="get_vm_stats",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
