# -*- mode: python ; coding: utf-8 -*-
import ast
from pathlib import Path
from PyInstaller.utils.win32.versioninfo import (VSVersionInfo,FixedFileInfo,StringFileInfo,
                                                StringTable,StringStruct,VarFileInfo,VarStruct)

# SPECPATH is supplied by PyInstaller and stays valid if this folder is moved.
ROOT = Path(SPECPATH).resolve()
version_tree = ast.parse((ROOT / 'campus_core.py').read_text(encoding='utf-8'))
VERSION = next(ast.literal_eval(node.value) for node in version_tree.body
               if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'VERSION'
                       for target in node.targets))

version_parts=tuple(int(part) for part in VERSION.split('.'))
assert len(version_parts)<=4
numeric_version=version_parts+(0,)*(4-len(version_parts))
version_info=VSVersionInfo(
    ffi=FixedFileInfo(filevers=numeric_version,prodvers=numeric_version,
                      mask=0x3f,flags=0,OS=0x40004,fileType=0x1,subtype=0,date=(0,0)),
    kids=[StringFileInfo([StringTable('080404B0',[
        StringStruct('FileDescription','矿大校园网登录器'),
        StringStruct('FileVersion',VERSION),
        StringStruct('ProductName','矿大校园网登录器'),
        StringStruct('ProductVersion',VERSION),
        StringStruct('InternalName','CumtCampusLogin'),
        StringStruct('OriginalFilename',f'矿大校园网登录器_v{VERSION}.exe'),
    ])]),VarFileInfo([VarStruct('Translation',[2052,1200])])])

datas = [(str(ROOT / 'campus_ui.html'), '.')]
datas += [(str(ROOT/'assets'/name),'assets') for name in ('logo.png','icon.ico')]
binaries = []
hiddenimports = ['clr', 'pythonnet', 'webview.platforms.winforms',
                 'webview.platforms.edgechromium']


a = Analysis(
    [str(ROOT / 'campus_app.py')],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[str(ROOT / 'build_support' / 'hooks')],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['playwright', 'greenlet', 'pyee', 'webview.__pyinstaller',
              'webview.platforms.android', 'webview.platforms.cef',
              'webview.platforms.cocoa', 'webview.platforms.gtk',
              'webview.platforms.qt', 'webview.platforms.mshtml',
              'PyInstaller', '_pyinstaller_hooks_contrib', 'setuptools',
              'pkg_resources', 'pefile', 'altgraph', 'packaging'],
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
    name=f'矿大校园网登录器_v{VERSION}',
    icon=str(ROOT/'assets'/'icon.ico'),
    version=version_info,
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
