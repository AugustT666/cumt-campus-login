"""Ship Windows WebView2 files without collecting every build/backend module.

pywebview currently probes all three native loader directories during import,
even when its actual process is x64. All three small loaders are required.
"""
import struct

from PyInstaller.compat import is_win
from PyInstaller.utils.hooks import collect_data_files, copy_metadata


if not is_win or struct.calcsize('P') != 8:
    raise RuntimeError('This specification builds the Windows x64 client only')

datas = collect_data_files('webview', include_py_files=False, includes=[
    'js/*.js', 'js/lib/*.js',
    'lib/Microsoft.Web.WebView2.Core.dll',
    'lib/Microsoft.Web.WebView2.WinForms.dll',
    'lib/runtimes/win-x64/native/WebView2Loader.dll',
    'lib/runtimes/win-x86/native/WebView2Loader.dll',
    'lib/runtimes/win-arm64/native/WebView2Loader.dll',
])
for distribution in ('pywebview', 'pythonnet', 'clr_loader', 'cffi',
                     'proxy_tools', 'bottle', 'typing_extensions'):
    # Metadata contains the licenses supplied by the installed runtime packages.
    datas += copy_metadata(distribution)

hiddenimports = ['webview.platforms.winforms', 'webview.platforms.edgechromium']
