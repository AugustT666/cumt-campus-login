"""Resize the approved PNG master and assemble the Windows icon, entirely offline.

No network requests or user settings are used. PNG frames are rendered directly
at their target resolution, so the desktop icon stays clear at small sizes.
"""
from pathlib import Path
import base64
import json
import struct
import sys
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 24, 32, 48, 64, 128, 256)


def main():
    directory = ROOT / 'assets'
    master = (directory / 'logo-master.png').read_bytes()
    source = 'data:image/png;base64,' + base64.b64encode(master).decode('ascii')
    frames = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel='msedge', headless=True,
                                    args=['--no-proxy-server', '--disable-background-networking'])
        context = browser.new_context(service_workers='block', device_scale_factor=1)
        context.route('**/*', lambda route: route.abort())
        page = context.new_page()
        for size in (*SIZES, 512):
            page.set_viewport_size({'width': size, 'height': size})
            page.set_content(f'<style>html,body{{margin:0;overflow:hidden}}img{{width:{size}px;height:{size}px;display:block}}</style><img src="{source}">',wait_until='load')
            frame = page.screenshot(omit_background=True)
            if size == 512:
                (directory / 'logo.png').write_bytes(frame)
            else:
                assert struct.unpack('>II', frame[16:24]) == (size, size)
                frames.append((size, frame))
        context.close()
        browser.close()
    offset = 6 + 16 * len(frames)
    entries = []
    for size, data in frames:
        entries.append(struct.pack('<BBBBHHII', size if size < 256 else 0,
                                   size if size < 256 else 0, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    ico = struct.pack('<HHH', 0, 1, len(frames)) + b''.join(entries) + b''.join(data for _, data in frames)
    (directory / 'icon.ico').write_bytes(ico)
    print(json.dumps({'master': 'assets/logo-master.png', 'png': 'assets/logo.png',
                      'ico': 'assets/icon.ico', 'sizes': SIZES}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
