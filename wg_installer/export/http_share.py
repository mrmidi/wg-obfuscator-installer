from __future__ import annotations
import os, time, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import qrcode

from wg_installer.core.runner import Runner
from wg_installer.firewall.nft import add_temp_http_rule, del_temp_http_rule
from wg_installer.export.bundle import EXPORT_ROOT

class QuietHTTP(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence
        pass

def qr_print_and_png(text: str, png_path: Path, r: Runner) -> None:
    if r.dry_run:
        print(f"[DRY-RUN] Would generate QR for: {text}")
        return
    img = qrcode.make(text)
    png_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(png_path)

def serve_zip(public_host: str, port: int, zip_name: str, r: Runner) -> None:
    url = f"http://{public_host}:{port}/{zip_name}"
    index = f"""<!doctype html><meta charset="utf-8">
<title>WG Client Share</title><h1>WireGuard Client Download</h1>
<ul><li><a href="{zip_name}">{zip_name}</a></li></ul>
<h2>QR</h2><img src="qr/client-zip.png" alt="ZIP QR" width="240">
"""
    (EXPORT_ROOT / "index.html").write_text(index, encoding="utf-8")
    qr_print_and_png(url, EXPORT_ROOT / "qr" / "client-zip.png", r)

    handle = add_temp_http_rule(port, r)
    if r.dry_run:
        print(f"[DRY-RUN] Would start HTTP server on 0.0.0.0:{port} serving {EXPORT_ROOT}")
        return

    os.chdir(EXPORT_ROOT)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), QuietHTTP)
    print(f"[wg-installer] HTTP share on {url} (Ctrl+C to stop)")

    def _serve():
        try: httpd.serve_forever()
        except KeyboardInterrupt: pass
    t = threading.Thread(target=_serve, daemon=True); t.start()
    try:
        while t.is_alive(): time.sleep(0.25)
    finally:
        httpd.shutdown(); t.join()
        del_temp_http_rule(handle, r)