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

def serve_files(public_host: str, port: int, zip_name: str, apk_name: str | None, r: Runner) -> None:
    """Create an index with links and QR codes for the zip and optional apk, then serve EXPORT_ROOT.

    If apk_name is provided, include it in the index and generate a QR for it. The function
    will add a temporary nft rule to allow HTTP and remove it when the server stops.
    """
    links = []
    if apk_name:
        links.append((apk_name, "APK"))
    links.append((zip_name, "WireGuard client ZIP"))

    parts = ["<!doctype html><meta charset=\"utf-8\">", "<title>WG Client Share</title>", "<h1>Downloads</h1>", "<ul>"]
    for name, label in links:
        parts.append(f'  <li><a href="{name}">{label}: {name}</a></li>')
    parts.append("</ul>")
    parts.append("<h2>QR codes</h2>")
    if apk_name:
        parts.append('<p><img src="qr/client-apk.png" alt="APK QR" width="240"></p>')
    parts.append('<p><img src="qr/client-zip.png" alt="ZIP QR" width="240"></p>')
    index = "\n".join(parts)
    (EXPORT_ROOT / "index.html").write_text(index, encoding="utf-8")

    # Generate QR images
    if apk_name:
        url_apk = f"http://{public_host}:{port}/{apk_name}"
        qr_print_and_png(url_apk, EXPORT_ROOT / "qr" / "client-apk.png", r)
    url_zip = f"http://{public_host}:{port}/{zip_name}"
    qr_print_and_png(url_zip, EXPORT_ROOT / "qr" / "client-zip.png", r)

    handle = add_temp_http_rule(port, r)
    if r.dry_run:
        print(f"[DRY-RUN] Would start HTTP server on 0.0.0.0:{port} serving {EXPORT_ROOT}")
        return

    os.chdir(EXPORT_ROOT)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), QuietHTTP)
    print(f"[wg-installer] HTTP share on http://{public_host}:{port}/ (Ctrl+C to stop)")

    def _serve():
        try: httpd.serve_forever()
        except KeyboardInterrupt: pass
    t = threading.Thread(target=_serve, daemon=True); t.start()
    try:
        while t.is_alive(): time.sleep(0.25)
    finally:
        httpd.shutdown(); t.join()
        del_temp_http_rule(handle, r)