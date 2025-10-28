from __future__ import annotations
import os, time, threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import qrcode
import zipfile

from wg_installer.core.runner import Runner
from wg_installer.firewall.nft import add_temp_http_rule, del_temp_http_rule
from wg_installer.export.bundle import EXPORT_ROOT
import urllib.request
from pathlib import Path

# Try to import Jinja2; fall back to simple HTML when unavailable
try:
    from jinja2 import Environment, FileSystemLoader
    _JINJA_AVAILABLE = True
except Exception:
    _JINJA_AVAILABLE = False

# Remote APK to include when HTTP share is enabled
APK_REMOTE_URL = "https://clusterm.github.io/wg-obfuscator-android/wg-obfuscator-v2-debug-250929-001531.apk"

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


def qr_print_ascii_from_text(text: str) -> None:
    """Print a block-style ASCII QR to the current terminal for `text`."""
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    print()
    for row in matrix:
        # print wide blocks for good scannability
        print("".join("  " if not cell else "██" for cell in row))
    print()

def serve_files(public_host: str, port: int, zip_name: str, apk_name: str | None, r: Runner) -> None:
    """Create an index with links and QR codes for the zip and optional apk, then serve EXPORT_ROOT.

    If apk_name is provided, include it in the index and generate a QR for it. The function
    will add a temporary nft rule to allow HTTP and remove it when the server stops.
    """
    # Ensure export directories
    (EXPORT_ROOT / "qr").mkdir(parents=True, exist_ok=True)
    (EXPORT_ROOT / "apk").mkdir(parents=True, exist_ok=True)

    # We no longer download the remote APK. If an APK was built locally (apk_name)
    # include that; otherwise include a link to the original remote APK URL and
    # generate a QR pointing at that URL.

    links = []
    # Include local built APK (if provided) otherwise link to the remote APK URL
    if apk_name:
        # apk_name is expected to be a basename (already under export)
        links.append((apk_name, "APK (built)"))
    else:
        links.append((APK_REMOTE_URL, "APK (debug remote)"))
    links.append((zip_name, "WireGuard client ZIP"))

    # Build template context
    links_ctx = [{"href": name, "label": label} for name, label in links]

    qr_images = []
    # APK QR present?
    if any(n for n, _ in links if n.endswith('.apk')):
        qr_images.append({"src": "qr/client-apk.png", "alt": "APK QR", "caption": "APK download"})
    qr_images.append({"src": "qr/client-zip.png", "alt": "ZIP QR", "caption": "ZIP download"})
    qr_images.append({"src": "qr/client-wg.png", "alt": "WireGuard config QR", "caption": "WireGuard config"})

    # Render using Jinja2 template if available, otherwise fallback to simple HTML
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    index_path = EXPORT_ROOT / "index.html"
    if _JINJA_AVAILABLE:
        try:
            env = Environment(loader=FileSystemLoader(str(template_dir)))
            tpl = env.get_template("share_index.html.j2")
            rendered = tpl.render(public_host=public_host, port=port, links=links_ctx, qr_images=qr_images)
            if r.dry_run:
                print("[DRY-RUN] Would render index.html from Jinja2 template with context:")
                print(f"  public_host={public_host} port={port} links={links_ctx} qr_images={qr_images}")
            else:
                index_path.write_text(rendered, encoding="utf-8")
        except Exception as e:
            print(f"[WARN] Jinja2 render failed: {e}; falling back to simple HTML")
            # Fall through to legacy writer below
            _JINJA_FALLBACK = True
    else:
        _JINJA_FALLBACK = False

    if (not _JINJA_AVAILABLE) or ('_JINJA_FALLBACK' in locals() and _JINJA_FALLBACK):
        parts = ["<!doctype html><meta charset=\"utf-8\">", "<title>WG Client Share</title>", "<h1>Downloads</h1>", "<ul>"]
        for name, label in links:
            parts.append(f'  <li><a href="{name}">{label}: {name}</a></li>')
        parts.append("</ul>")
        parts.append("<h2>QR codes</h2>")
        # Show APK QR if any APK link is present
        if any(n for n, _ in links if n.endswith('.apk')):
            parts.append('<p><img src="qr/client-apk.png" alt="APK QR" width="240"></p>')
        # QR for downloading ZIP
        parts.append('<p><img src="qr/client-zip.png" alt="ZIP QR" width="240"></p>')
        # QR encoding the WireGuard client config itself
        parts.append('<p><img src="qr/client-wg.png" alt="WireGuard config QR" width="240"></p>')
        index = "\n".join(parts)
        if r.dry_run:
            print("[DRY-RUN] Would write index.html (legacy)")
        else:
            (EXPORT_ROOT / "index.html").write_text(index, encoding="utf-8")

    # Generate QR images
    # Generate APK QR: if a local APK was built, point to its local URL; otherwise
    # point at the upstream APK URL (we don't download it).
    if apk_name:
        apk_qr_url = f"http://{public_host}:{port}/{apk_name}"
    else:
        apk_qr_url = APK_REMOTE_URL
    # Always generate the APK QR (dry-run will only print the action)
    qr_print_and_png(apk_qr_url, EXPORT_ROOT / "qr" / "client-apk.png", r)
    url_zip = f"http://{public_host}:{port}/{zip_name}"
    qr_print_and_png(url_zip, EXPORT_ROOT / "qr" / "client-zip.png", r)

    # Generate a PNG QR that encodes the WireGuard client configuration
    # itself (client-wg.conf) so users can scan it from the web page.
    try:
        zip_path = EXPORT_ROOT / zip_name
        if zip_path.exists() and not r.dry_run:
            with zipfile.ZipFile(zip_path, "r") as z:
                if "client-wg.conf" in z.namelist():
                    text = z.read("client-wg.conf").decode("utf-8")
                    qr_print_and_png(text, EXPORT_ROOT / "qr" / "client-wg.png", r)
                # Fallback: try obf client config if present
                elif "client-obf.conf" in z.namelist():
                    text = z.read("client-obf.conf").decode("utf-8")
                    qr_print_and_png(text, EXPORT_ROOT / "qr" / "client-wg.png", r)
    except Exception:
        # Non-fatal; continue serving even if QR generation fails
        pass

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