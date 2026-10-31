"""Lightweight web dashboard server for VeriPack prototype demonstration."""
import http.server
import socketserver
import sys
import webbrowser
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class VeriPackHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, format, *args):
        # Clean server logs
        sys.stderr.write(f"[VeriPack Web] {args[0]} - {args[1]}\n")


def serve(port: int = 8080, open_browser: bool = True) -> None:
    socketserver.TCPServer.allow_reuse_address = True
    for p in range(port, port + 10):
        try:
            with socketserver.TCPServer(("", p), VeriPackHandler) as httpd:
                url = f"http://localhost:{p}"
                print("=" * 70)
                print(f"[*] VeriPack Web Prototype running at: {url}")
                print(f"[*] Serving interactive UI from: {WEB_DIR}")
                print("=" * 70)
                if open_browser:
                    try:
                        webbrowser.open(url)
                    except Exception:
                        pass
                httpd.serve_forever()
                return
        except OSError:
            continue
    print(f"Error: Could not bind to ports {port}-{port+9}", file=sys.stderr)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    serve(port=port)
