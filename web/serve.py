#!/usr/bin/env python3
"""Convenience launcher for the VeriPack web dashboard."""
import os
import sys
import http.server
import socketserver
import webbrowser
from pathlib import Path

cur_dir = Path(__file__).resolve().parent
repo_dir = cur_dir.parent if (cur_dir.parent / "veripack").exists() else cur_dir.parent / "pratyancha-hacktoberfest"

if repo_dir.exists():
    sys.path.insert(0, str(repo_dir))

def get_port() -> int:
    env_port = os.getenv("PORT")
    if env_port:
        return int(env_port)
    return int(sys.argv[1]) if len(sys.argv) > 1 else 8080

try:
    from veripack.web import serve
    if __name__ == "__main__":
        port = get_port()
        serve(port=port, open_browser=False if os.getenv("PORT") else True)
except Exception:
    # Standalone mode
    port = get_port()
    socketserver.TCPServer.allow_reuse_address = True
    class StandaloneHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(cur_dir), **kwargs)

    url = f"http://localhost:{port}"
    print("=" * 70)
    print(f"[*] VeriPack Web Dashboard running at: {url}")
    print(f"[*] Serving files from: {cur_dir}")
    print("=" * 70)
    if not os.getenv("PORT"):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    with socketserver.TCPServer(("", port), StandaloneHandler) as httpd:
        httpd.serve_forever()
