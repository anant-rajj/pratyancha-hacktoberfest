#!/usr/bin/env python3
"""Convenience launcher for the VeriPack web dashboard."""
import sys
import http.server
import socketserver
import webbrowser
from pathlib import Path

cur_dir = Path(__file__).resolve().parent
repo_dir = cur_dir.parent if (cur_dir.parent / "veripack").exists() else cur_dir.parent / "pratyancha-hacktoberfest"

if repo_dir.exists():
    sys.path.insert(0, str(repo_dir))

try:
    from veripack.web import serve
    if __name__ == "__main__":
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
        serve(port=port)
except Exception:
    # Standalone mode
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    socketserver.TCPServer.allow_reuse_address = True
    class StandaloneHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(cur_dir), **kwargs)

    url = f"http://localhost:{port}"
    print("=" * 70)
    print(f"[*] VeriPack Web Dashboard running at: {url}")
    print(f"[*] Serving files from: {cur_dir}")
    print("=" * 70)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    with socketserver.TCPServer(("", port), StandaloneHandler) as httpd:
        httpd.serve_forever()
