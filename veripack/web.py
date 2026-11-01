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

    def do_POST(self):
        if self.path == "/api/qwen":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                import json
                data = json.loads(body.decode("utf-8"))
                file_path = data.get("file_path", "")
                classification = data.get("classification", "EXPECTED_BUILD_ARTIFACT")
                evidence = data.get("evidence", [])
                diff_snippet = data.get("diff_snippet", "")
                entropy = data.get("entropy")
                prompt = data.get("prompt", "")

                from veripack.llm import query_qwen_explainer
                explanation = query_qwen_explainer(
                    file_path=file_path,
                    classification=classification,
                    evidence=evidence,
                    diff_snippet=diff_snippet,
                    entropy=entropy,
                    custom_prompt=prompt if prompt else None,
                )
                response_data = json.dumps({"response": explanation}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_data)))
                self.end_headers()
                self.wfile.write(response_data)
                return
            except Exception as e:
                import json
                err_data = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_data)))
                self.end_headers()
                self.wfile.write(err_data)
                return

        self.send_error(404, "Endpoint not found")


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
