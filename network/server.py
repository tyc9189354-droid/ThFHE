import os
import sys
import pickle
import base64
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any

# 加入專案路徑
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schemes.dummy_scheme import DummyThFHEScheme

# 全域伺服器狀態
SERVER_SCHEMES: Dict[str, Any] = {
    "dummy": DummyThFHEScheme()
}

def register_scheme(name: str, scheme_instance: Any):
    SERVER_SCHEMES[name] = scheme_instance

class BenchmarkHTTPRequestHandler(BaseHTTPRequestHandler):
    """輕量化標準 HTTP 伺服器處理器 (無需第三方套件即可在雲端執行)"""

    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "ok", "schemes": list(SERVER_SCHEMES.keys())}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req_json = json.loads(post_data.decode("utf-8"))
        except Exception as e:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": f"Invalid JSON: {str(e)}"}).encode())
            return

        scheme_name = req_json.get("scheme", "dummy")
        scheme = SERVER_SCHEMES.get(scheme_name)
        if not scheme:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": f"Scheme {scheme_name} not registered"}).encode())
            return

        endpoint = self.path
        if endpoint == "/api/setup":
            sec = req_json.get("security_param", 128)
            t = req_json.get("threshold_t", 2)
            n = req_json.get("total_n", 3)
            scheme.setup(security_param=sec, threshold_t=t, total_n=n)
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "setup complete"}).encode())

        elif endpoint == "/api/eval":
            # 雲端伺服器執行同態運算 (Homomorphic Evaluation)
            op = req_json.get("op", "add")
            ct1 = pickle.loads(base64.b64decode(req_json["ct1"]))
            ct2 = pickle.loads(base64.b64decode(req_json["ct2"]))
            eval_key = pickle.loads(base64.b64decode(req_json["eval_key"])) if "eval_key" in req_json else None

            if op == "add":
                res_ct = scheme.eval_add(ct1, ct2, eval_key)
            elif op == "mult":
                res_ct = scheme.eval_mult(ct1, ct2, eval_key)
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": f"Unsupported op {op}"}).encode())
                return

            res_bytes = pickle.dumps(res_ct)
            res_b64 = base64.b64encode(res_bytes).decode("ascii")

            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "success",
                "result_ct": res_b64,
                "bytes_size": len(res_bytes)
            }).encode())

        elif endpoint == "/api/combine":
            # 雲端伺服器匯聚部分解密份額重構明文
            raw_shares = [pickle.loads(base64.b64decode(s)) for s in req_json["shares"]]
            raw_ct = pickle.loads(base64.b64decode(req_json["ciphertext"]))
            pk = pickle.loads(base64.b64decode(req_json["pk"])) if "pk" in req_json else None

            result_plain = scheme.combine_decryption(raw_shares, raw_ct, pk)
            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "success",
                "plaintext": result_plain
            }).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": f"Endpoint {endpoint} not found"}).encode())

def run_server(host: str = "0.0.0.0", port: int = 8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, BenchmarkHTTPRequestHandler)
    print(f"[*] ThFHE Benchmark Cloud Server is listening on {host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.server_close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Start ThFHE Cloud Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host")
    parser.add_argument("--port", type=int, default=8000, help="Port number")
    args = parser.parse_args()
    run_server(args.host, args.port)
