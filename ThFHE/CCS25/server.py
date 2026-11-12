#!/usr/bin/env python3
"""
================================================================================
CCS 2025: Server Module (Cloud / Coordinator Server for Threshold FHE Decryption)
Paper: "High-Throughput Universally Composable Threshold FHE Decryption"
Supports:
  - Setup & Distributed KeyGen (10 <= num_parties <= 1000)
  - Encryption (/encrypt_demo)
  - Homomorphic Addition (/eval_add) & Homomorphic Multiplication (/eval_mul)
  - One-shot & 3-Round Interactive MPC Rounding Decryption (/decrypt)
================================================================================
"""

import os
import sys
import json
import time
import math
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

# Add paths to locate tool.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import (
    ThresholdFHEDecryptor,
    ToyLWE,
    StoredVar,
    PreprocessedGates,
    ltrand,
    mod_l_k,
    encode_ciphertext,
    decode_ciphertext
)

# Global Server State
SERVER_STATE = {
    "k": 64,
    "m": 1,
    "b": 8,
    "n_dim": 16,
    "num_parties": 10,
    "decryptor": None,
    "lwe": None,
    "s_ext_stored": None,
    "gates_pool": [],
    "sessions": {}
}

def init_server(
    k: int = 64,
    m: int = 1,
    b: int = 8,
    n_dim: int = 16,
    num_parties: int = 10,
    pool_size: int = 5
):
    print(f"[*] [CCS25 Server] Initializing: k={k}, m={m}, b={b}, n_dim={n_dim}, parties={num_parties}...")
    SERVER_STATE["k"] = k
    SERVER_STATE["m"] = m
    SERVER_STATE["b"] = b
    SERVER_STATE["n_dim"] = n_dim
    SERVER_STATE["num_parties"] = num_parties

    decryptor = ThresholdFHEDecryptor(k=k, m=m, b=b, num_parties=num_parties)
    lwe = ToyLWE(n_dim=n_dim, k=k, m=m, num_parties=num_parties)

    s_ext_stored = [decryptor.abb.store(val, k) for val in lwe.s] + [decryptor.abb.store(1, k)]

    SERVER_STATE["decryptor"] = decryptor
    SERVER_STATE["lwe"] = lwe
    SERVER_STATE["s_ext_stored"] = s_ext_stored
    SERVER_STATE["gates_pool"] = []

    print(f"[*] [CCS25 Server] Preprocessing {pool_size} gate sets offline...")
    t0 = time.time()
    for _ in range(pool_size):
        g = decryptor.preprocess()
        SERVER_STATE["gates_pool"].append(g)
    print(f"[✓] [CCS25 Server] Ready in {time.time() - t0:.3f}s for {pool_size} gate sets.")


def get_fresh_gate() -> PreprocessedGates:
    pool = SERVER_STATE["gates_pool"]
    if pool:
        return pool.pop(0)
    decryptor = SERVER_STATE["decryptor"]
    return decryptor.preprocess()


class ThresholdFHEServerHandler(BaseHTTPRequestHandler):
    def _send_response_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_response_json(200, {
                "status": "healthy",
                "service": "CCS25-Threshold-FHE-Decryption",
                "params": {
                    "k": SERVER_STATE["k"],
                    "m": SERVER_STATE["m"],
                    "b": SERVER_STATE["b"],
                    "n_dim": SERVER_STATE["n_dim"],
                    "num_parties": SERVER_STATE["num_parties"],
                    "available_gates": len(SERVER_STATE["gates_pool"])
                }
            })
        else:
            self._send_response_json(404, {"error": "Not Found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception as e:
            self._send_response_json(400, {"error": f"Invalid JSON: {str(e)}"})
            return

        endpoint = self.path

        if endpoint == "/setup":
            k = req.get("k", SERVER_STATE["k"])
            m = req.get("m", SERVER_STATE["m"])
            b = req.get("b", SERVER_STATE["b"])
            n_dim = req.get("n_dim", SERVER_STATE["n_dim"])
            num_parties = req.get("num_parties", SERVER_STATE["num_parties"])
            pool_size = req.get("pool_size", 3)
            t0 = time.perf_counter()
            init_server(k=k, m=m, b=b, n_dim=n_dim, num_parties=num_parties, pool_size=pool_size)
            setup_ms = (time.perf_counter() - t0) * 1000.0
            self._send_response_json(200, {
                "status": "setup complete",
                "k": k,
                "m": m,
                "b": b,
                "num_parties": num_parties,
                "setup_time_ms": round(setup_ms, 3)
            })

        elif endpoint == "/encrypt_demo":
            msg = req.get("message", 1)
            lwe: ToyLWE = SERVER_STATE["lwe"]
            c_ext, noise = lwe.encrypt(msg)
            c_str = encode_ciphertext(c_ext)
            self._send_response_json(200, {
                "message": msg,
                "ciphertext": c_str,
                "ciphertext_vec": c_ext,
                "noise": noise
            })

        elif endpoint == "/eval_add":
            if "ciphertext1" not in req or "ciphertext2" not in req:
                self._send_response_json(400, {"error": "Missing 'ciphertext1' or 'ciphertext2'"})
                return
            lwe: ToyLWE = SERVER_STATE["lwe"]
            c1 = decode_ciphertext(req["ciphertext1"]) if isinstance(req["ciphertext1"], str) else req["ciphertext1"]
            c2 = decode_ciphertext(req["ciphertext2"]) if isinstance(req["ciphertext2"], str) else req["ciphertext2"]
            t0 = time.perf_counter()
            c_add = lwe.eval_add(c1, c2)
            eval_ms = (time.perf_counter() - t0) * 1000.0
            self._send_response_json(200, {
                "status": "success",
                "operation": "eval_add",
                "ciphertext": encode_ciphertext(c_add),
                "ciphertext_vec": c_add,
                "eval_time_ms": round(eval_ms, 4)
            })

        elif endpoint == "/eval_mul":
            if "ciphertext1" not in req or "ciphertext2" not in req:
                self._send_response_json(400, {"error": "Missing 'ciphertext1' or 'ciphertext2'"})
                return
            lwe: ToyLWE = SERVER_STATE["lwe"]
            c1 = decode_ciphertext(req["ciphertext1"]) if isinstance(req["ciphertext1"], str) else req["ciphertext1"]
            c2 = decode_ciphertext(req["ciphertext2"]) if isinstance(req["ciphertext2"], str) else req["ciphertext2"]
            t0 = time.perf_counter()
            c_mul = lwe.eval_mul(c1, c2)
            eval_ms = (time.perf_counter() - t0) * 1000.0
            self._send_response_json(200, {
                "status": "success",
                "operation": "eval_mul",
                "ciphertext": encode_ciphertext(c_mul),
                "ciphertext_vec": c_mul,
                "eval_time_ms": round(eval_ms, 4)
            })

        elif endpoint == "/decrypt":
            if "ciphertext" not in req:
                self._send_response_json(400, {"error": "Missing 'ciphertext'"})
                return

            c_ext = decode_ciphertext(req["ciphertext"]) if isinstance(req["ciphertext"], str) else req["ciphertext"]
            decryptor: ThresholdFHEDecryptor = SERVER_STATE["decryptor"]
            s_ext = SERVER_STATE["s_ext_stored"]
            gates = get_fresh_gate()

            t_start = time.perf_counter()
            decryptor.abb.reset_metrics()
            recovered_msg = decryptor.decrypt(c_ext, s_ext, gates)
            latency_ms = (time.perf_counter() - t_start) * 1000.0

            self._send_response_json(200, {
                "status": "success",
                "decrypted_message": recovered_msg,
                "latency_ms": round(latency_ms, 3),
                "metrics": {
                    "num_opens": decryptor.abb.num_opens,
                    "opened_bits": decryptor.abb.opened_bits,
                    "num_mults": decryptor.abb.num_mults
                }
            })

        elif endpoint == "/decrypt_interactive/start":
            c_ext = decode_ciphertext(req["ciphertext"]) if isinstance(req["ciphertext"], str) else req["ciphertext"]
            decryptor = SERVER_STATE["decryptor"]
            s_ext = SERVER_STATE["s_ext_stored"]
            gates = get_fresh_gate()

            session_id = f"sess_{int(time.time() * 1000)}_{len(SERVER_STATE['sessions'])}"

            pairs = [(c_val, s_var) for c_val, s_var in zip(c_ext, s_ext)]
            shift = 1 << (decryptor.l - 1)
            z_k = decryptor.abb.lin_comb(shift, pairs, out_len=decryptor.k)

            z_plus_r = decryptor.abb.add(z_k, gates.r_combined, out_len=decryptor.l)
            z_prime = decryptor.abb.open(z_plus_r, truncated_l=decryptor.l)

            SERVER_STATE["sessions"][session_id] = {
                "z_k": z_k,
                "gates": gates,
                "z_prime": z_prime
            }

            self._send_response_json(200, {
                "session_id": session_id,
                "round": 1,
                "z_prime": z_prime,
                "l_bits": decryptor.l
            })

        elif endpoint == "/decrypt_interactive/step2":
            session_id = req.get("session_id")
            if session_id not in SERVER_STATE["sessions"]:
                self._send_response_json(400, {"error": "Invalid or expired session_id"})
                return

            sess = SERVER_STATE["sessions"][session_id]
            decryptor = SERVER_STATE["decryptor"]
            gates = sess["gates"]
            z_prime = sess["z_prime"]

            d = math.ceil(decryptor.l / decryptor.b)
            d_plus_1 = d + 1
            z_temp = z_prime
            z_digits = []
            for i in range(d):
                cur_b = decryptor.b if i < d - 1 else (decryptor.l - (d - 1) * decryptor.b)
                digit = z_temp & ((1 << cur_b) - 1)
                z_digits.append(digit)
                z_temp >>= cur_b

            y_shares = [gates.sign_gates[i][1][z_digits[i]] for i in range(d)]
            comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
            y_sum = decryptor.abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

            r_modltz, modltz_table = gates.modltz_gate
            y_masked = decryptor.abb.add(y_sum, r_modltz, out_len=d_plus_1)
            y_prime = decryptor.abb.open(y_masked, truncated_l=d_plus_1)

            u_k = modltz_table[y_prime]
            sess["u_k"] = u_k

            self._send_response_json(200, {
                "session_id": session_id,
                "round": 2,
                "y_prime": y_prime,
                "d_plus_1_bits": d_plus_1
            })

        elif endpoint == "/decrypt_interactive/finish":
            session_id = req.get("session_id")
            if session_id not in SERVER_STATE["sessions"]:
                self._send_response_json(400, {"error": "Invalid or expired session_id"})
                return

            sess = SERVER_STATE["sessions"].pop(session_id)
            decryptor = SERVER_STATE["decryptor"]
            gates = sess["gates"]
            z_k = sess["z_k"]
            z_prime = sess["z_prime"]
            u_k = sess["u_k"]

            e_k = decryptor.abb.lin_comb(z_prime, [(-1, gates.r_combined), (1 << decryptor.l, u_k)], out_len=decryptor.k)
            mu_scaled = decryptor.abb.sub(z_k, e_k, out_len=decryptor.k)
            mu_prime = decryptor.abb.open(mu_scaled, truncated_l=decryptor.k)
            mu = (mu_prime // decryptor.L) % decryptor.p

            self._send_response_json(200, {
                "round": 3,
                "status": "complete",
                "decrypted_message": mu
            })
        else:
            self._send_response_json(404, {"error": f"Endpoint {endpoint} not found"})


def run(host: str = "0.0.0.0", port: int = 8000, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16, num_parties: int = 10):
    init_server(k=k, m=m, b=b, n_dim=n_dim, num_parties=num_parties, pool_size=5)
    server_address = (host, port)
    httpd = HTTPServer(server_address, ThresholdFHEServerHandler)
    print(f"[*] [CCS25 Server] Listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down CCS25 server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCS 2025 Threshold FHE Decryption Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--k", type=int, default=64, help="Ciphertext modulus bit-length (default: 64)")
    parser.add_argument("--m", type=int, default=1, help="Plaintext modulus bit-length (default: 1)")
    parser.add_argument("--b", type=int, default=8, help="Digit base bit-length (default: 8)")
    parser.add_argument("--n-dim", type=int, default=16, help="LWE dimension (default: 16)")
    parser.add_argument("--parties", type=int, default=10, help="Number of parties (10..1000, default: 10)")
    args = parser.parse_args()

    run(host=args.host, port=args.port, k=args.k, m=args.m, b=args.b, n_dim=args.n_dim, num_parties=args.parties)
