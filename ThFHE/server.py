#!/usr/bin/env python3
"""
================================================================================
Server Module: Cloud / Coordinator Server for Threshold FHE Decryption
Based on CCS 2025: "High-Throughput Universally Composable Threshold FHE Decryption"
================================================================================

Role:
  - Manages LWE secret keys stored in F_ABB
  - Generates and manages Preprocessed Gates (Sign & ModLTZ gates)
  - Coordinates both one-shot decryption and interactive 3-round MPC decryption
  - Provides a clean REST API without requiring external dependencies
"""

import os
import sys
import json
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

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
    "decryptor": None,
    "lwe": None,
    "s_ext_stored": None,
    "gates_pool": [],
    # Active interactive sessions: session_id -> state
    "sessions": {}
}

def init_server(k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16, pool_size: int = 5):
    """Initializes the server with parameters, secret key, and preprocessed gates."""
    print(f"[*] Initializing Server: k={k}, m={m}, b={b}, n_dim={n_dim}...")
    SERVER_STATE["k"] = k
    SERVER_STATE["m"] = m
    SERVER_STATE["b"] = b
    SERVER_STATE["n_dim"] = n_dim

    decryptor = ThresholdFHEDecryptor(k=k, m=m, b=b)
    lwe = ToyLWE(n_dim=n_dim, k=k, m=m)

    # Store secret key in F_ABB: s_ext = (s_0, ..., s_{n-1}, 1)
    s_ext_stored = [decryptor.abb.store(val, k) for val in lwe.s] + [decryptor.abb.store(1, k)]

    SERVER_STATE["decryptor"] = decryptor
    SERVER_STATE["lwe"] = lwe
    SERVER_STATE["s_ext_stored"] = s_ext_stored
    SERVER_STATE["gates_pool"] = []

    print(f"[*] Preprocessing {pool_size} gate sets offline...")
    t0 = time.time()
    for i in range(pool_size):
        g = decryptor.preprocess()
        SERVER_STATE["gates_pool"].append(g)
    print(f"[✓] Server Ready. Offline Preprocessing took {time.time() - t0:.3f}s for {pool_size} gate sets.")


def get_fresh_gate() -> PreprocessedGates:
    """Retrieves a preprocessed gate set, generating one on-the-fly if pool is empty."""
    pool = SERVER_STATE["gates_pool"]
    if pool:
        return pool.pop(0)
    # Generate on-demand
    decryptor = SERVER_STATE["decryptor"]
    return decryptor.preprocess()


class ThresholdFHEServerHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Threshold FHE Decryption Server."""

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
                "service": "Threshold-FHE-CCS25",
                "params": {
                    "k": SERVER_STATE["k"],
                    "m": SERVER_STATE["m"],
                    "b": SERVER_STATE["b"],
                    "n_dim": SERVER_STATE["n_dim"],
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

        # -------------------------------------------------------------
        # Endpoint: /setup
        # -------------------------------------------------------------
        if endpoint == "/setup":
            k = req.get("k", SERVER_STATE["k"])
            m = req.get("m", SERVER_STATE["m"])
            b = req.get("b", SERVER_STATE["b"])
            n_dim = req.get("n_dim", SERVER_STATE["n_dim"])
            pool_size = req.get("pool_size", 3)
            init_server(k=k, m=m, b=b, n_dim=n_dim, pool_size=pool_size)
            self._send_response_json(200, {"status": "setup complete", "k": k, "m": m, "b": b})

        # -------------------------------------------------------------
        # Endpoint: /encrypt_demo
        # Helper endpoint: encrypts a message on server to aid testing
        # -------------------------------------------------------------
        elif endpoint == "/encrypt_demo":
            msg = req.get("message", 1)
            lwe = SERVER_STATE["lwe"]
            c_ext, noise = lwe.encrypt(msg)
            c_str = encode_ciphertext(c_ext)
            self._send_response_json(200, {
                "message": msg,
                "ciphertext": c_str,
                "noise": noise
            })

        # -------------------------------------------------------------
        # Endpoint: /decrypt (One-Shot End-to-End Decryption)
        # -------------------------------------------------------------
        elif endpoint == "/decrypt":
            if "ciphertext" not in req:
                self._send_response_json(400, {"error": "Missing 'ciphertext'"})
                return

            c_ext = decode_ciphertext(req["ciphertext"])
            decryptor = SERVER_STATE["decryptor"]
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

        # -------------------------------------------------------------
        # Endpoint: /decrypt_interactive/start (Interactive MPC Round 1)
        # Step 1: Open [z]_l + [r]_l -> z'
        # -------------------------------------------------------------
        elif endpoint == "/decrypt_interactive/start":
            c_ext = decode_ciphertext(req["ciphertext"])
            decryptor = SERVER_STATE["decryptor"]
            s_ext = SERVER_STATE["s_ext_stored"]
            gates = get_fresh_gate()

            session_id = f"sess_{int(time.time() * 1000)}_{len(SERVER_STATE['sessions'])}"

            # Step 1: Compute [z]_k = <c, s> + 2^{l-1}
            pairs = [(c_val, s_var) for c_val, s_var in zip(c_ext, s_ext)]
            shift = 1 << (decryptor.l - 1)
            z_k = decryptor.abb.lin_comb(shift, pairs, out_len=decryptor.k)

            # Open [z]_l + [r]_l -> z'
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

        # -------------------------------------------------------------
        # Endpoint: /decrypt_interactive/step2 (Interactive MPC Round 2)
        # Step 2: Open [y]_{d+1} + [r_modltz]_{d+1} -> y'
        # -------------------------------------------------------------
        elif endpoint == "/decrypt_interactive/step2":
            session_id = req.get("session_id")
            if session_id not in SERVER_STATE["sessions"]:
                self._send_response_json(400, {"error": "Invalid or expired session_id"})
                return

            sess = SERVER_STATE["sessions"][session_id]
            decryptor = SERVER_STATE["decryptor"]
            gates = sess["gates"]
            z_prime = sess["z_prime"]

            # Base B decomposition
            d = math.ceil(decryptor.l / decryptor.b)
            d_plus_1 = d + 1
            z_temp = z_prime
            z_digits = []
            for i in range(d):
                cur_b = decryptor.b if i < d - 1 else (decryptor.l - (d - 1) * decryptor.b)
                digit = z_temp & ((1 << cur_b) - 1)
                z_digits.append(digit)
                z_temp >>= cur_b

            # Lookup Sign gates
            y_shares = [gates.sign_gates[i][1][z_digits[i]] for i in range(d)]
            comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
            y_sum = decryptor.abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

            # Masked open for ModLTZ
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

        # -------------------------------------------------------------
        # Endpoint: /decrypt_interactive/finish (Interactive MPC Round 3)
        # Step 3: [z]_k - [e]_k = [L * mu]_k -> Open -> mu
        # -------------------------------------------------------------
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

            # [e]_k = z' - [r]_k + 2^l * [u]_k
            e_k = decryptor.abb.lin_comb(z_prime, [(-1, gates.r_combined), (1 << decryptor.l, u_k)], out_len=decryptor.k)

            # [z]_k - [e]_k
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


def run(host: str = "0.0.0.0", port: int = 8000, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16):
    init_server(k=k, m=m, b=b, n_dim=n_dim, pool_size=5)
    server_address = (host, port)
    httpd = HTTPServer(server_address, ThresholdFHEServerHandler)
    print(f"[*] Threshold FHE Decryption Server listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCS 2025 Threshold FHE Decryption Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--k", type=int, default=64, help="Ciphertext modulus bit-length (default: 64)")
    parser.add_argument("--m", type=int, default=1, help="Plaintext modulus bit-length (default: 1)")
    parser.add_argument("--b", type=int, default=8, help="Digit base bit-length (default: 8)")
    parser.add_argument("--n-dim", type=int, default=16, help="LWE dimension (default: 16)")
    args = parser.parse_args()

    run(host=args.host, port=args.port, k=args.k, m=args.m, b=args.b, n_dim=args.n_dim)
