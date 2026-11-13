#!/usr/bin/env python3
"""
================================================================================
Ajax: Server Module (Coordinator & Plaintext Receiver P_R)
Paper: "Ajax: Fast Threshold Fully Homomorphic Encryption without Noise Flooding"
       (Hu et al., USENIX Security 2025)
================================================================================
Implements:
  - Coordination of Two-Round Online Decryption ("Mask-Then-Open"):
    * Round 1: Aggregates <v>_\Phi shares and broadcasts reconstructed v_open mod \Phi
    * Round 2: Aggregates <\Phi * m>_\eta shares and decodes plaintext m in Z_p
  - Zero Noise Flooding: small modulus, low latency, and zero smudging overhead
================================================================================
"""

import os
import sys
import json
import time
import random
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import AjaxThFHE

SERVER_STATE = {
    "ajax": None,
    "current_ct": None,
    "expected_msg": 0,
    "active_parties": [],
    "round1_v_shares": {},
    "v_open": None,
    "round2_phi_m_shares": {},
    "status": "idle"
}

def init_server(n_dim: int = 16, q: Optional[int] = None, p: int = 4, num_parties: int = 10, threshold: Optional[int] = None):
    t_plus_1 = threshold if threshold is not None else min(num_parties, ((num_parties - 1) // 2) + 1)
    ajax = AjaxThFHE(n_dim=n_dim, q=q, p=p, num_parties=num_parties, threshold=t_plus_1)
    ajax.setup()
    ajax.keygen()
    SERVER_STATE["ajax"] = ajax
    SERVER_STATE["active_parties"] = list(range(t_plus_1))
    print(f"[*] [Ajax Server] Initialized: n={n_dim}, q={ajax.q}, p={p}, Delta={ajax.Delta}, eta={ajax.eta}, Phi={ajax.Phi}, Parties={num_parties}, T={t_plus_1}")
    return ajax

class AjaxHTTPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: Dict[str, Any]):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self._send_json(200, {"status": "ok"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            req = json.loads(raw_body)
        except Exception:
            req = {}

        path = self.path.split("?")[0]
        ajax: AjaxThFHE = SERVER_STATE["ajax"]
        if ajax is None and path != "/api/setup":
            ajax = init_server()

        if path == "/api/setup":
            n_dim = int(req.get("n_dim", 16))
            q_val = req.get("q")
            q = int(q_val) if q_val is not None else None
            p = int(req.get("p", 4))
            num_parties = int(req.get("num_parties", 10))
            thresh_val = req.get("threshold")
            threshold = int(thresh_val) if thresh_val is not None else None
            aj = init_server(n_dim=n_dim, q=q, p=p, num_parties=num_parties, threshold=threshold)
            self._send_json(200, {
                "status": "ok",
                "message": "Ajax Server initialized",
                "params": aj.setup()
            })

        elif path == "/api/start_dec":
            msg = int(req.get("msg", 2))
            ct = ajax.encrypt(msg)
            SERVER_STATE["current_ct"] = ct
            SERVER_STATE["expected_msg"] = msg
            SERVER_STATE["round1_v_shares"] = {}
            SERVER_STATE["round2_phi_m_shares"] = {}
            SERVER_STATE["v_open"] = None

            self._send_json(200, {
                "status": "ok",
                "ct_a": ct[0].tolist(),
                "ct_b": int(ct[1]),
                "expected_msg": msg,
                "threshold": ajax.threshold,
                "q": ajax.q,
                "p": ajax.p,
                "Phi": ajax.Phi,
                "eta": ajax.eta
            })

        elif path == "/api/round1_open":
            party_id = int(req.get("party_id", 0))
            v_share = int(req.get("v_share", 0))
            SERVER_STATE["round1_v_shares"][party_id] = v_share

            # If all submitted, reconstruct v
            if len(SERVER_STATE["round1_v_shares"]) >= ajax.threshold:
                v_sum = sum(SERVER_STATE["round1_v_shares"][i] for i in range(ajax.threshold)) % ajax.Phi
                SERVER_STATE["v_open"] = v_sum

            self._send_json(200, {
                "status": "ok",
                "received_count": len(SERVER_STATE["round1_v_shares"]),
                "threshold": ajax.threshold,
                "v_open": SERVER_STATE["v_open"]
            })

        elif path == "/api/round2_dec":
            party_id = int(req.get("party_id", 0))
            phi_m_share = int(req.get("phi_m_share", 0))
            SERVER_STATE["round2_phi_m_shares"][party_id] = phi_m_share

            dec_msg = None
            if len(SERVER_STATE["round2_phi_m_shares"]) >= ajax.threshold:
                t0 = time.perf_counter()
                tot = sum(SERVER_STATE["round2_phi_m_shares"][i] for i in range(ajax.threshold)) % ajax.eta
                dec_msg = int(round(tot / ajax.Phi)) % ajax.p
                dec_ms = (time.perf_counter() - t0) * 1000.0
            else:
                dec_ms = 0.0

            self._send_json(200, {
                "status": "ok",
                "received_count": len(SERVER_STATE["round2_phi_m_shares"]),
                "threshold": ajax.threshold,
                "decrypted_msg": dec_msg,
                "expected_msg": SERVER_STATE["expected_msg"],
                "verified": (dec_msg == SERVER_STATE["expected_msg"]) if dec_msg is not None else False
            })

        else:
            self._send_json(404, {"error": f"Unknown endpoint: {path}"})

def run_server(port: int = 8004):
    init_server()
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, AjaxHTTPHandler)
    print(f"[*] Ajax Standalone Server listening on http://0.0.0.0:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Ajax server...")
        httpd.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8004, help="Port to listen on")
    args = parser.parse_args()
    run_server(args.port)
