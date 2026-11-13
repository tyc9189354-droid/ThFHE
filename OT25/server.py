#!/usr/bin/env python3
"""
================================================================================
OT25: Server Module (Untrusted / Semi-Honest Server & Aggregator)
Paper: "Low Communication Threshold FHE from Standard (Module-)LWE"
       (Hiroki Okada & Tsuyoshi Takagi, Asiacrypt 2025)
================================================================================
Implements:
  - Algorithm 3 / Algorithm 6: ServerDec ("Flood-and-Round")
  - Sanitization of ciphertext with Gaussian flooding noise E ~ D_{1/2 Z, \sigma_flood}
  - Randomized Gaussian rounding from large modulus Q to small modulus q
  - Mask addition sum_{i in act} m_i mod q (where m_i = PRF(seed_i, sid))
  - FinDec: Reconstructs plaintext from partial decryption shares
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

from tool import OT25ThFHE

SERVER_STATE = {
    "ot25": None,
    "current_ct_dec": None,
    "active_parties": [],
    "current_sid": 0,
    "received_pd_shares": {},
    "status": "idle"
}

def init_server(n_dim: int = 16, q: int = 65537, p: int = 16, num_parties: int = 10, threshold: int = 6):
    ot25 = OT25ThFHE(n_dim=n_dim, q=q, p=p, num_parties=num_parties, threshold=threshold)
    ot25.setup()
    ot25.keygen()
    SERVER_STATE["ot25"] = ot25
    SERVER_STATE["active_parties"] = list(range(1, threshold + 1))
    print(f"[*] [OT25 Server] Initialized: n={n_dim}, q={q}, p={p}, Q={ot25.Q}, Parties={num_parties}, T={threshold}")
    return ot25

class OT25HTTPHandler(BaseHTTPRequestHandler):
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
        ot25: OT25ThFHE = SERVER_STATE["ot25"]
        if ot25 is None and path != "/api/setup":
            ot25 = init_server()

        if path == "/api/setup":
            n_dim = int(req.get("n_dim", 16))
            q = int(req.get("q", 65537))
            p = int(req.get("p", 16))
            num_parties = int(req.get("num_parties", 10))
            threshold = int(req.get("threshold", 6))
            ot = init_server(n_dim=n_dim, q=q, p=p, num_parties=num_parties, threshold=threshold)
            self._send_json(200, {
                "status": "ok",
                "message": "OT25 Server initialized",
                "params": {
                    "n_dim": ot.n_dim,
                    "q": ot.q,
                    "p": ot.p,
                    "Q": ot.Q,
                    "num_parties": ot.num_parties,
                    "threshold": ot.threshold,
                    "B_pub": ot.B_pub
                }
            })

        elif path == "/api/server_dec":
            # Execute ServerDec on ciphertext
            msg = int(req.get("msg", 1))
            ct = ot25.encrypt(msg)
            active_parties = req.get("active_parties", SERVER_STATE["active_parties"])
            SERVER_STATE["active_parties"] = active_parties
            SERVER_STATE["received_pd_shares"] = {}

            t0 = time.perf_counter()
            a_bar, b_bar, sid = ot25.server_dec(ct, active_parties)
            server_dec_ms = (time.perf_counter() - t0) * 1000.0

            SERVER_STATE["current_ct_dec"] = (a_bar, b_bar)
            SERVER_STATE["current_sid"] = sid

            self._send_json(200, {
                "status": "ok",
                "sid": sid,
                "a_bar": a_bar.tolist(),
                "b_bar": int(b_bar),
                "server_dec_ms": round(server_dec_ms, 3),
                "active_parties": active_parties,
                "expected_msg": msg
            })

        elif path == "/api/submit_share":
            party_id = int(req.get("party_id", 1))
            pd_share = int(req.get("pd_share", 0))
            SERVER_STATE["received_pd_shares"][party_id] = pd_share
            received_count = len(SERVER_STATE["received_pd_shares"])
            req_count = len(SERVER_STATE["active_parties"])

            self._send_json(200, {
                "status": "ok",
                "party_id": party_id,
                "received_count": received_count,
                "required_count": req_count,
                "ready_to_reconstruct": (received_count >= req_count)
            })

        elif path == "/api/fin_dec":
            # Reconstruct plaintext
            active_parties = SERVER_STATE["active_parties"]
            received = SERVER_STATE["received_pd_shares"]
            if len(received) < len(active_parties):
                # Auto fill remaining from local simulation for testing
                a_bar, b_bar = SERVER_STATE["current_ct_dec"]
                sid = SERVER_STATE["current_sid"]
                for p_id in active_parties:
                    if p_id not in received:
                        received[p_id] = ot25.part_dec(p_id, a_bar, active_parties, sid)

            a_bar, b_bar = SERVER_STATE["current_ct_dec"]
            pd_list = [received[p_id] for p_id in active_parties]

            t0 = time.perf_counter()
            dec_msg = ot25.fin_dec(b_bar, pd_list)
            fin_dec_ms = (time.perf_counter() - t0) * 1000.0

            self._send_json(200, {
                "status": "ok",
                "decrypted_msg": dec_msg,
                "fin_dec_ms": round(fin_dec_ms, 3),
                "shares_used": len(pd_list)
            })

        else:
            self._send_json(404, {"error": f"Unknown endpoint: {path}"})

def run_server(port: int = 8003):
    init_server()
    server_address = ("0.0.0.0", port)
    httpd = HTTPServer(server_address, OT25HTTPHandler)
    print(f"[*] OT25 Standalone Server listening on http://0.0.0.0:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping OT25 server...")
        httpd.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8003, help="Port to listen on")
    args = parser.parse_args()
    run_server(args.port)
