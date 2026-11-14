#!/usr/bin/env python3
"""
================================================================================
BS23: Server Module (Coordinator / Combiner)
Paper: "Simple Threshold (Fully Homomorphic) Encryption From LWE With Polynomial Modulus"
       (Katharina Boudgoust & Peter Scholl, ASIACRYPT 2023)
================================================================================
Implements:
  - Setup / KeyGen : LWE-BFV key pair + LSS.Share(sk) (replicated or additive, {0,1}-reconstruction)
  - Combine        : picks ONE provider per sub-secret from the partial decryptions d_{i,j}
                     y = sum d_{i,j},  mu = round(p/q * (b + y))
  - Single non-interactive decryption round, polynomial modulus, no exponential noise flooding
================================================================================
"""

import os
import sys
import json
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import BS23ThFHE

SERVER_STATE: Dict[str, Any] = {"bs23": None, "current_ct": None, "expected_msg": 0, "d_shares": {}}


def init_server(n_dim: int = 16, p: int = 4, num_parties: int = 10, threshold: Optional[int] = None) -> BS23ThFHE:
    bs23 = BS23ThFHE(n_dim=n_dim, p=p, num_parties=num_parties, threshold=threshold)
    bs23.setup()
    bs23.keygen()
    SERVER_STATE["bs23"] = bs23
    print(f"[*] [BS23 Server] n={bs23.n_eff}, t={bs23.t_eff}, q={bs23.q} ({bs23.q.bit_length()} bits), "
          f"sigma_flood={bs23.sigma_flood}, L={bs23.L}, tau_min={bs23.tau_min}, sharing={bs23.sharing}")
    return bs23


class BS23HTTPHandler(BaseHTTPRequestHandler):
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
        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n).decode("utf-8")) if n > 0 else {}
        except Exception:
            req = {}
        path = self.path.split("?")[0]
        bs23: BS23ThFHE = SERVER_STATE["bs23"]
        if bs23 is None and path != "/api/setup":
            bs23 = init_server()

        if path == "/api/setup":
            th = req.get("threshold")
            b = init_server(int(req.get("n_dim", 16)), int(req.get("p", 4)), int(req.get("num_parties", 10)),
                            int(th) if th is not None else None)
            self._send_json(200, {"status": "ok", "message": "BS23 Server initialized", "params": b.setup()})

        elif path == "/api/start_dec":
            msg = int(req.get("msg", 2)) % bs23.p
            ct = bs23.encrypt(msg)
            SERVER_STATE.update(current_ct=ct, expected_msg=msg, d_shares={})
            self._send_json(200, {
                "status": "ok", "ct_a": [int(x) for x in ct[0]], "ct_b": int(ct[1]), "expected_msg": msg,
                "threshold": bs23.threshold, "q": bs23.q, "p": bs23.p, "L": bs23.L,
                "active_parties": list(range(1, bs23.threshold + 1)),
            })

        elif path == "/api/submit_partial":
            pid = int(req.get("party_id", 1))
            SERVER_STATE["d_shares"][pid] = [int(x) for x in req.get("d", [])]
            dec, done = None, False
            active = list(range(1, bs23.threshold + 1))
            if all(i in SERVER_STATE["d_shares"] for i in active):
                if bs23._share_pos_stamp is not bs23.shares:
                    bs23._build_pos_index()
                    bs23._share_pos_stamp = bs23.shares
                dec, _, _ = bs23.combine(SERVER_STATE["current_ct"], SERVER_STATE["d_shares"], active)
                done = True
            self._send_json(200, {
                "status": "ok", "received_count": len(SERVER_STATE["d_shares"]), "threshold": bs23.threshold,
                "decrypted_msg": dec, "expected_msg": SERVER_STATE["expected_msg"],
                "verified": (dec == SERVER_STATE["expected_msg"]) if done else False,
            })
        else:
            self._send_json(404, {"error": f"Unknown endpoint: {path}"})


def run_server(port: int = 8006):
    init_server()
    httpd = HTTPServer(("0.0.0.0", port), BS23HTTPHandler)
    print(f"[*] BS23 Standalone Server listening on http://0.0.0.0:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping BS23 server...")
        httpd.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8006, help="Port to listen on")
    run_server(ap.parse_args().port)
