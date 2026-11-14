#!/usr/bin/env python3
"""
================================================================================
PS24: Server Module (evaluator, ServerDec, FinDec)
Paper: "Low Communication Threshold Fully Homomorphic Encryption"
       (Alain Passelegue & Damien Stehle, ePrint 2024/1984)
================================================================================
Implements the trusted-server side of the Double-Flood-and-Round construction:
  - ServerDec : ct_in = ct + Enc(0);  E <- D_sigma_flood;  rescale Z_Q -> Z_qdec by randomised Gaussian rounding
                (exponential flooding is confined to the server; only the SMALL ct_dec is sent to the parties)
  - FinDec    : z = sum_i p_i + ct_dec,1 mod q_dec ; mu = Decode(z)
================================================================================
"""

import os
import sys
import json
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import PS24ThFHE

SERVER_STATE: Dict[str, Any] = {"ps24": None, "ct_dec": None, "expected_msg": 0, "p_shares": {}}


def init_server(n_dim: int = 16, p: int = 4, num_parties: int = 10) -> PS24ThFHE:
    ps24 = PS24ThFHE(n_dim=n_dim, p=p, num_parties=num_parties)
    ps24.setup()
    ps24.keygen()
    SERVER_STATE["ps24"] = ps24
    print(f"[*] [PS24 Server] N={ps24.num_parties}, Q={ps24.Q} ({ps24.Q.bit_length()} bits), "
          f"q_dec={ps24.q_dec} ({ps24.q_dec.bit_length()} bits), sigma_flood={ps24.sigma_flood:.3e}, eta={ps24.eta}")
    return ps24


class PS24HTTPHandler(BaseHTTPRequestHandler):
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
        ps24: PS24ThFHE = SERVER_STATE["ps24"]
        if ps24 is None and path != "/api/setup":
            ps24 = init_server()

        if path == "/api/setup":
            s = init_server(int(req.get("n_dim", 16)), int(req.get("p", 4)), int(req.get("num_parties", 10)))
            self._send_json(200, {"status": "ok", "message": "PS24 Server initialized", "params": s.setup()})

        elif path == "/api/start_dec":
            msg = int(req.get("msg", 2)) % ps24.p_plain
            ct = ps24.encrypt(msg)
            a_dec, b_dec = ps24.server_dec(ct)                    # ServerDec
            SERVER_STATE.update(ct_dec=(a_dec, b_dec), expected_msg=msg, p_shares={})
            self._send_json(200, {
                "status": "ok", "ct_dec_a": [int(x) for x in a_dec], "ct_dec_b": int(b_dec),
                "expected_msg": msg, "q_dec": ps24.q_dec, "num_parties": ps24.num_parties, "p": ps24.p_plain,
            })

        elif path == "/api/submit_partial":
            pid = int(req.get("party_id", 1))
            SERVER_STATE["p_shares"][pid] = int(req.get("p_i", 0))
            dec, done = None, False
            if len(SERVER_STATE["p_shares"]) >= ps24.num_parties:
                dec = ps24.fin_dec(SERVER_STATE["ct_dec"][1], [SERVER_STATE["p_shares"][i] for i in sorted(SERVER_STATE["p_shares"])])
                done = True
            self._send_json(200, {
                "status": "ok", "received_count": len(SERVER_STATE["p_shares"]), "needed": ps24.num_parties,
                "decrypted_msg": dec, "expected_msg": SERVER_STATE["expected_msg"],
                "verified": (dec == SERVER_STATE["expected_msg"]) if done else False,
            })
        else:
            self._send_json(404, {"error": f"Unknown endpoint: {path}"})


def run_server(port: int = 8007):
    init_server()
    httpd = HTTPServer(("0.0.0.0", port), PS24HTTPHandler)
    print(f"[*] PS24 Standalone Server listening on http://0.0.0.0:{port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping PS24 server...")
        httpd.server_close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8007, help="Port to listen on")
    run_server(ap.parse_args().port)
