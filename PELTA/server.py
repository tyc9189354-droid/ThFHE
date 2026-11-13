#!/usr/bin/env python3
"""
================================================================================
PELTA: Server Module (Aggregator, Verifier, and RLWE Homomorphic Evaluator)
Paper: "PELTA - Shielding Multiparty-FHE against Malicious Adversaries"
================================================================================
"""

import os
import sys
import json
import time
import random
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

# Add paths to locate tool.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import (
    PolyRing,
    PeltaVerifier,
    PeltaProof,
    VerifiableAggregation,
    PeltaMFHE,
    hash_commitment
)

SERVER_STATE = {
    "N": 64,
    "q": 12289,
    "B": 16,
    "num_parties": 10,
    "ring": None,
    "verifier": None,
    "mfhe": None,
    "crs_a": None,
    "alpha": 42,
    "received_submissions": {},
    "aggregated_poly": None,
    "aggregation_verified": False
}

def init_server(N: int = 64, q: int = 12289, B: int = 16, num_parties: int = 10):
    print(f"[*] [PELTA Server] Initializing: N={N}, q={q}, NoiseBound={B}, Parties={num_parties}...")
    ring = PolyRing(N=N, q=q)
    verifier = PeltaVerifier(ring, B_noise_bound=B)
    crs_a = ring.sample_uniform()
    alpha = random.randint(1, q - 1)

    mfhe = PeltaMFHE(N=min(N, 32), q=65536, p=2, B=4, num_parties=num_parties)
    mfhe.keygen()

    SERVER_STATE["N"] = N
    SERVER_STATE["q"] = q
    SERVER_STATE["B"] = B
    SERVER_STATE["num_parties"] = num_parties
    SERVER_STATE["ring"] = ring
    SERVER_STATE["verifier"] = verifier
    SERVER_STATE["mfhe"] = mfhe
    SERVER_STATE["crs_a"] = crs_a
    SERVER_STATE["alpha"] = alpha
    SERVER_STATE["received_submissions"] = {}
    SERVER_STATE["aggregated_poly"] = None
    SERVER_STATE["aggregation_verified"] = False
    print(f"[✓] [PELTA Server] Ready. CRS 'a' and RLWE RelinKey generated.")


class PeltaServerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "PELTA-MFHE-Shield"})
        elif self.path == "/params":
            self._send_json(200, {
                "N": SERVER_STATE["N"],
                "q": SERVER_STATE["q"],
                "B": SERVER_STATE["B"],
                "num_parties": SERVER_STATE["num_parties"],
                "crs_a": SERVER_STATE["crs_a"],
                "alpha": SERVER_STATE["alpha"]
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {str(e)}"})
            return

        endpoint = self.path

        if endpoint == "/submit":
            party_id = req.get("party_id")
            share_poly = req.get("share")
            proof_dict = req.get("proof")
            h_commit = req.get("h_commit")

            if not party_id or share_poly is None or not proof_dict:
                self._send_json(400, {"error": "Missing party_id, share, or proof"})
                return

            if h_commit:
                expected_hash = hash_commitment(share_poly)
                if expected_hash != h_commit:
                    self._send_json(400, {
                        "status": "rejected",
                        "reason": f"Hash commitment mismatch for party {party_id}!"
                    })
                    return

            proof = PeltaProof.from_dict(proof_dict)
            verifier: PeltaVerifier = SERVER_STATE["verifier"]
            crs_a = SERVER_STATE["crs_a"]
            alpha = SERVER_STATE["alpha"]

            is_valid = verifier.verify_share(a_public=crs_a, b_share=share_poly, proof=proof, alpha_eval=alpha)

            if not is_valid:
                print(f"[!] [PELTA Server] MALICIOUS ACTIVITY DETECTED from party '{party_id}'! Proof invalid.")
                self._send_json(403, {
                    "status": "rejected",
                    "party_id": party_id,
                    "reason": "Invalid Zero-Knowledge Proof: Malicious share or improper key/noise bounds detected!"
                })
                return

            print(f"[✓] [PELTA Server] Verified share and proof from party '{party_id}'.")
            SERVER_STATE["received_submissions"][party_id] = {
                "share": share_poly,
                "proof": proof
            }

            self._send_json(200, {
                "status": "accepted",
                "party_id": party_id,
                "message": "Proof verified successfully."
            })

        elif endpoint == "/aggregate":
            subs = SERVER_STATE["received_submissions"]
            if not subs:
                self._send_json(400, {"error": "No verified submissions available to aggregate."})
                return

            ring: PolyRing = SERVER_STATE["ring"]
            alpha = SERVER_STATE["alpha"]

            shares_list = [entry["share"] for entry in subs.values()]
            agg_poly = VerifiableAggregation.aggregate(ring, shares_list)

            evals_list = [entry["proof"].eval_proof for entry in subs.values()]
            agg_eval = ring.eval(agg_poly, alpha)
            is_agg_verified = VerifiableAggregation.verify_sum_at_alpha(evals_list, agg_eval, ring.q)

            SERVER_STATE["aggregated_poly"] = agg_poly
            SERVER_STATE["aggregation_verified"] = is_agg_verified

            self._send_json(200, {
                "status": "success",
                "participating_parties": list(subs.keys()),
                "aggregated_poly": agg_poly,
                "verifiable_aggregation_passed": is_agg_verified,
                "alpha_challenge": alpha,
                "aggregated_evaluation_at_alpha": agg_eval
            })

        elif endpoint == "/eval_mul":
            mfhe: PeltaMFHE = SERVER_STATE["mfhe"]
            m1 = int(req.get("m1", 1))
            m2 = int(req.get("m2", 1))
            ct1 = mfhe.encrypt(m1)
            ct2 = mfhe.encrypt(m2)
            t0 = time.perf_counter()
            ct_mul = mfhe.eval_mul(ct1, ct2)
            eval_ms = (time.perf_counter() - t0) * 1000.0
            dec = mfhe.decrypt(ct_mul)
            self._send_json(200, {
                "status": "success",
                "m1": m1,
                "m2": m2,
                "decrypted": dec,
                "eval_time_ms": round(eval_ms, 4)
            })
        else:
            self._send_json(404, {"error": f"Endpoint {endpoint} not found"})


def run(host: str = "0.0.0.0", port: int = 8001, N: int = 64, q: int = 12289, B: int = 16, num_parties: int = 10):
    init_server(N=N, q=q, B=B, num_parties=num_parties)
    server_address = (host, port)
    httpd = HTTPServer(server_address, PeltaServerHandler)
    print(f"[*] [PELTA Server] Listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down PELTA server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PELTA Aggregator and Verifier Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address")
    parser.add_argument("--port", type=int, default=8001, help="Port (default: 8001)")
    parser.add_argument("--N", type=int, default=64, help="Ring polynomial degree (default: 64)")
    parser.add_argument("--q", type=int, default=12289, help="Ring modulus (default: 12289)")
    parser.add_argument("--B", type=int, default=16, help="Noise infinity norm bound (default: 16)")
    parser.add_argument("--parties", type=int, default=10, help="Number of parties (10..1000, default: 10)")
    args = parser.parse_args()

    run(host=args.host, port=args.port, N=args.N, q=args.q, B=args.B, num_parties=args.parties)
