#!/usr/bin/env python3
"""
================================================================================
HQ-FS: Server Module (Cloud Service Provider [CSP] & Data Receiver [DR])
Paper: "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic
        Quotient Proofs"
================================================================================
Responsibilities (Fig. 1 & Section III):
  - CSP:
      * Algorithm 1 (Setup): Initializes RNS basis Q={q_1..q_r}, auxiliary basis
        P={p_1..p_k}, baseline ZKP modulus K_Q=q_1, scaling factor Delta,
        global matrix A, and HQ-FS ZKP reference matrix A_zkp.
      * Algorithm 2 & 3 Aggregation: Aggregates public keys pk_global and
        relinearization keys RLK_global from DCN nodes.
      * Algorithm 7 (Addition): Homomorphic addition + Zero-Ciphertext Superposition
        to erase algebraic traces and ensure IND-FuncCPA / CPA^D security.
      * Algorithm 8 (Multiplication): Tensor product + RNS Digit Decomposition
        relinearization + Zero-Ciphertext Superposition.
  - DR:
      * Algorithm 6 (Decryption): Uses a Breadth-First Search (BFS) queue to
        batch-verify node partial decryptions and HQ-FS ZKP proofs modulo the
        small baseline prime K_Q = q_1 (checking b_dec, b_key, b_norm), drops
        malicious nodes, aggregates valid shares, reconstructs via CRT, and
        extracts plaintext slots via NTT.
================================================================================
"""

import os
import sys
import json
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

import importlib.util

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from tool import HQFSRNSGLWE
except ModuleNotFoundError:
    _spec = importlib.util.spec_from_file_location("hqfs_tool", os.path.join(CURRENT_DIR, "tool.py"))
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    HQFSRNSGLWE = _mod.HQFSRNSGLWE

SERVER_STATE: Dict[str, Any] = {
    "hqfs": None,
    "d": 16,
    "n_glwe": 2,
    "m_glwe": 2,
    "T_plain": 1024,
    "eta": 1,
    "B_flood": 64,
    "num_parties": 10,
    "setup_ms": 0.0,
    "keygen_ms": 0.0,
    "rlkgen_ms": 0.0,
    "submitted_shares": {},
    "submitted_proofs": {},
    "last_ciphertext": None
}


def init_server(
    d: int = 16,
    n_glwe: int = 2,
    m_glwe: int = 2,
    T_plain: int = 1024,
    eta: int = 1,
    B_flood: int = 64,
    num_parties: int = 10
):
    print(
        f"[*] [HQ-FS CSP/DR Server] Running Algorithm 1 (Setup): "
        f"d={d}, (m,n)=({m_glwe},{n_glwe}), T={T_plain}, B_flood={B_flood}, N={num_parties}..."
    )
    t0 = time.perf_counter()
    hqfs = HQFSRNSGLWE(
        d=d,
        n_glwe=n_glwe,
        m_glwe=m_glwe,
        T_plain=T_plain,
        eta=eta,
        B_flood=B_flood,
        num_parties=num_parties
    )
    setup_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    hqfs.keygen_and_commitment()
    keygen_ms = (time.perf_counter() - t1) * 1000.0

    t2 = time.perf_counter()
    hqfs.rlk_gen()
    rlkgen_ms = (time.perf_counter() - t2) * 1000.0

    SERVER_STATE["hqfs"] = hqfs
    SERVER_STATE["d"] = d
    SERVER_STATE["n_glwe"] = n_glwe
    SERVER_STATE["m_glwe"] = m_glwe
    SERVER_STATE["T_plain"] = T_plain
    SERVER_STATE["eta"] = eta
    SERVER_STATE["B_flood"] = B_flood
    SERVER_STATE["num_parties"] = num_parties
    SERVER_STATE["setup_ms"] = round(setup_ms, 3)
    SERVER_STATE["keygen_ms"] = round(keygen_ms, 3)
    SERVER_STATE["rlkgen_ms"] = round(rlkgen_ms, 3)
    SERVER_STATE["submitted_shares"] = {}
    SERVER_STATE["submitted_proofs"] = {}
    SERVER_STATE["last_ciphertext"] = None

    print(
        f"[✓] [HQ-FS Server] Ready | RNS Q={hqfs.rns.q_primes} (K_Q={hqfs.K_Q}) | "
        f"Setup={setup_ms:.2f}ms, KeyGen={keygen_ms:.2f}ms, RLKGen={rlkgen_ms:.2f}ms"
    )


class HQFSServerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        hqfs: HQFSRNSGLWE = SERVER_STATE["hqfs"]
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "service": "HQ-FS-RNS-GLWE-Server",
                "K_Q": hqfs.K_Q,
                "T": hqfs.T,
                "num_parties": hqfs.num_parties
            })
        elif self.path == "/params":
            self._send_json(200, {
                "d": hqfs.d,
                "n_glwe": hqfs.n_glwe,
                "m_glwe": hqfs.m_glwe,
                "T": hqfs.T,
                "p_ntt": hqfs.p_ntt,
                "eta": hqfs.eta,
                "B_flood": hqfs.B_flood,
                "num_parties": hqfs.num_parties,
                "q_primes": hqfs.rns.q_primes,
                "p_primes": hqfs.rns.p_primes,
                "K_Q": hqfs.K_Q,
                "setup_ms": SERVER_STATE["setup_ms"],
                "keygen_ms": SERVER_STATE["keygen_ms"],
                "rlkgen_ms": SERVER_STATE["rlkgen_ms"]
            })
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"})
            return

        hqfs: HQFSRNSGLWE = SERVER_STATE["hqfs"]
        endpoint = self.path

        if endpoint == "/encrypt":
            # Algorithm 4: Encryption (supports scalar or SIMD slot vector via iNTT)
            slots = req.get("slots")
            t0 = time.perf_counter()
            if isinstance(slots, list):
                ct = hqfs.encrypt_simd([int(x) for x in slots])
            else:
                msg = int(req.get("message", 12))
                ct = hqfs.encrypt(msg)
            enc_ms = (time.perf_counter() - t0) * 1000.0
            SERVER_STATE["last_ciphertext"] = ct
            self._send_json(200, {
                "status": "ok",
                "ciphertext": {"u": ct[0], "v": ct[1]},
                "enc_time_ms": round(enc_ms, 4)
            })

        elif endpoint == "/eval_add":
            # Algorithm 7: Addition with Zero-Ciphertext Superposition
            c1 = req.get("c1")
            c2 = req.get("c2")
            ct_alpha = (c1["u"], c1["v"])
            ct_beta = (c2["u"], c2["v"])
            t0 = time.perf_counter()
            ct_add = hqfs.eval_add(ct_alpha, ct_beta)
            add_ms = (time.perf_counter() - t0) * 1000.0
            SERVER_STATE["last_ciphertext"] = ct_add
            self._send_json(200, {
                "status": "ok",
                "operation": "Algorithm 7 (Addition + Zero-Ciphertext Superposition)",
                "ciphertext": {"u": ct_add[0], "v": ct_add[1]},
                "eval_time_ms": round(add_ms, 4)
            })

        elif endpoint == "/eval_mul":
            # Algorithm 8: Multiplication with RNS Digit Decomposition + Zero-Ciphertext Superposition
            c1 = req.get("c1")
            c2 = req.get("c2")
            ct_alpha = (c1["u"], c1["v"])
            ct_beta = (c2["u"], c2["v"])
            t0 = time.perf_counter()
            ct_mul = hqfs.eval_mul(ct_alpha, ct_beta)
            mul_ms = (time.perf_counter() - t0) * 1000.0
            SERVER_STATE["last_ciphertext"] = ct_mul
            self._send_json(200, {
                "status": "ok",
                "operation": "Algorithm 8 (Multiplication + RNS Gadget Relin + Zero-Ciphertext Superposition)",
                "ciphertext": {"u": ct_mul[0], "v": ct_mul[1]},
                "eval_time_ms": round(mul_ms, 4)
            })

        elif endpoint == "/decrypt_bfs":
            # Algorithm 5 & 6: Partial Decryption across N nodes + BFS Batch-Filtering Queue Decryption
            ct_obj = req.get("ciphertext")
            if ct_obj:
                ct = (ct_obj["u"], ct_obj["v"])
            elif SERVER_STATE["last_ciphertext"] is not None:
                ct = SERVER_STATE["last_ciphertext"]
            else:
                self._send_json(400, {"error": "No ciphertext provided"})
                return

            malicious_nodes: List[int] = [int(x) for x in req.get("malicious_nodes", [])]
            attack_type: str = req.get("attack_type", "share_tampering")
            slot_count: int = int(req.get("slot_count", 4))

            u_rns, _ = ct
            shares_map = {}
            proofs_map = {}

            t_pdec0 = time.perf_counter()
            for node_idx in range(hqfs.num_parties):
                atk = attack_type if node_idx in malicious_nodes else None
                sh_i, pi_i = hqfs.partial_decrypt_node(node_idx, u_rns, malicious_attack=atk)
                shares_map[node_idx] = sh_i
                proofs_map[node_idx] = pi_i
            pdec_ms = (time.perf_counter() - t_pdec0) * 1000.0

            t_bfs0 = time.perf_counter()
            m_vec, audit = hqfs.decrypt_with_bfs(ct, shares_map, proofs_map)
            bfs_dec_ms = (time.perf_counter() - t_bfs0) * 1000.0

            self._send_json(200, {
                "status": "ok",
                "decrypted_slots": m_vec[:slot_count],
                "decrypted_scalar": m_vec[0],
                "audit": audit,
                "timings": {
                    "partial_dec_and_prove_ms": round(pdec_ms, 3),
                    "per_node_prove_ms": round(pdec_ms / max(1, hqfs.num_parties), 4),
                    "bfs_verify_and_crt_dec_ms": round(bfs_dec_ms, 3)
                }
            })
        else:
            self._send_json(404, {"error": f"Unknown endpoint {endpoint}"})


def run(host: str = "0.0.0.0", port: int = 8002, d: int = 16, T_plain: int = 1024, num_parties: int = 10):
    init_server(d=d, T_plain=T_plain, num_parties=num_parties)
    httpd = HTTPServer((host, port), HQFSServerHandler)
    print(f"[*] [HQ-FS Server] Listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down HQ-FS Server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HQ-FS CSP & DR Server (Algorithms 1..8)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8002, help="Bind port (default: 8002)")
    parser.add_argument("--d", type=int, default=16, help="Polynomial ring degree d (default: 16)")
    parser.add_argument("--T", type=int, default=1024, help="Plaintext modulus T (default: 1024)")
    parser.add_argument("--parties", type=int, default=10, help="Number of DCN nodes N (default: 10)")
    args = parser.parse_args()

    run(host=args.host, port=args.port, d=args.d, T_plain=args.T, num_parties=args.parties)
