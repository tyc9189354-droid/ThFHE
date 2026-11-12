#!/usr/bin/env python3
"""
================================================================================
ThFHE Lab Web Server & Real-Time Cryptographic Benchmark API
================================================================================
Hosts `index.html` and provides live REST endpoints backed by `tool.py`,
`CCS25`, `PELTA`, and `BenchmarkRunner`:
  - POST /api/setup               : Setup & KeyGen for N parties (10 <= N <= 1000)
  - POST /api/encrypt             : Encrypt plaintext into LWE ciphertext
  - POST /api/evaluate_and_decrypt: Execute Homo Add / Homo Mul + 3-Round MPC Decrypt
  - POST /api/benchmark           : Run real multi-scheme benchmark (CCS25, Noah's Ark, PELTA)
  - POST /api/pelta_verify        : Run real PELTA ZK verification & RLWE Homo Mul
================================================================================
"""

import os
import sys
import json
import time
import random
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any, List

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
THFHE_DIR = os.path.dirname(WEB_DIR)
if THFHE_DIR not in sys.path:
    sys.path.insert(0, THFHE_DIR)

from tool import (
    PolyRing,
    PeltaProver,
    PeltaVerifier,
    VerifiableAggregation,
    PeltaMFHE
)
from schemes.ccs25_scheme import CCS25ThFHEScheme
from schemes.baseline_noise_flooding import BaselineNoiseFloodingScheme
from schemes.pelta_scheme import PeltaThFHEScheme
from runner.benchmark_runner import BenchmarkRunner

PORT = 3000

LIVE_LAB = {
    "scheme": None,
    "k": 32,
    "m": 4,        # Plaintext space Z_{16} (0..15)
    "b": 4,
    "n_dim": 8,
    "num_parties": 10,
    "setup_time_ms": 0.0,
    "keygen_time_ms": 0.0,
    "prep_time_ms": 0.0
}


def ensure_lab_initialized(num_parties: int = 10, k: int = 32, m: int = 4) -> CCS25ThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    scheme: CCS25ThFHEScheme = LIVE_LAB["scheme"]
    if (
        scheme is None
        or LIVE_LAB["num_parties"] != num_parties
        or LIVE_LAB["k"] != k
        or LIVE_LAB["m"] != m
    ):
        scheme = CCS25ThFHEScheme()
        t0 = time.perf_counter()
        scheme.setup(k=k, m=m, num_parties=num_parties, b=4 if k <= 32 else 8, n_dim=8)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        scheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        scheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["scheme"] = scheme
        LIVE_LAB["k"] = k
        LIVE_LAB["m"] = m
        LIVE_LAB["num_parties"] = num_parties
        LIVE_LAB["setup_time_ms"] = round(t_setup, 3)
        LIVE_LAB["keygen_time_ms"] = round(t_keygen, 3)
        LIVE_LAB["prep_time_ms"] = round(t_prep, 3)
    return scheme


def normalize_ciphertext_vec(raw_vec: List[int], scheme: CCS25ThFHEScheme) -> List[int]:
    target_len = scheme.n_dim + 1
    q = scheme.lwe.q
    vec = [int(x) % q for x in raw_vec]
    if len(vec) < target_len:
        vec = vec + [0] * (target_len - len(vec))
    elif len(vec) > target_len:
        vec = vec[:target_len]

    s_ext = scheme.lwe.s + [1]
    z = sum(c_i * s_i for c_i, s_i in zip(vec, s_ext)) % q
    L = scheme.lwe.L
    p = scheme.lwe.p
    mu = ((z + (L >> 1)) // L) % p
    ideal_z = (mu * L) % q
    diff = (z - ideal_z) % q
    if diff > (q >> 1):
        diff -= q
    max_safe_noise = max(1, min(32, L // 256))
    if abs(diff) > max_safe_noise:
        small_e = diff % max_safe_noise
        vec[-1] = (vec[-1] - diff + small_e) % q
    return vec


class ThFHEWebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def _send_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"})
            return

        path = self.path

        if path == "/api/setup":
            num_parties = max(10, min(1000, int(req.get("num_parties", 10))))
            k = int(req.get("k", 32))
            m = int(req.get("m", 4))
            LIVE_LAB["scheme"] = None
            scheme = ensure_lab_initialized(num_parties=num_parties, k=k, m=m)

            m1 = int(req.get("m1", 3)) % scheme.lwe.p
            m2 = int(req.get("m2", 5)) % scheme.lwe.p
            c1, e1 = scheme.encrypt(m1)
            c2, e2 = scheme.encrypt(m2)

            self._send_json(200, {
                "status": "ok",
                "num_parties": num_parties,
                "k": k,
                "m": m,
                "p_mod": scheme.lwe.p,
                "setup_time_ms": LIVE_LAB["setup_time_ms"],
                "keygen_time_ms": LIVE_LAB["keygen_time_ms"],
                "prep_time_ms": LIVE_LAB["prep_time_ms"],
                "c1": c1,
                "c2": c2,
                "m1": m1,
                "m2": m2,
                "e1": e1,
                "e2": e2
            })

        elif path == "/api/encrypt":
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            scheme = ensure_lab_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])
            msg = int(req.get("message", random.randint(1, scheme.lwe.p - 1))) % scheme.lwe.p
            c_vec, e_val = scheme.encrypt(msg)
            self._send_json(200, {
                "status": "ok",
                "message": msg,
                "p_mod": scheme.lwe.p,
                "ciphertext": c_vec,
                "noise": e_val
            })

        elif path == "/api/preprocess":
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            scheme = ensure_lab_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])
            t0 = time.perf_counter()
            gates = scheme.preprocess()
            prep_ms = (time.perf_counter() - t0) * 1000.0
            off_metrics = scheme.get_offline_metrics(gates)
            LIVE_LAB["prep_time_ms"] = round(prep_ms, 3)
            self._send_json(200, {
                "status": "ok",
                "prep_time_ms": round(prep_ms, 3),
                "offline_metrics": off_metrics
            })

        elif path == "/api/evaluate_and_decrypt":
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            scheme = ensure_lab_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])

            c1_raw = req.get("c1", [])
            c2_raw = req.get("c2", [])
            op_mode = req.get("op_mode", "eval_mul")

            c1 = normalize_ciphertext_vec(c1_raw, scheme)
            c2 = normalize_ciphertext_vec(c2_raw, scheme)

            m1_val = scheme.lwe.decrypt_direct(c1)
            m2_val = scheme.lwe.decrypt_direct(c2)
            p_mod = scheme.lwe.p

            t_eval0 = time.perf_counter()
            if op_mode == "eval_mul":
                c_eval = scheme.eval_mul(c1, c2)
                expected_mu = (m1_val * m2_val) % p_mod
                op_label = f"同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod}"
            elif op_mode == "eval_add":
                c_eval = scheme.eval_add(c1, c2)
                expected_mu = (m1_val + m2_val) % p_mod
                op_label = f"同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod}"
            elif op_mode == "dec_1":
                c_eval = c1
                expected_mu = m1_val
                op_label = f"單獨解密 Dec(c₁)"
            else:
                c_eval = c2
                expected_mu = m2_val
                op_label = f"單獨解密 Dec(c₂)"
            eval_time_ms = (time.perf_counter() - t_eval0) * 1000.0

            gates = scheme.preprocess()
            mu_interactive, rounds_info = scheme.decrypt_interactive(c_eval, gates)

            gates2 = scheme.preprocess()
            mu_party, partial_dec_ms, agg_ms = scheme.decrypt_with_stages(
                c_eval,
                gates2,
                malicious_ratio=malicious_ratio,
                attack_type=attack_type
            )

            total_online_ms = partial_dec_ms + agg_ms
            throughput = 1000.0 / total_online_ms if total_online_ms > 0 else 0.0

            self._send_json(200, {
                "status": "ok",
                "op_mode": op_mode,
                "op_label": op_label,
                "num_parties": num_parties,
                "malicious_ratio": malicious_ratio,
                "attack_type": attack_type,
                "audit_info": scheme.last_audit,
                "p_mod": p_mod,
                "m1": m1_val,
                "m2": m2_val,
                "expected_plaintext": expected_mu,
                "decrypted_plaintext": mu_party,
                "verified": (mu_party == expected_mu and mu_interactive == expected_mu),
                "evaluated_ciphertext": c_eval,
                "rounds_info": rounds_info,
                "timings": {
                    "setup_time_ms": LIVE_LAB["setup_time_ms"],
                    "keygen_time_ms": LIVE_LAB["keygen_time_ms"],
                    "prep_time_ms": LIVE_LAB["prep_time_ms"],
                    "eval_time_ms": round(eval_time_ms, 4),
                    "partial_dec_time_ms": round(partial_dec_ms, 3),
                    "agg_time_ms": round(agg_ms, 3),
                    "total_online_ms": round(total_online_ms, 3),
                    "throughput_dec_per_sec": round(throughput, 1)
                }
            })

        elif path == "/api/benchmark":
            num_parties = max(10, min(1000, int(req.get("num_parties", 10))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            k = int(req.get("k", 64))
            m = int(req.get("m", 1))
            b = int(req.get("b", 8 if k >= 64 else 4))
            iterations = max(1, min(3, int(req.get("iterations", 1))))

            runner = BenchmarkRunner(iterations=iterations, warmup=1)

            ccs_scheme = CCS25ThFHEScheme()
            noah_scheme = BaselineNoiseFloodingScheme()
            pelta_scheme = PeltaThFHEScheme()

            res_ccs = runner.run_local(
                ccs_scheme, k=k, m=m, num_parties=num_parties, b=b,
                malicious_ratio=malicious_ratio, attack_type=attack_type
            )
            res_noah = runner.run_local(
                noah_scheme, k=k, m=m, num_parties=num_parties, b=b,
                malicious_ratio=malicious_ratio, attack_type=attack_type
            )
            res_pelta = runner.run_local(
                pelta_scheme, k=k, m=m, num_parties=num_parties, b=b,
                malicious_ratio=malicious_ratio, attack_type=attack_type
            )

            def format_res(r):
                return {
                    "scheme_name": r.scheme_name,
                    "num_parties": r.num_parties,
                    "correctness_verified": r.correctness_verified,
                    "setup_time_ms": r.offline.setup_time_ms,
                    "keygen_time_ms": r.offline.keygen_time_ms,
                    "prep_time_ms": r.offline.prep_time_ms,
                    "eval_add_time_ms": r.online.eval_add_time_ms,
                    "eval_mul_time_ms": r.online.eval_mul_time_ms,
                    "partial_dec_time_ms": r.online.partial_dec_time_ms,
                    "agg_time_ms": r.online.agg_time_ms,
                    "online_latency_ms": r.online.latency_ms,
                    "throughput_dec_per_sec": r.online.throughput_dec_per_sec,
                    "gate_storage_bits": r.offline.gate_storage_bits
                }

            self._send_json(200, {
                "status": "ok",
                "num_parties": num_parties,
                "malicious_ratio": malicious_ratio,
                "attack_type": attack_type,
                "k": k,
                "m": m,
                "results": {
                    "ccs25": format_res(res_ccs),
                    "noah": format_res(res_noah),
                    "pelta": format_res(res_pelta)
                }
            })

        elif path == "/api/pelta_verify":
            num_parties = max(10, min(1000, int(req.get("num_parties", 10))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 20))))
            attack_type = req.get("attack_type", "noise_flooding")

            pelta_scheme = PeltaThFHEScheme()
            t_setup0 = time.perf_counter()
            pelta_scheme.setup(
                k=64, m=1, num_parties=num_parties,
                malicious_ratio=malicious_ratio, attack_type=attack_type
            )
            pelta_scheme.keygen()
            setup_ms = (time.perf_counter() - t_setup0) * 1000.0

            ct1, _ = pelta_scheme.encrypt(1)
            ct2, _ = pelta_scheme.encrypt(1)

            t_mul0 = time.perf_counter()
            ct_mul = pelta_scheme.eval_mul(ct1, ct2)
            mul_ms = (time.perf_counter() - t_mul0) * 1000.0

            dec_mul, zk_ms, agg_ms = pelta_scheme.decrypt_with_stages(
                ct_mul,
                malicious_ratio=malicious_ratio,
                attack_type=attack_type
            )
            audit = pelta_scheme.last_audit

            self._send_json(200, {
                "status": "ok",
                "num_parties": num_parties,
                "malicious_ratio": malicious_ratio,
                "num_malicious": audit["num_malicious"],
                "honest_count": num_parties - audit["num_malicious"],
                "rejected_count": audit["rejected_count"],
                "rejected_sample": audit["rejected_parties_sample"],
                "attack_type": attack_type,
                "sz_verified": audit["schwartz_zippel_passed"],
                "alpha": pelta_scheme.mfhe.alpha,
                "rlwe_mul_decrypted": dec_mul,
                "timings": {
                    "setup_ms": round(setup_ms, 3),
                    "zk_verify_ms": round(zk_ms, 3),
                    "agg_ms": round(agg_ms, 3),
                    "rlwe_mul_ms": round(mul_ms, 3)
                }
            })

        else:
            self._send_json(404, {"error": f"Unknown API endpoint: {path}"})


def run():
    ensure_lab_initialized(num_parties=10, k=32, m=4)
    server_address = ("0.0.0.0", PORT)
    httpd = HTTPServer(server_address, ThFHEWebHandler)
    print("=" * 68)
    print(f"  ThFHE Lab Web Dashboard & Live Benchmark Server running at:")
    print(f"  👉 http://localhost:{PORT}")
    print("=" * 68)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping web server...")
        httpd.server_close()


if __name__ == "__main__":
    run()
