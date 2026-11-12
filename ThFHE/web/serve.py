#!/usr/bin/env python3
"""
================================================================================
ThFHE Lab Web Server & Real-Time Cryptographic Benchmark API
================================================================================
Hosts `index.html` and provides live REST endpoints backed by `tool.py`,
`CCS25`, `PELTA`, and `BenchmarkRunner`:
  - POST /api/setup                   : Initialize both CCS25 & PELTA for N parties
  - POST /api/encrypt                 : Encrypt plaintext for CCS25 or PELTA
  - POST /api/ccs/stage               : Execute individual stage or full flow for CCS 2025
  - POST /api/pelta/stage             : Execute individual stage or full flow for PELTA
  - POST /api/evaluate_and_decrypt    : Full CCS25 evaluation & decryption
  - POST /api/pelta_verify            : Full PELTA evaluation, ZK check & decryption
  - POST /api/benchmark               : Run real 7-stage multi-scheme benchmark
================================================================================
"""

import os
import sys
import json
import time
import random
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any, List, Tuple

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
    # CCS 2025 state
    "scheme": None,
    "k": 32,
    "m": 4,        # Plaintext space Z_{16} (0..15)
    "b": 4,
    "n_dim": 8,
    "num_parties": 10,
    "setup_time_ms": 0.0,
    "keygen_time_ms": 0.0,
    "prep_time_ms": 0.0,
    "last_c_eval": None,
    "last_expected_mu": 0,
    "last_op_label": "",
    "last_eval_ms": 0.0,
    "last_pdec_ms": 0.0,
    "last_mu": 0,
    # PELTA state
    "pelta_scheme": None,
    "pelta_setup_ms": 0.0,
    "pelta_keygen_ms": 0.0,
    "pelta_prep_ms": 0.0,
    "pelta_last_ct_eval": None,
    "pelta_last_expected_mu": 0,
    "pelta_last_op_label": "",
    "pelta_last_eval_ms": 0.0,
    "pelta_last_pdec_ms": 0.0,
    "pelta_last_mu": 0
}


def ensure_ccs_initialized(num_parties: int = 10, k: int = 32, m: int = 4) -> CCS25ThFHEScheme:
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


def ensure_pelta_initialized(num_parties: int = 10, m: int = 4) -> PeltaThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    pscheme: PeltaThFHEScheme = LIVE_LAB["pelta_scheme"]
    if pscheme is None or pscheme.num_parties != num_parties or pscheme.m != m:
        pscheme = PeltaThFHEScheme()
        t0 = time.perf_counter()
        pscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        pscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        pscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["pelta_scheme"] = pscheme
        LIVE_LAB["pelta_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["pelta_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["pelta_prep_ms"] = round(t_prep, 3)
    return pscheme


def normalize_ccs_ciphertext(raw_vec: List[int], scheme: CCS25ThFHEScheme) -> List[int]:
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


def normalize_pelta_ciphertext(raw_ct: Any, pscheme: PeltaThFHEScheme) -> Tuple[List[int], List[int]]:
    mfhe = pscheme.mfhe
    N = mfhe.N
    q = mfhe.q
    if isinstance(raw_ct, list) and len(raw_ct) == 2 and isinstance(raw_ct[0], list) and isinstance(raw_ct[1], list):
        c0 = ([int(x) % q for x in raw_ct[0]] + [0] * N)[:N]
        c1 = ([int(x) % q for x in raw_ct[1]] + [0] * N)[:N]
    elif isinstance(raw_ct, list):
        flat = [int(x) % q for x in raw_ct] + [0] * (2 * N)
        c0 = flat[:N]
        c1 = flat[N:2 * N]
    else:
        return mfhe.encrypt(1)

    # Ensure valid low-noise RLWE phase so user-typed polynomials don't overflow multiplication
    phase = mfhe.ring.add(c0, mfhe.ring.mul(c1, mfhe.s_joint))
    val0 = phase[0] % q
    mu = ((val0 + (mfhe.delta // 2)) // mfhe.delta) % mfhe.p
    ideal_m_poly = mfhe.ring.zero()
    ideal_m_poly[0] = (mu * mfhe.delta) % q
    diff_poly = mfhe.ring.sub(phase, ideal_m_poly)
    centered_diff = mfhe.ring.center(diff_poly)
    if max(abs(x) for x in centered_diff) > 4:
        c0 = mfhe.ring.sub(c0, diff_poly)
    return c0, c1


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
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 20))))
            attack_type = req.get("attack_type", "noise_flooding")
            k = int(req.get("k", 32))
            m = int(req.get("m", 4))

            LIVE_LAB["scheme"] = None
            LIVE_LAB["pelta_scheme"] = None
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=k, m=m)
            pscheme = ensure_pelta_initialized(num_parties=num_parties, m=m)

            m1 = int(req.get("m1", 3)) % scheme.lwe.p
            m2 = int(req.get("m2", 5)) % scheme.lwe.p
            c1, e1 = scheme.encrypt(m1)
            c2, e2 = scheme.encrypt(m2)

            pm1 = int(req.get("pm1", 3)) % pscheme.mfhe.p
            pm2 = int(req.get("pm2", 5)) % pscheme.mfhe.p
            pct1, _ = pscheme.encrypt(pm1)
            pct2, _ = pscheme.encrypt(pm2)

            num_mal = 0 if attack_type == "none" else (num_parties * malicious_ratio) // 100
            random_mal_parties = sorted(random.sample(range(1, num_parties + 1), num_mal)) if num_mal > 0 else []

            self._send_json(200, {
                "status": "ok",
                "num_parties": num_parties,
                "malicious_ratio": malicious_ratio,
                "random_malicious_parties": random_mal_parties,
                "k": k,
                "m": m,
                "p_mod": scheme.lwe.p,
                "setup_time_ms": LIVE_LAB["setup_time_ms"],
                "keygen_time_ms": LIVE_LAB["keygen_time_ms"],
                "prep_time_ms": LIVE_LAB["prep_time_ms"],
                "pelta_setup_ms": LIVE_LAB["pelta_setup_ms"],
                "pelta_keygen_ms": LIVE_LAB["pelta_keygen_ms"],
                "pelta_prep_ms": LIVE_LAB["pelta_prep_ms"],
                "c1": c1,
                "c2": c2,
                "pelta_c1": [pct1[0], pct1[1]],
                "pelta_c2": [pct2[0], pct2[1]]
            })

        elif path == "/api/encrypt":
            target = req.get("target", "ccs25")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            if target == "pelta":
                pscheme = ensure_pelta_initialized(num_parties=num_parties, m=LIVE_LAB["m"])
                msg = int(req.get("message", random.randint(1, pscheme.mfhe.p - 1))) % pscheme.mfhe.p
                t0 = time.perf_counter()
                ct, _ = pscheme.encrypt(msg)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "pelta",
                    "message": msg,
                    "p_mod": pscheme.mfhe.p,
                    "ciphertext": [ct[0], ct[1]],
                    "enc_time_ms": round(enc_ms, 4)
                })
            else:
                scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])
                msg = int(req.get("message", random.randint(1, scheme.lwe.p - 1))) % scheme.lwe.p
                t0 = time.perf_counter()
                c_vec, e_val = scheme.encrypt(msg)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "ccs25",
                    "message": msg,
                    "p_mod": scheme.lwe.p,
                    "ciphertext": c_vec,
                    "noise": e_val,
                    "enc_time_ms": round(enc_ms, 4)
                })

        elif path == "/api/ccs/stage":
            stage = req.get("stage", "setup")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])

            if stage == "setup":
                t0 = time.perf_counter()
                params = scheme.setup(k=LIVE_LAB["k"], m=LIVE_LAB["m"], num_parties=num_parties, b=4, n_dim=8)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["setup_time_ms"] = ms
                # Keep keys ready after setup
                scheme.keygen()
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "params": params
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = scheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["keygen_time_ms"] = ms
                m1 = int(req.get("m1", 3)) % scheme.lwe.p
                m2 = int(req.get("m2", 5)) % scheme.lwe.p
                c1, _ = scheme.encrypt(m1)
                c2, _ = scheme.encrypt(m2)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "keygen_info": kg_info,
                    "c1": c1,
                    "c2": c2
                })

            elif stage == "preprocess":
                t0 = time.perf_counter()
                gates = scheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["prep_time_ms"] = ms
                off_metrics = scheme.get_offline_metrics(gates)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "offline_metrics": off_metrics
                })

            elif stage == "encrypt":
                m1 = int(req.get("m1", 3)) % scheme.lwe.p
                m2 = int(req.get("m2", 5)) % scheme.lwe.p
                t0 = time.perf_counter()
                c1, e1 = scheme.encrypt(m1)
                c2, e2 = scheme.encrypt(m2)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "time_ms": ms,
                    "m1": m1,
                    "m2": m2,
                    "c1": c1,
                    "c2": c2,
                    "e1": e1,
                    "e2": e2
                })

            elif stage == "eval":
                c1 = normalize_ccs_ciphertext(req.get("c1", []), scheme)
                c2 = normalize_ccs_ciphertext(req.get("c2", []), scheme)
                op_mode = req.get("op_mode", "eval_mul")
                m1_val = scheme.lwe.decrypt_direct(c1)
                m2_val = scheme.lwe.decrypt_direct(c2)
                p_mod = scheme.lwe.p

                t0 = time.perf_counter()
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
                ms = round((time.perf_counter() - t0) * 1000.0, 4)

                LIVE_LAB["last_c_eval"] = c_eval
                LIVE_LAB["last_expected_mu"] = expected_mu
                LIVE_LAB["last_op_label"] = op_label
                LIVE_LAB["last_eval_ms"] = ms

                self._send_json(200, {
                    "status": "ok",
                    "stage": "eval",
                    "time_ms": ms,
                    "op_label": op_label,
                    "c_eval": c_eval,
                    "expected_mu": expected_mu
                })

            elif stage in ("partial_dec", "aggregate"):
                c1 = normalize_ccs_ciphertext(req.get("c1", []), scheme)
                c2 = normalize_ccs_ciphertext(req.get("c2", []), scheme)
                op_mode = req.get("op_mode", "eval_mul")
                m1_val = scheme.lwe.decrypt_direct(c1)
                m2_val = scheme.lwe.decrypt_direct(c2)
                p_mod = scheme.lwe.p

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

                gates = scheme.preprocess()
                _, rounds_info = scheme.decrypt_interactive(c_eval, gates)

                gates2 = scheme.preprocess()
                mu_party, partial_dec_ms, agg_ms = scheme.decrypt_with_stages(
                    c_eval,
                    gates2,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type
                )
                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "op_label": op_label,
                    "partial_dec_ms": round(partial_dec_ms, 3),
                    "agg_ms": round(agg_ms, 3),
                    "total_online_ms": round(partial_dec_ms + agg_ms, 3),
                    "throughput_dec_per_sec": round(1000.0 / max(0.001, partial_dec_ms + agg_ms), 1),
                    "rounds_info": rounds_info,
                    "audit_info": scheme.last_audit,
                    "decrypted_plaintext": mu_party,
                    "expected_plaintext": expected_mu,
                    "verified": (mu_party == expected_mu)
                })

        elif path == "/api/pelta/stage":
            stage = req.get("stage", "setup")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 20))))
            attack_type = req.get("attack_type", "noise_flooding")
            pscheme = ensure_pelta_initialized(num_parties=num_parties, m=LIVE_LAB["m"])

            if stage == "setup":
                t0 = time.perf_counter()
                params = pscheme.setup(k=32, m=LIVE_LAB["m"], num_parties=num_parties, malicious_ratio=malicious_ratio, attack_type=attack_type)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["pelta_setup_ms"] = ms
                pscheme.keygen()
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "params": params
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = pscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["pelta_keygen_ms"] = ms
                pm1 = int(req.get("m1", 3)) % pscheme.mfhe.p
                pm2 = int(req.get("m2", 5)) % pscheme.mfhe.p
                pct1, _ = pscheme.encrypt(pm1)
                pct2, _ = pscheme.encrypt(pm2)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "keygen_info": kg_info,
                    "c1": [pct1[0], pct1[1]],
                    "c2": [pct2[0], pct2[1]]
                })

            elif stage == "preprocess":
                t0 = time.perf_counter()
                prep_data = pscheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["pelta_prep_ms"] = ms
                off_metrics = pscheme.get_offline_metrics(prep_data)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "commit_count": len(prep_data["commitments"]),
                    "offline_metrics": off_metrics
                })

            elif stage == "encrypt":
                pm1 = int(req.get("m1", 3)) % pscheme.mfhe.p
                pm2 = int(req.get("m2", 5)) % pscheme.mfhe.p
                t0 = time.perf_counter()
                pct1, _ = pscheme.encrypt(pm1)
                pct2, _ = pscheme.encrypt(pm2)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "time_ms": ms,
                    "m1": pm1,
                    "m2": pm2,
                    "c1": [pct1[0], pct1[1]],
                    "c2": [pct2[0], pct2[1]]
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                ct1 = normalize_pelta_ciphertext(req.get("c1", []), pscheme)
                ct2 = normalize_pelta_ciphertext(req.get("c2", []), pscheme)
                op_mode = req.get("op_mode", "eval_mul")
                m1_val = pscheme.mfhe.decrypt_direct(ct1)
                m2_val = pscheme.mfhe.decrypt_direct(ct2)
                p_mod = pscheme.mfhe.p

                t_eval0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = pscheme.eval_mul(ct1, ct2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"RLWE 同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod}"
                elif op_mode == "eval_add":
                    ct_eval = pscheme.eval_add(ct1, ct2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"RLWE 同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod}"
                elif op_mode == "dec_1":
                    ct_eval = ct1
                    expected_mu = m1_val
                    op_label = f"RLWE 單獨解密 Dec(c₁)"
                else:
                    ct_eval = ct2
                    expected_mu = m2_val
                    op_label = f"RLWE 單獨解密 Dec(c₂)"
                eval_ms = round((time.perf_counter() - t_eval0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "time_ms": eval_ms,
                        "op_label": op_label,
                        "ct_eval": [ct_eval[0], ct_eval[1]],
                        "expected_mu": expected_mu
                    })
                    return

                mu_party, zk_ms, agg_ms = pscheme.decrypt_with_stages(
                    ct_eval,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type
                )
                audit = pscheme.last_audit
                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "p_mod": p_mod,
                    "m1": m1_val,
                    "m2": m2_val,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": mu_party,
                    "verified": (mu_party == expected_mu),
                    "evaluated_ciphertext": [ct_eval[0], ct_eval[1]],
                    "audit_info": audit,
                    "alpha": pscheme.mfhe.alpha,
                    "timings": {
                        "setup_time_ms": LIVE_LAB["pelta_setup_ms"],
                        "keygen_time_ms": LIVE_LAB["pelta_keygen_ms"],
                        "prep_time_ms": LIVE_LAB["pelta_prep_ms"],
                        "eval_time_ms": eval_ms,
                        "partial_dec_time_ms": round(zk_ms, 3),
                        "agg_time_ms": round(agg_ms, 3),
                        "total_online_ms": round(zk_ms + agg_ms, 3)
                    }
                })

        elif path == "/api/evaluate_and_decrypt":
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=LIVE_LAB["m"])

            c1 = normalize_ccs_ciphertext(req.get("c1", []), scheme)
            c2 = normalize_ccs_ciphertext(req.get("c2", []), scheme)
            op_mode = req.get("op_mode", "eval_mul")

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

        else:
            self._send_json(404, {"error": f"Unknown API endpoint: {path}"})


def run():
    ensure_ccs_initialized(num_parties=10, k=32, m=4)
    ensure_pelta_initialized(num_parties=10, m=4)
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
