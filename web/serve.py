#!/usr/bin/env python3
"""
================================================================================
ThFHE Lab Web Server & Real-Time Cryptographic Benchmark API
================================================================================
Hosts `index.html` and provides live REST endpoints backed by `tool.py`,
`CCS25`, `PELTA`, and `BenchmarkRunner`:
  - POST /api/setup                   : Initialize both CCS25 & PELTA for N parties (T=1024 default, Scalar & SIMD)
  - POST /api/encrypt                 : Encrypt scalar or SIMD plaintext vector for CCS25 or PELTA
  - POST /api/ccs/stage               : Execute individual stage or full flow for CCS 2025 (Scalar & SIMD)
  - POST /api/pelta/stage             : Execute individual stage or full flow for PELTA (Scalar & SIMD)
  - POST /api/evaluate_and_decrypt    : Full CCS25 evaluation & decryption (Scalar & SIMD)
  - POST /api/benchmark               : Run real 7-stage multi-scheme benchmark
================================================================================
"""

import os
import sys
import json
import time
import random
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any, List, Tuple, Union

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
THFHE_DIR = os.path.dirname(WEB_DIR)
if THFHE_DIR not in sys.path:
    sys.path.insert(0, THFHE_DIR)

from schemes.ccs25_scheme import CCS25ThFHEScheme
from schemes.baseline_noise_flooding import BaselineNoiseFloodingScheme
from schemes.pelta_scheme import PeltaThFHEScheme
from schemes.hqfs_scheme import HQFSThFHEScheme
from runner.benchmark_runner import BenchmarkRunner

PORT = 3000

LIVE_LAB = {
    # CCS 2025 state
    "scheme": None,
    "k": 32,
    "m": 10,       # Default Plaintext space T = 2^10 = 1024 (Z_{1024}: 0..1023)
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
    "pelta_simd_slot_count": 4,
    "pelta_last_ct_eval": None,
    "pelta_last_expected_mu": 0,
    "pelta_last_op_label": "",
    "pelta_last_eval_ms": 0.0,
    "pelta_last_pdec_ms": 0.0,
    "pelta_last_mu": 0,
    # HQ-FS (Our Work) state
    "hqfs_scheme": None,
    "hqfs_setup_ms": 0.0,
    "hqfs_keygen_ms": 0.0,
    "hqfs_prep_ms": 0.0,
    "hqfs_simd_slot_count": 4
}


def ensure_ccs_initialized(num_parties: int = 10, k: int = 32, m: int = 10) -> CCS25ThFHEScheme:
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


def ensure_pelta_initialized(num_parties: int = 10, m: int = 10) -> PeltaThFHEScheme:
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


def ensure_hqfs_initialized(num_parties: int = 10, m: int = 10) -> HQFSThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    t_target = 1 << m if m <= 16 else 1024
    hscheme: HQFSThFHEScheme = LIVE_LAB["hqfs_scheme"]
    if hscheme is None or hscheme.num_parties != num_parties or hscheme.T != t_target:
        hscheme = HQFSThFHEScheme()
        t0 = time.perf_counter()
        hscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        hscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        hscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["hqfs_scheme"] = hscheme
        LIVE_LAB["hqfs_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["hqfs_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["hqfs_prep_ms"] = round(t_prep, 3)
    return hscheme


def parse_message_or_slots(raw_val: Any, p_mod: int, simd_mode: bool = False) -> Tuple[bool, Union[int, List[int]]]:
    """
    Parses a user message input into either `(False, scalar_int)` or `(True, slot_list)`.
    Automatically detects comma/space-separated vectors or JSON arrays.
    """
    if isinstance(raw_val, list):
        slots = [int(x) % p_mod for x in raw_val if str(x).strip() != ""]
        if not slots:
            slots = [3 % p_mod, 15 % p_mod, 100 % p_mod, 512 % p_mod]
        return True, slots[:16]

    if isinstance(raw_val, str):
        cleaned = raw_val.strip()
        if "," in cleaned or " " in cleaned or cleaned.startswith("["):
            parts = cleaned.replace("[", "").replace("]", "").split(",")
            slots = []
            for part in parts:
                for token in part.strip().split():
                    try:
                        slots.append(int(float(token)) % p_mod)
                    except Exception:
                        pass
            if len(slots) > 1 or simd_mode:
                if not slots:
                    slots = [3 % p_mod, 15 % p_mod, 100 % p_mod, 512 % p_mod]
                return True, slots[:16]
            if len(slots) == 1:
                return False, slots[0]

    try:
        val = int(float(raw_val)) % p_mod
    except Exception:
        val = 3 % p_mod

    if simd_mode:
        return True, [val, (val * 2 + 1) % p_mod, (val * 3 + 2) % p_mod, (val * 5 + 3) % p_mod]
    return False, val


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
    max_safe_noise = max(1, min(16, L // (512 * max(1, p // 16))))
    if abs(diff) > max_safe_noise:
        small_e = diff % max_safe_noise
        vec[-1] = (vec[-1] - diff + small_e) % q
    return vec


def is_ccs_simd_batch(raw_ct: Any) -> bool:
    return isinstance(raw_ct, list) and len(raw_ct) > 0 and isinstance(raw_ct[0], list)


def normalize_ccs_simd_batch(raw_ct: Any, scheme: CCS25ThFHEScheme) -> List[List[int]]:
    if is_ccs_simd_batch(raw_ct):
        return [normalize_ccs_ciphertext(vec, scheme) for vec in raw_ct[:16]]
    elif isinstance(raw_ct, list):
        return [normalize_ccs_ciphertext(raw_ct, scheme)]
    return scheme.encrypt_simd([3, 15, 100, 512])


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

    # Preserve all N polynomial coefficients (supporting both Scalar and CRT/NTT SIMD slots!)
    phase = mfhe.ring.add(c0, mfhe.ring.mul(c1, mfhe.s_joint))
    half_delta = mfhe.delta // 2
    m_poly = [(((val % q) + half_delta) // mfhe.delta) % mfhe.p_ntt for val in phase]
    ideal_m_poly = [(m_c * mfhe.delta) % q for m_c in m_poly]
    diff_poly = mfhe.ring.sub(phase, ideal_m_poly)
    centered_diff = mfhe.ring.center(diff_poly)
    if max(abs(x) for x in centered_diff) > 4:
        c0 = mfhe.ring.sub(c0, diff_poly)
    return c0, c1


def normalize_hqfs_ciphertext(raw_ct: Any, hscheme: HQFSThFHEScheme) -> Tuple[List[List[List[int]]], List[List[int]]]:
    hqfs = hscheme.hqfs
    if isinstance(raw_ct, dict) and "u" in raw_ct and "v" in raw_ct:
        return raw_ct["u"], raw_ct["v"]
    if (
        isinstance(raw_ct, list)
        and len(raw_ct) == 2
        and isinstance(raw_ct[0], list)
        and isinstance(raw_ct[1], list)
        and len(raw_ct[0]) == hqfs.n_glwe
    ):
        return raw_ct[0], raw_ct[1]
    return hqfs.encrypt(12)


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
            m = int(req.get("m", 10))  # Default T = 2^10 = 1024
            ccs_simd = bool(req.get("ccs_simd", False))
            pelta_simd = bool(req.get("pelta_simd", False))
            hqfs_simd = bool(req.get("hqfs_simd", False))

            LIVE_LAB["scheme"] = None
            LIVE_LAB["pelta_scheme"] = None
            LIVE_LAB["hqfs_scheme"] = None
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=k, m=m)
            pscheme = ensure_pelta_initialized(num_parties=num_parties, m=m)
            hscheme = ensure_hqfs_initialized(num_parties=num_parties, m=m)

            p_mod = scheme.lwe.p
            is_simd_1, m1_parsed = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=ccs_simd)
            is_simd_2, m2_parsed = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=ccs_simd)
            if is_simd_1 or is_simd_2:
                s1 = m1_parsed if isinstance(m1_parsed, list) else [m1_parsed] * 4
                s2 = m2_parsed if isinstance(m2_parsed, list) else [m2_parsed] * 4
                L_len = max(len(s1), len(s2))
                s1 = (s1 + [0] * L_len)[:L_len]
                s2 = (s2 + [0] * L_len)[:L_len]
                c1 = scheme.encrypt_simd(s1)
                c2 = scheme.encrypt_simd(s2)
            else:
                c1, _ = scheme.encrypt(int(m1_parsed))
                c2, _ = scheme.encrypt(int(m2_parsed))

            pelta_p = pscheme.mfhe.p
            p_simd_1, pm1_parsed = parse_message_or_slots(req.get("pm1", 12), pelta_p, simd_mode=pelta_simd)
            p_simd_2, pm2_parsed = parse_message_or_slots(req.get("pm2", 25), pelta_p, simd_mode=pelta_simd)
            if p_simd_1 or p_simd_2:
                ps1 = pm1_parsed if isinstance(pm1_parsed, list) else [pm1_parsed] * 4
                ps2 = pm2_parsed if isinstance(pm2_parsed, list) else [pm2_parsed] * 4
                L_len = max(len(ps1), len(ps2))
                ps1 = (ps1 + [0] * L_len)[:L_len]
                ps2 = (ps2 + [0] * L_len)[:L_len]
                LIVE_LAB["pelta_simd_slot_count"] = L_len
                pct1 = pscheme.encrypt_simd(ps1)
                pct2 = pscheme.encrypt_simd(ps2)
            else:
                pct1, _ = pscheme.encrypt(int(pm1_parsed))
                pct2, _ = pscheme.encrypt(int(pm2_parsed))

            hqfs_p = hscheme.T
            h_simd_1, hm1_parsed = parse_message_or_slots(req.get("hm1", 12), hqfs_p, simd_mode=hqfs_simd)
            h_simd_2, hm2_parsed = parse_message_or_slots(req.get("hm2", 25), hqfs_p, simd_mode=hqfs_simd)
            if h_simd_1 or h_simd_2:
                hs1 = hm1_parsed if isinstance(hm1_parsed, list) else [hm1_parsed] * 4
                hs2 = hm2_parsed if isinstance(hm2_parsed, list) else [hm2_parsed] * 4
                L_len = max(len(hs1), len(hs2))
                hs1 = (hs1 + [0] * L_len)[:L_len]
                hs2 = (hs2 + [0] * L_len)[:L_len]
                LIVE_LAB["hqfs_simd_slot_count"] = L_len
                hct1 = hscheme.encrypt_simd(hs1)
                hct2 = hscheme.encrypt_simd(hs2)
            else:
                hct1, _ = hscheme.encrypt(int(hm1_parsed))
                hct2, _ = hscheme.encrypt(int(hm2_parsed))

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
                "t_space": scheme.lwe.p,
                "setup_time_ms": LIVE_LAB["setup_time_ms"],
                "keygen_time_ms": LIVE_LAB["keygen_time_ms"],
                "prep_time_ms": LIVE_LAB["prep_time_ms"],
                "pelta_setup_ms": LIVE_LAB["pelta_setup_ms"],
                "pelta_keygen_ms": LIVE_LAB["pelta_keygen_ms"],
                "pelta_prep_ms": LIVE_LAB["pelta_prep_ms"],
                "hqfs_setup_ms": LIVE_LAB["hqfs_setup_ms"],
                "hqfs_keygen_ms": LIVE_LAB["hqfs_keygen_ms"],
                "hqfs_prep_ms": LIVE_LAB["hqfs_prep_ms"],
                "hqfs_k_q": hscheme.hqfs.K_Q,
                "c1": c1,
                "c2": c2,
                "pelta_c1": [pct1[0], pct1[1]],
                "pelta_c2": [pct2[0], pct2[1]],
                "hqfs_c1": [hct1[0], hct1[1]],
                "hqfs_c2": [hct2[0], hct2[1]]
            })

        elif path == "/api/encrypt":
            target = req.get("target", "ccs25")
            simd_mode = bool(req.get("simd_mode", False))
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))

            if target == "hqfs":
                hscheme = ensure_hqfs_initialized(num_parties=num_parties, m=m_bits)
                p_mod = hscheme.T
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_simd:
                    LIVE_LAB["hqfs_simd_slot_count"] = len(parsed)
                    ct = hscheme.encrypt_simd(parsed)
                else:
                    ct, _ = hscheme.encrypt(int(parsed))
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "hqfs",
                    "simd_mode": is_simd,
                    "message": parsed,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "p_ntt": hscheme.hqfs.p_ntt,
                    "K_Q": hscheme.hqfs.K_Q,
                    "ciphertext": [ct[0], ct[1]],
                    "enc_time_ms": round(enc_ms, 4)
                })
            elif target == "pelta":
                pscheme = ensure_pelta_initialized(num_parties=num_parties, m=m_bits)
                p_mod = pscheme.mfhe.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_simd:
                    LIVE_LAB["pelta_simd_slot_count"] = len(parsed)
                    ct = pscheme.encrypt_simd(parsed)
                else:
                    ct, _ = pscheme.encrypt(int(parsed))
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "pelta",
                    "simd_mode": is_simd,
                    "message": parsed,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "p_ntt": pscheme.mfhe.p_ntt,
                    "ciphertext": [ct[0], ct[1]],
                    "enc_time_ms": round(enc_ms, 4)
                })
            else:
                scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=m_bits)
                p_mod = scheme.lwe.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_simd:
                    c_out = scheme.encrypt_simd(parsed)
                    e_val = 0
                else:
                    c_out, e_val = scheme.encrypt(int(parsed))
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "ccs25",
                    "simd_mode": is_simd,
                    "message": parsed,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "ciphertext": c_out,
                    "noise": e_val,
                    "enc_time_ms": round(enc_ms, 4)
                })

        elif path == "/api/ccs/stage":
            stage = req.get("stage", "setup")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            simd_mode = bool(req.get("simd_mode", False))
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=m_bits)
            p_mod = scheme.lwe.p

            if stage == "setup":
                t0 = time.perf_counter()
                params = scheme.setup(k=LIVE_LAB["k"], m=m_bits, num_parties=num_parties, b=4, n_dim=8)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["setup_time_ms"] = ms
                LIVE_LAB["m"] = m_bits
                scheme.keygen()
                p_mod = scheme.lwe.p
                is_s1, m1_p = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, m2_p = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = m1_p if isinstance(m1_p, list) else [m1_p] * 4
                    s2 = m2_p if isinstance(m2_p, list) else [m2_p] * 4
                    L_len = max(len(s1), len(s2))
                    c1 = scheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    c2 = scheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    c1, _ = scheme.encrypt(int(m1_p))
                    c2, _ = scheme.encrypt(int(m2_p))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": 1 << m_bits,
                    "params": params,
                    "c1": c1,
                    "c2": c2
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = scheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["keygen_time_ms"] = ms
                is_s1, m1_p = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, m2_p = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = m1_p if isinstance(m1_p, list) else [m1_p] * 4
                    s2 = m2_p if isinstance(m2_p, list) else [m2_p] * 4
                    L_len = max(len(s1), len(s2))
                    c1 = scheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    c2 = scheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    c1, _ = scheme.encrypt(int(m1_p))
                    c2, _ = scheme.encrypt(int(m2_p))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "t_space": p_mod,
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
                    "t_space": p_mod,
                    "offline_metrics": off_metrics
                })

            elif stage == "encrypt":
                is_s1, m1_p = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, m2_p = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_s1 or is_s2:
                    s1 = m1_p if isinstance(m1_p, list) else [m1_p] * 4
                    s2 = m2_p if isinstance(m2_p, list) else [m2_p] * 4
                    L_len = max(len(s1), len(s2))
                    s1 = (s1 + [0] * L_len)[:L_len]
                    s2 = (s2 + [0] * L_len)[:L_len]
                    c1 = scheme.encrypt_simd(s1)
                    c2 = scheme.encrypt_simd(s2)
                    e1, e2 = 0, 0
                    m1_out, m2_out = s1, s2
                else:
                    c1, e1 = scheme.encrypt(int(m1_p))
                    c2, e2 = scheme.encrypt(int(m2_p))
                    m1_out, m2_out = int(m1_p), int(m2_p)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "simd_mode": (is_s1 or is_s2),
                    "t_space": p_mod,
                    "time_ms": ms,
                    "m1": m1_out,
                    "m2": m2_out,
                    "c1": c1,
                    "c2": c2,
                    "e1": e1,
                    "e2": e2
                })

            elif stage in ("eval", "partial_dec", "aggregate"):
                raw_c1 = req.get("c1", [])
                raw_c2 = req.get("c2", [])
                op_mode = req.get("op_mode", "eval_mul")
                use_simd = simd_mode or is_ccs_simd_batch(raw_c1) or is_ccs_simd_batch(raw_c2)

                if use_simd:
                    batch_c1 = normalize_ccs_simd_batch(raw_c1, scheme)
                    batch_c2 = normalize_ccs_simd_batch(raw_c2, scheme)
                    L_len = max(len(batch_c1), len(batch_c2))
                    while len(batch_c1) < L_len:
                        batch_c1.append(batch_c1[-1])
                    while len(batch_c2) < L_len:
                        batch_c2.append(batch_c2[-1])

                    m1_slots = [scheme.lwe.decrypt_direct(c) for c in batch_c1]
                    m2_slots = [scheme.lwe.decrypt_direct(c) for c in batch_c2]

                    t0 = time.perf_counter()
                    if op_mode == "eval_mul":
                        c_eval = scheme.eval_mul_simd(batch_c1, batch_c2)
                        expected_mu = [(a * b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"SIMD 平行同態乘法 Dec(c₁ ⊗ c₂) = ({m1_slots} ⊙ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "eval_add":
                        c_eval = scheme.eval_add_simd(batch_c1, batch_c2)
                        expected_mu = [(a + b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"SIMD SWAR 平行同態加法 Dec(c₁ ⊕ c₂) = ({m1_slots} ⊕ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "dec_1":
                        c_eval = batch_c1
                        expected_mu = m1_slots
                        op_label = f"SIMD 批次解密 Dec(c₁) (T={p_mod})"
                    else:
                        c_eval = batch_c2
                        expected_mu = m2_slots
                        op_label = f"SIMD 批次解密 Dec(c₂) (T={p_mod})"
                    eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                    if stage == "eval":
                        self._send_json(200, {
                            "status": "ok",
                            "stage": "eval",
                            "simd_mode": True,
                            "slot_count": len(c_eval),
                            "t_space": p_mod,
                            "time_ms": eval_ms,
                            "op_label": op_label,
                            "c_eval": c_eval,
                            "expected_mu": expected_mu
                        })
                        return

                    _, rounds_info = scheme.decrypt_interactive(c_eval[0], scheme.preprocess())
                    mu_slots, partial_dec_ms, agg_ms = scheme.decrypt_simd_with_stages(
                        c_eval, malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    self._send_json(200, {
                        "status": "ok",
                        "stage": stage,
                        "simd_mode": True,
                        "slot_count": len(mu_slots),
                        "t_space": p_mod,
                        "op_label": op_label,
                        "partial_dec_ms": round(partial_dec_ms, 3),
                        "agg_ms": round(agg_ms, 3),
                        "total_online_ms": round(partial_dec_ms + agg_ms, 3),
                        "throughput_dec_per_sec": round((len(mu_slots) * 1000.0) / max(0.001, partial_dec_ms + agg_ms), 1),
                        "rounds_info": rounds_info,
                        "audit_info": scheme.last_audit,
                        "decrypted_plaintext": mu_slots,
                        "expected_plaintext": expected_mu,
                        "verified": (mu_slots == expected_mu)
                    })
                    return

                # Scalar path
                c1 = normalize_ccs_ciphertext(raw_c1, scheme)
                c2 = normalize_ccs_ciphertext(raw_c2, scheme)
                m1_val = scheme.lwe.decrypt_direct(c1)
                m2_val = scheme.lwe.decrypt_direct(c2)

                t0 = time.perf_counter()
                if op_mode == "eval_mul":
                    c_eval = scheme.eval_mul(c1, c2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    c_eval = scheme.eval_add(c1, c2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    c_eval = c1
                    expected_mu = m1_val
                    op_label = f"單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    c_eval = c2
                    expected_mu = m2_val
                    op_label = f"單獨解密 Dec(c₂) (T={p_mod})"
                ms = round((time.perf_counter() - t0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "simd_mode": False,
                        "t_space": p_mod,
                        "time_ms": ms,
                        "op_label": op_label,
                        "c_eval": c_eval,
                        "expected_mu": expected_mu
                    })
                    return

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
                    "simd_mode": False,
                    "t_space": p_mod,
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
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            simd_mode = bool(req.get("simd_mode", False))
            pscheme = ensure_pelta_initialized(num_parties=num_parties, m=m_bits)
            p_mod = pscheme.mfhe.p

            if stage == "setup":
                t0 = time.perf_counter()
                params = pscheme.setup(k=32, m=m_bits, num_parties=num_parties, malicious_ratio=malicious_ratio, attack_type=attack_type)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["pelta_setup_ms"] = ms
                LIVE_LAB["m"] = m_bits
                pscheme.keygen()
                p_mod = pscheme.mfhe.p
                is_s1, pm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, pm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = pm1 if isinstance(pm1, list) else [pm1] * 4
                    s2 = pm2 if isinstance(pm2, list) else [pm2] * 4
                    L_len = max(len(s1), len(s2))
                    LIVE_LAB["pelta_simd_slot_count"] = L_len
                    pct1 = pscheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    pct2 = pscheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    pct1, _ = pscheme.encrypt(int(pm1))
                    pct2, _ = pscheme.encrypt(int(pm2))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": pscheme.mfhe.p,
                    "p_ntt": pscheme.mfhe.p_ntt,
                    "params": params,
                    "c1": [pct1[0], pct1[1]],
                    "c2": [pct2[0], pct2[1]]
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = pscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["pelta_keygen_ms"] = ms
                is_s1, pm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, pm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = pm1 if isinstance(pm1, list) else [pm1] * 4
                    s2 = pm2 if isinstance(pm2, list) else [pm2] * 4
                    L_len = max(len(s1), len(s2))
                    LIVE_LAB["pelta_simd_slot_count"] = L_len
                    pct1 = pscheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    pct2 = pscheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    pct1, _ = pscheme.encrypt(int(pm1))
                    pct2, _ = pscheme.encrypt(int(pm2))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "t_space": p_mod,
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
                    "t_space": p_mod,
                    "commit_count": len(prep_data["commitments"]),
                    "offline_metrics": off_metrics
                })

            elif stage == "encrypt":
                is_s1, pm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, pm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_s1 or is_s2:
                    s1 = pm1 if isinstance(pm1, list) else [pm1] * 4
                    s2 = pm2 if isinstance(pm2, list) else [pm2] * 4
                    L_len = max(len(s1), len(s2))
                    s1 = (s1 + [0] * L_len)[:L_len]
                    s2 = (s2 + [0] * L_len)[:L_len]
                    LIVE_LAB["pelta_simd_slot_count"] = L_len
                    pct1 = pscheme.encrypt_simd(s1)
                    pct2 = pscheme.encrypt_simd(s2)
                    m1_out, m2_out = s1, s2
                else:
                    pct1, _ = pscheme.encrypt(int(pm1))
                    pct2, _ = pscheme.encrypt(int(pm2))
                    m1_out, m2_out = int(pm1), int(pm2)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "simd_mode": (is_s1 or is_s2),
                    "t_space": p_mod,
                    "p_ntt": pscheme.mfhe.p_ntt,
                    "time_ms": ms,
                    "m1": m1_out,
                    "m2": m2_out,
                    "c1": [pct1[0], pct1[1]],
                    "c2": [pct2[0], pct2[1]]
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                ct1 = normalize_pelta_ciphertext(req.get("c1", []), pscheme)
                ct2 = normalize_pelta_ciphertext(req.get("c2", []), pscheme)
                op_mode = req.get("op_mode", "eval_mul")
                is_s1, m1_in = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, m2_in = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                use_simd = simd_mode or is_s1 or is_s2

                if use_simd:
                    slot_count = int(req.get("slot_count", LIVE_LAB.get("pelta_simd_slot_count", 4)))
                    if isinstance(m1_in, list):
                        slot_count = len(m1_in)
                    slot_count = max(2, min(pscheme.N_poly, slot_count))
                    m1_slots = pscheme.mfhe.decrypt_direct_simd(ct1)[:slot_count]
                    m2_slots = pscheme.mfhe.decrypt_direct_simd(ct2)[:slot_count]

                    t_eval0 = time.perf_counter()
                    if op_mode == "eval_mul":
                        ct_eval = pscheme.eval_mul(ct1, ct2)
                        expected_mu = [(a * b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"RLWE CRT/NTT SIMD 單密文平行乘法 Dec(c₁ ⊗ c₂) = ({m1_slots} ⊙ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "eval_add":
                        ct_eval = pscheme.eval_add(ct1, ct2)
                        expected_mu = [(a + b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"RLWE CRT/NTT SIMD 單密文平行加法 Dec(c₁ ⊕ c₂) = ({m1_slots} ⊕ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "dec_1":
                        ct_eval = ct1
                        expected_mu = m1_slots
                        op_label = f"RLWE CRT/NTT SIMD 解密 Dec(c₁) (T={p_mod})"
                    else:
                        ct_eval = ct2
                        expected_mu = m2_slots
                        op_label = f"RLWE CRT/NTT SIMD 解密 Dec(c₂) (T={p_mod})"
                    eval_ms = round((time.perf_counter() - t_eval0) * 1000.0, 4)

                    if stage == "eval":
                        self._send_json(200, {
                            "status": "ok",
                            "stage": "eval",
                            "simd_mode": True,
                            "slot_count": slot_count,
                            "t_space": p_mod,
                            "p_ntt": pscheme.mfhe.p_ntt,
                            "time_ms": eval_ms,
                            "op_label": op_label,
                            "ct_eval": [ct_eval[0], ct_eval[1]],
                            "expected_mu": expected_mu
                        })
                        return

                    mu_slots, zk_ms, agg_ms = pscheme.decrypt_simd_with_stages(
                        ct_eval,
                        slot_count=slot_count,
                        malicious_ratio=malicious_ratio,
                        attack_type=attack_type
                    )
                    audit = pscheme.last_audit
                    self._send_json(200, {
                        "status": "ok",
                        "stage": stage,
                        "simd_mode": True,
                        "slot_count": slot_count,
                        "t_space": p_mod,
                        "p_ntt": pscheme.mfhe.p_ntt,
                        "op_label": op_label,
                        "num_parties": num_parties,
                        "malicious_ratio": malicious_ratio,
                        "attack_type": attack_type,
                        "p_mod": p_mod,
                        "m1": m1_slots,
                        "m2": m2_slots,
                        "expected_plaintext": expected_mu,
                        "decrypted_plaintext": mu_slots,
                        "verified": (mu_slots == expected_mu),
                        "evaluated_ciphertext": [ct_eval[0], ct_eval[1]],
                        "audit_info": audit,
                        "alpha": audit.get("fiat_shamir_alpha", pscheme.mfhe.alpha),
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
                    return

                # Scalar path
                m1_val = pscheme.mfhe.decrypt_direct(ct1)
                m2_val = pscheme.mfhe.decrypt_direct(ct2)

                t_eval0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = pscheme.eval_mul(ct1, ct2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"RLWE 同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    ct_eval = pscheme.eval_add(ct1, ct2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"RLWE 同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    ct_eval = ct1
                    expected_mu = m1_val
                    op_label = f"RLWE 單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    ct_eval = ct2
                    expected_mu = m2_val
                    op_label = f"RLWE 單獨解密 Dec(c₂) (T={p_mod})"
                eval_ms = round((time.perf_counter() - t_eval0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "simd_mode": False,
                        "t_space": p_mod,
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
                    "simd_mode": False,
                    "t_space": p_mod,
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
                    "alpha": audit.get("fiat_shamir_alpha", pscheme.mfhe.alpha),
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
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            simd_mode = bool(req.get("simd_mode", False))
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=LIVE_LAB["k"], m=m_bits)
            p_mod = scheme.lwe.p

            raw_c1 = req.get("c1", [])
            raw_c2 = req.get("c2", [])
            op_mode = req.get("op_mode", "eval_mul")
            use_simd = simd_mode or is_ccs_simd_batch(raw_c1) or is_ccs_simd_batch(raw_c2)

            if use_simd:
                batch_c1 = normalize_ccs_simd_batch(raw_c1, scheme)
                batch_c2 = normalize_ccs_simd_batch(raw_c2, scheme)
                L_len = max(len(batch_c1), len(batch_c2))
                while len(batch_c1) < L_len:
                    batch_c1.append(batch_c1[-1])
                while len(batch_c2) < L_len:
                    batch_c2.append(batch_c2[-1])

                m1_slots = [scheme.lwe.decrypt_direct(c) for c in batch_c1]
                m2_slots = [scheme.lwe.decrypt_direct(c) for c in batch_c2]

                t_eval0 = time.perf_counter()
                if op_mode == "eval_mul":
                    c_eval = scheme.eval_mul_simd(batch_c1, batch_c2)
                    expected_mu = [(a * b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                    op_label = f"SIMD 平行同態乘法 Dec(c₁ ⊗ c₂) = ({m1_slots} ⊙ {m2_slots}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    c_eval = scheme.eval_add_simd(batch_c1, batch_c2)
                    expected_mu = [(a + b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                    op_label = f"SIMD SWAR 平行同態加法 Dec(c₁ ⊕ c₂) = ({m1_slots} ⊕ {m2_slots}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    c_eval = batch_c1
                    expected_mu = m1_slots
                    op_label = f"SIMD 批次解密 Dec(c₁) (T={p_mod})"
                else:
                    c_eval = batch_c2
                    expected_mu = m2_slots
                    op_label = f"SIMD 批次解密 Dec(c₂) (T={p_mod})"
                eval_time_ms = (time.perf_counter() - t_eval0) * 1000.0

                _, rounds_info = scheme.decrypt_interactive(c_eval[0], scheme.preprocess())
                mu_slots, partial_dec_ms, agg_ms = scheme.decrypt_simd_with_stages(
                    c_eval,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type
                )
                total_online_ms = partial_dec_ms + agg_ms
                throughput = (len(mu_slots) * 1000.0) / total_online_ms if total_online_ms > 0 else 0.0

                self._send_json(200, {
                    "status": "ok",
                    "simd_mode": True,
                    "slot_count": len(mu_slots),
                    "t_space": p_mod,
                    "op_mode": op_mode,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "audit_info": scheme.last_audit,
                    "p_mod": p_mod,
                    "m1": m1_slots,
                    "m2": m2_slots,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": mu_slots,
                    "verified": (mu_slots == expected_mu),
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
                return

            c1 = normalize_ccs_ciphertext(raw_c1, scheme)
            c2 = normalize_ccs_ciphertext(raw_c2, scheme)
            m1_val = scheme.lwe.decrypt_direct(c1)
            m2_val = scheme.lwe.decrypt_direct(c2)

            t_eval0 = time.perf_counter()
            if op_mode == "eval_mul":
                c_eval = scheme.eval_mul(c1, c2)
                expected_mu = (m1_val * m2_val) % p_mod
                op_label = f"同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
            elif op_mode == "eval_add":
                c_eval = scheme.eval_add(c1, c2)
                expected_mu = (m1_val + m2_val) % p_mod
                op_label = f"同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
            elif op_mode == "dec_1":
                c_eval = c1
                expected_mu = m1_val
                op_label = f"單獨解密 Dec(c₁) (T={p_mod})"
            else:
                c_eval = c2
                expected_mu = m2_val
                op_label = f"單獨解密 Dec(c₂) (T={p_mod})"
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
                "simd_mode": False,
                "t_space": p_mod,
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

        elif path == "/api/hqfs/stage":
            stage = req.get("stage", "run_all")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 20))))
            attack_type = req.get("attack_type", "share_tampering")
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            simd_mode = bool(req.get("simd_mode", False))
            hscheme = ensure_hqfs_initialized(num_parties=num_parties, m=m_bits)
            p_mod = hscheme.T

            if stage == "setup":
                t0 = time.perf_counter()
                params = hscheme.setup(k=32, m=m_bits, num_parties=num_parties, malicious_ratio=malicious_ratio, attack_type=attack_type)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["hqfs_setup_ms"] = ms
                LIVE_LAB["m"] = m_bits
                hscheme.keygen()
                hscheme.preprocess()
                p_mod = hscheme.T
                is_s1, hm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, hm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = hm1 if isinstance(hm1, list) else [hm1] * 4
                    s2 = hm2 if isinstance(hm2, list) else [hm2] * 4
                    L_len = max(len(s1), len(s2))
                    LIVE_LAB["hqfs_simd_slot_count"] = L_len
                    hct1 = hscheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    hct2 = hscheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    hct1, _ = hscheme.encrypt(int(hm1))
                    hct2, _ = hscheme.encrypt(int(hm2))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "p_ntt": hscheme.hqfs.p_ntt,
                    "K_Q": hscheme.hqfs.K_Q,
                    "params": params,
                    "c1": [hct1[0], hct1[1]],
                    "c2": [hct2[0], hct2[1]]
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = hscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["hqfs_keygen_ms"] = ms
                hscheme.preprocess()
                is_s1, hm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, hm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                if is_s1 or is_s2:
                    s1 = hm1 if isinstance(hm1, list) else [hm1] * 4
                    s2 = hm2 if isinstance(hm2, list) else [hm2] * 4
                    L_len = max(len(s1), len(s2))
                    LIVE_LAB["hqfs_simd_slot_count"] = L_len
                    hct1 = hscheme.encrypt_simd((s1 + [0] * L_len)[:L_len])
                    hct2 = hscheme.encrypt_simd((s2 + [0] * L_len)[:L_len])
                else:
                    hct1, _ = hscheme.encrypt(int(hm1))
                    hct2, _ = hscheme.encrypt(int(hm2))
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "keygen_info": kg_info,
                    "c1": [hct1[0], hct1[1]],
                    "c2": [hct2[0], hct2[1]]
                })

            elif stage == "preprocess":
                t0 = time.perf_counter()
                prep_data = hscheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["hqfs_prep_ms"] = ms
                off_metrics = hscheme.get_offline_metrics(prep_data)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "rlk_entries": prep_data["rlk_entries"],
                    "rns_limbs": prep_data["rns_limbs"],
                    "K_Q": prep_data["K_Q"],
                    "offline_metrics": off_metrics
                })

            elif stage == "encrypt":
                is_s1, hm1 = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, hm2 = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                if is_s1 or is_s2:
                    s1 = hm1 if isinstance(hm1, list) else [hm1] * 4
                    s2 = hm2 if isinstance(hm2, list) else [hm2] * 4
                    L_len = max(len(s1), len(s2))
                    s1 = (s1 + [0] * L_len)[:L_len]
                    s2 = (s2 + [0] * L_len)[:L_len]
                    LIVE_LAB["hqfs_simd_slot_count"] = L_len
                    hct1 = hscheme.encrypt_simd(s1)
                    hct2 = hscheme.encrypt_simd(s2)
                    m1_out, m2_out = s1, s2
                else:
                    hct1, _ = hscheme.encrypt(int(hm1))
                    hct2, _ = hscheme.encrypt(int(hm2))
                    m1_out, m2_out = int(hm1), int(hm2)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "simd_mode": (is_s1 or is_s2),
                    "t_space": p_mod,
                    "p_ntt": hscheme.hqfs.p_ntt,
                    "K_Q": hscheme.hqfs.K_Q,
                    "time_ms": ms,
                    "m1": m1_out,
                    "m2": m2_out,
                    "c1": [hct1[0], hct1[1]],
                    "c2": [hct2[0], hct2[1]]
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                raw_c1 = req.get("c1", [])
                raw_c2 = req.get("c2", [])
                op_mode = req.get("op_mode", "eval_mul")
                ct1 = normalize_hqfs_ciphertext(raw_c1, hscheme)
                ct2 = normalize_hqfs_ciphertext(raw_c2, hscheme)

                is_s1, hm1_p = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=simd_mode)
                is_s2, hm2_p = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=simd_mode)
                use_simd = simd_mode or is_s1 or is_s2
                slot_count = LIVE_LAB["hqfs_simd_slot_count"]
                if isinstance(hm1_p, list):
                    slot_count = max(slot_count, len(hm1_p))
                if isinstance(hm2_p, list):
                    slot_count = max(slot_count, len(hm2_p))

                if use_simd:
                    m1_slots = hscheme.hqfs.decrypt_simd(ct1, slot_count=slot_count)
                    m2_slots = hscheme.hqfs.decrypt_simd(ct2, slot_count=slot_count)
                    t0 = time.perf_counter()
                    if op_mode == "eval_mul":
                        ct_eval = hscheme.eval_mul(ct1, ct2)
                        expected_mu = [(a * b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"RNS-GLWE SIMD 同態乘法 + 零密文疊加 (Alg 8) Dec(c₁ ⊗ c₂ + c_zero) = ({m1_slots} ⊙ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "eval_add":
                        ct_eval = hscheme.eval_add(ct1, ct2)
                        expected_mu = [(a + b) % p_mod for a, b in zip(m1_slots, m2_slots)]
                        op_label = f"RNS-GLWE SIMD 同態加法 + 零密文疊加 (Alg 7) Dec(c₁ ⊕ c₂ + c_zero) = ({m1_slots} ⊕ {m2_slots}) mod {p_mod} (T={p_mod})"
                    elif op_mode == "dec_1":
                        ct_eval = ct1
                        expected_mu = m1_slots
                        op_label = f"RNS-GLWE SIMD 解密 Dec(c₁) (T={p_mod})"
                    else:
                        ct_eval = ct2
                        expected_mu = m2_slots
                        op_label = f"RNS-GLWE SIMD 解密 Dec(c₂) (T={p_mod})"
                    eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                    if stage == "eval":
                        self._send_json(200, {
                            "status": "ok",
                            "stage": "eval",
                            "simd_mode": True,
                            "slot_count": slot_count,
                            "t_space": p_mod,
                            "time_ms": eval_ms,
                            "op_label": op_label,
                            "ct_eval": [ct_eval[0], ct_eval[1]],
                            "expected_mu": expected_mu
                        })
                        return

                    mu_slots, zk_ms, agg_ms = hscheme.decrypt_simd_with_stages(
                        ct_eval,
                        slot_count=slot_count,
                        malicious_ratio=malicious_ratio,
                        attack_type=attack_type
                    )
                    self._send_json(200, {
                        "status": "ok",
                        "stage": stage,
                        "simd_mode": True,
                        "slot_count": slot_count,
                        "t_space": p_mod,
                        "K_Q": hscheme.hqfs.K_Q,
                        "op_mode": op_mode,
                        "op_label": op_label,
                        "num_parties": num_parties,
                        "malicious_ratio": malicious_ratio,
                        "attack_type": attack_type,
                        "m1": m1_slots,
                        "m2": m2_slots,
                        "expected_plaintext": expected_mu,
                        "decrypted_plaintext": mu_slots,
                        "verified": (mu_slots == expected_mu),
                        "audit_info": hscheme.last_audit,
                        "timings": {
                            "setup_time_ms": LIVE_LAB["hqfs_setup_ms"],
                            "keygen_time_ms": LIVE_LAB["hqfs_keygen_ms"],
                            "prep_time_ms": LIVE_LAB["hqfs_prep_ms"],
                            "eval_time_ms": eval_ms,
                            "partial_dec_time_ms": round(zk_ms, 3),
                            "agg_time_ms": round(agg_ms, 3),
                            "total_online_ms": round(zk_ms + agg_ms, 3)
                        }
                    })
                    return

                # Scalar path
                m1_val = hscheme.hqfs.decrypt(ct1)
                m2_val = hscheme.hqfs.decrypt(ct2)
                t0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = hscheme.eval_mul(ct1, ct2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"RNS-GLWE 同態乘法 + 零密文疊加 (Alg 8) Dec(c₁ ⊗ c₂ + c_zero) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    ct_eval = hscheme.eval_add(ct1, ct2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"RNS-GLWE 同態加法 + 零密文疊加 (Alg 7) Dec(c₁ ⊕ c₂ + c_zero) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    ct_eval = ct1
                    expected_mu = m1_val
                    op_label = f"RNS-GLWE 單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    ct_eval = ct2
                    expected_mu = m2_val
                    op_label = f"RNS-GLWE 單獨解密 Dec(c₂) (T={p_mod})"
                eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "simd_mode": False,
                        "t_space": p_mod,
                        "time_ms": eval_ms,
                        "op_label": op_label,
                        "ct_eval": [ct_eval[0], ct_eval[1]],
                        "expected_mu": expected_mu
                    })
                    return

                mu_dec, zk_ms, agg_ms = hscheme.decrypt_with_stages(
                    ct_eval,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type
                )
                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "simd_mode": False,
                    "t_space": p_mod,
                    "K_Q": hscheme.hqfs.K_Q,
                    "op_mode": op_mode,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "m1": m1_val,
                    "m2": m2_val,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": mu_dec,
                    "verified": (mu_dec == expected_mu),
                    "audit_info": hscheme.last_audit,
                    "timings": {
                        "setup_time_ms": LIVE_LAB["hqfs_setup_ms"],
                        "keygen_time_ms": LIVE_LAB["hqfs_keygen_ms"],
                        "prep_time_ms": LIVE_LAB["hqfs_prep_ms"],
                        "eval_time_ms": eval_ms,
                        "partial_dec_time_ms": round(zk_ms, 3),
                        "agg_time_ms": round(agg_ms, 3),
                        "total_online_ms": round(zk_ms + agg_ms, 3)
                    }
                })

        elif path == "/api/benchmark":
            mode = req.get("mode", "local")
            num_parties = max(10, min(1000, int(req.get("num_parties", 10))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            k = int(req.get("k", 64))
            m = int(req.get("m", 10))
            b = int(req.get("b", 8 if k >= 64 else 4))
            iterations = max(1, min(3, int(req.get("iterations", 1))))

            runner = BenchmarkRunner(iterations=iterations, warmup=1)

            ccs_scheme = CCS25ThFHEScheme()
            noah_scheme = BaselineNoiseFloodingScheme()
            pelta_scheme = PeltaThFHEScheme()
            hqfs_scheme = HQFSThFHEScheme()

            schemes_requested = req.get("schemes", ["ccs25", "noah", "pelta", "hqfs"])
            if not isinstance(schemes_requested, list) or not schemes_requested:
                schemes_requested = ["ccs25", "noah", "pelta", "hqfs"]

            def format_res(r):
                return {
                    "scheme_name": r.scheme_name,
                    "mode": r.mode,
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
                    "gate_storage_bits": r.offline.gate_storage_bits,
                    "comm_sent_bytes": r.online.comm_sent_bytes,
                    "comm_recv_bytes": r.online.comm_recv_bytes,
                    "sockets_count": r.metadata.get("sockets_count", num_parties),
                    "rns_primes_count": r.metadata.get("rns_primes_count", 19 if "hqfs" in r.scheme_name.lower() and r.mode == "distributed" else 2),
                    "peak_mem_mb": r.online.details.get("peak_mem_mb", 0)
                }

            results_map = {}
            if mode == "distributed":
                # Real Multi-Port Distributed TCP Socket Mode
                if "ccs25" in schemes_requested:
                    res_ccs = runner.run_distributed("ccs25", k=k, m=m, num_parties=num_parties, b=b)
                    results_map["ccs25"] = format_res(res_ccs)
                if "noah" in schemes_requested:
                    res_noah = runner.run_distributed("noah", k=k, m=m, num_parties=num_parties, b=b)
                    results_map["noah"] = format_res(res_noah)
                if "pelta" in schemes_requested:
                    res_pelta = runner.run_distributed("pelta", k=k, m=m, num_parties=num_parties, b=b)
                    results_map["pelta"] = format_res(res_pelta)
                if "hqfs" in schemes_requested:
                    res_hqfs = runner.run_distributed("hqfs", k=k, m=m, num_parties=num_parties, b=b)
                    results_map["hqfs"] = format_res(res_hqfs)
            else:
                # Fast In-Memory Local Algorithm Mode
                if "ccs25" in schemes_requested:
                    res_ccs = runner.run_local(
                        ccs_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["ccs25"] = format_res(res_ccs)
                if "noah" in schemes_requested:
                    res_noah = runner.run_local(
                        noah_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["noah"] = format_res(res_noah)
                if "pelta" in schemes_requested:
                    res_pelta = runner.run_local(
                        pelta_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["pelta"] = format_res(res_pelta)
                if "hqfs" in schemes_requested:
                    res_hqfs = runner.run_local(
                        hqfs_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["hqfs"] = format_res(res_hqfs)

            self._send_json(200, {
                "status": "ok",
                "mode": mode,
                "num_parties": num_parties,
                "malicious_ratio": malicious_ratio,
                "attack_type": attack_type,
                "k": k,
                "m": m,
                "schemes": schemes_requested,
                "results": results_map
            })

        else:
            self._send_json(404, {"error": f"Unknown API endpoint: {path}"})


def run():
    ensure_ccs_initialized(num_parties=10, k=32, m=10)
    ensure_pelta_initialized(num_parties=10, m=10)
    ensure_hqfs_initialized(num_parties=10, m=10)
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
