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
import signal
import subprocess
import numpy as np
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
from schemes.ot25_scheme import OT25ThFHEScheme
from schemes.ajax_scheme import AjaxThFHEScheme
from schemes.bs23_scheme import BS23ThFHEScheme
from schemes.ps24_scheme import PS24ThFHEScheme
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
    "hqfs_simd_slot_count": 4,
    # Noah's Ark state
    "noah_scheme": None,
    "noah_setup_ms": 0.0,
    "noah_keygen_ms": 0.0,
    "noah_prep_ms": 0.0,
    # OT25 state
    "ot25_scheme": None,
    "ot25_setup_ms": 0.0,
    "ot25_keygen_ms": 0.0,
    "ot25_prep_ms": 0.0,
    # Ajax state
    "ajax_scheme": None,
    "ajax_setup_ms": 0.0,
    "ajax_keygen_ms": 0.0,
    "ajax_prep_ms": 0.0,
    # BS23 state
    "bs23_scheme": None,
    "bs23_setup_ms": 0.0,
    "bs23_keygen_ms": 0.0,
    "bs23_prep_ms": 0.0,
    # PS24 state
    "ps24_scheme": None,
    "ps24_setup_ms": 0.0,
    "ps24_keygen_ms": 0.0,
    "ps24_prep_ms": 0.0
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


def ensure_noah_initialized(num_parties: int = 10, m: int = 10) -> BaselineNoiseFloodingScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    nscheme: BaselineNoiseFloodingScheme = LIVE_LAB.get("noah_scheme")
    if nscheme is None or nscheme.num_parties != num_parties or nscheme.m != m:
        nscheme = BaselineNoiseFloodingScheme()
        t0 = time.perf_counter()
        nscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        nscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        nscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["noah_scheme"] = nscheme
        LIVE_LAB["noah_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["noah_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["noah_prep_ms"] = round(t_prep, 3)
    return nscheme


def ensure_ot25_initialized(num_parties: int = 10, m: int = 10) -> OT25ThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    otscheme: OT25ThFHEScheme = LIVE_LAB.get("ot25_scheme")
    if otscheme is None or otscheme.num_parties != num_parties or otscheme.m != m:
        otscheme = OT25ThFHEScheme()
        t0 = time.perf_counter()
        otscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        otscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        otscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["ot25_scheme"] = otscheme
        LIVE_LAB["ot25_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["ot25_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["ot25_prep_ms"] = round(t_prep, 3)
    return otscheme


def ensure_ajax_initialized(num_parties: int = 10, m: int = 10) -> AjaxThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    ajscheme: AjaxThFHEScheme = LIVE_LAB.get("ajax_scheme")
    if ajscheme is None or ajscheme.num_parties != num_parties or ajscheme.m != m:
        ajscheme = AjaxThFHEScheme()
        t0 = time.perf_counter()
        ajscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        ajscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        ajscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["ajax_scheme"] = ajscheme
        LIVE_LAB["ajax_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["ajax_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["ajax_prep_ms"] = round(t_prep, 3)
    return ajscheme


def ensure_bs23_initialized(num_parties: int = 10, m: int = 10) -> BS23ThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    bscheme: BS23ThFHEScheme = LIVE_LAB.get("bs23_scheme")
    if bscheme is None or bscheme.num_parties != num_parties or bscheme.m != m:
        bscheme = BS23ThFHEScheme()
        t0 = time.perf_counter()
        bscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        bscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        bscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["bs23_scheme"] = bscheme
        LIVE_LAB["bs23_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["bs23_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["bs23_prep_ms"] = round(t_prep, 3)
    return bscheme


def ensure_ps24_initialized(num_parties: int = 10, m: int = 10) -> PS24ThFHEScheme:
    num_parties = max(10, min(1000, int(num_parties)))
    pscheme: PS24ThFHEScheme = LIVE_LAB.get("ps24_scheme")
    if pscheme is None or pscheme.num_parties != num_parties or pscheme.m != m:
        pscheme = PS24ThFHEScheme()
        t0 = time.perf_counter()
        pscheme.setup(k=32, m=m, num_parties=num_parties)
        t_setup = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        pscheme.keygen()
        t_keygen = (time.perf_counter() - t1) * 1000.0

        t2 = time.perf_counter()
        pscheme.preprocess()
        t_prep = (time.perf_counter() - t2) * 1000.0

        LIVE_LAB["ps24_scheme"] = pscheme
        LIVE_LAB["ps24_setup_ms"] = round(t_setup, 3)
        LIVE_LAB["ps24_keygen_ms"] = round(t_keygen, 3)
        LIVE_LAB["ps24_prep_ms"] = round(t_prep, 3)
    return pscheme


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


def normalize_hqfs_ciphertext(raw_ct: Any, hscheme: HQFSThFHEScheme):
    hqfs = hscheme.hqfs
    def _to_rns_pair(u_raw, v_raw):
        u_arr = [[np.array(limb, dtype=np.int64) for limb in poly] for poly in u_raw]
        v_arr = [np.array(limb, dtype=np.int64) for limb in v_raw]
        return u_arr, v_arr
    if isinstance(raw_ct, dict) and "u" in raw_ct and "v" in raw_ct:
        return _to_rns_pair(raw_ct["u"], raw_ct["v"])
    if (
        isinstance(raw_ct, list)
        and len(raw_ct) == 2
        and isinstance(raw_ct[0], list)
        and isinstance(raw_ct[1], list)
        and len(raw_ct[0]) == hqfs.n_glwe
    ):
        return _to_rns_pair(raw_ct[0], raw_ct[1])
    return hqfs.encrypt(12)


def normalize_noah_ciphertext(raw_vec: Any, nscheme: BaselineNoiseFloodingScheme) -> List[int]:
    target_len = nscheme.n_dim + 1
    q = nscheme.lwe.q
    if isinstance(raw_vec, list) and raw_vec:
        vec = [int(x) % q for x in raw_vec]
        if len(vec) < target_len:
            vec = vec + [0] * (target_len - len(vec))
        return vec[:target_len]
    return nscheme.encrypt(12)[0]


def normalize_ot25_ciphertext(raw_ct: Any, otscheme: OT25ThFHEScheme) -> Any:
    if otscheme.ot25 is None or otscheme.ot25.s is None:
        otscheme.keygen()
    q = otscheme.ot25.Q
    if isinstance(raw_ct, (list, tuple)) and len(raw_ct) == 2:
        a_raw = raw_ct[0]
        b_raw = raw_ct[1]
        if isinstance(a_raw, (list, tuple, np.ndarray)):
            a_vec = np.array(([int(x) % q for x in a_raw] + [0] * otscheme.n_dim)[:otscheme.n_dim], dtype=np.int64)
            b_val = int(b_raw) % q
            return (a_vec, b_val)
    ct, _ = otscheme.encrypt(12)
    return ct


def normalize_ajax_ciphertext(raw_ct: Any, ajscheme: AjaxThFHEScheme) -> Any:
    if ajscheme.ajax is None or ajscheme.ajax.s is None:
        ajscheme.keygen()
    q = ajscheme.ajax.q
    if isinstance(raw_ct, (list, tuple)) and len(raw_ct) == 2:
        a_raw = raw_ct[0]
        b_raw = raw_ct[1]
        if isinstance(a_raw, (list, tuple, np.ndarray)):
            a_vec = np.array(([int(x) % q for x in a_raw] + [0] * ajscheme.n_dim)[:ajscheme.n_dim], dtype=np.int64)
            b_val = int(b_raw) % q
            return (a_vec, b_val)
    ct, _ = ajscheme.encrypt(3)
    return ct


def normalize_bs23_ciphertext(raw_ct: Any, bscheme: BS23ThFHEScheme) -> Any:
    if bscheme.bs23 is None or bscheme.bs23.s is None:
        bscheme.keygen()
    q = bscheme.bs23.q
    if isinstance(raw_ct, (list, tuple)) and len(raw_ct) == 2:
        a_raw, b_raw = raw_ct[0], raw_ct[1]
        if isinstance(a_raw, (list, tuple, np.ndarray)):
            a_vec = np.array(([int(x) % q for x in a_raw] + [0] * bscheme.n_dim)[:bscheme.n_dim], dtype=object)
            return (a_vec, int(b_raw) % q)
    ct, _ = bscheme.encrypt(3)
    return ct


def normalize_ps24_ciphertext(raw_ct: Any, pscheme: PS24ThFHEScheme) -> Any:
    if pscheme.ps24 is None or pscheme.ps24.s is None:
        pscheme.keygen()
    Q = pscheme.ps24.Q
    if isinstance(raw_ct, (list, tuple)) and len(raw_ct) == 2:
        a_raw, b_raw = raw_ct[0], raw_ct[1]
        if isinstance(a_raw, (list, tuple, np.ndarray)):
            a_vec = np.array(([int(x) % Q for x in a_raw] + [0] * pscheme.n_dim)[:pscheme.n_dim], dtype=object)
            return (a_vec, int(b_raw) % Q)
    ct, _ = pscheme.encrypt(3)
    return ct


def json_serialize_fallback(o):
    if hasattr(o, "tolist"):
        return o.tolist()
    if hasattr(o, "item"):
        return o.item()
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    return str(o)


class ThFHEWebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def _send_json(self, status: int, payload: Dict[str, Any]):
        body = json.dumps(payload, default=json_serialize_fallback).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # Generic single-stage lab API shared by BS23 and PS24 laboratories
    # ------------------------------------------------------------------
    def _lab_stage_generic(self, req: Dict[str, Any], key: str):
        is_bs = (key == "bs23")
        tag = "BS23" if is_bs else "PS24"
        ensure_fn = ensure_bs23_initialized if is_bs else ensure_ps24_initialized
        normalize_fn = normalize_bs23_ciphertext if is_bs else normalize_ps24_ciphertext
        stage = req.get("stage", "run_all")
        num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
        malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
        attack_type = req.get("attack_type", "none")
        m_bits = int(req.get("m", LIVE_LAB["m"]))
        xs = ensure_fn(num_parties=num_parties, m=m_bits)
        core = xs.bs23 if is_bs else xs.ps24
        p_mod = xs.p

        if stage == "setup":
            t0 = time.perf_counter()
            params = xs.setup(k=32, m=m_bits, num_parties=num_parties)
            ms = round((time.perf_counter() - t0) * 1000.0, 3)
            LIVE_LAB[f"{key}_setup_ms"] = ms
            xs.keygen()
            core = xs.bs23 if is_bs else xs.ps24
            m1_val = int(req.get("m1", 12)) % p_mod
            m2_val = int(req.get("m2", 25)) % p_mod
            c1, _ = xs.encrypt(m1_val)
            c2, _ = xs.encrypt(m2_val)
            self._send_json(200, {
                "status": "ok", "stage": "setup", "time_ms": ms, "t_space": p_mod,
                "params": params, "c1": [c1[0], c1[1]], "c2": [c2[0], c2[1]]
            })

        elif stage == "keygen":
            t0 = time.perf_counter()
            kg_info = xs.keygen()
            ms = round((time.perf_counter() - t0) * 1000.0, 3)
            LIVE_LAB[f"{key}_keygen_ms"] = ms
            m1_val = int(req.get("m1", 12)) % p_mod
            m2_val = int(req.get("m2", 25)) % p_mod
            c1, _ = xs.encrypt(m1_val)
            c2, _ = xs.encrypt(m2_val)
            self._send_json(200, {
                "status": "ok", "stage": "keygen", "time_ms": ms, "t_space": p_mod,
                "keygen_info": kg_info, "c1": [c1[0], c1[1]], "c2": [c2[0], c2[1]]
            })

        elif stage == "preprocess":
            t0 = time.perf_counter()
            prep_data = xs.preprocess()
            ms = round((time.perf_counter() - t0) * 1000.0, 3)
            LIVE_LAB[f"{key}_prep_ms"] = ms
            self._send_json(200, {
                "status": "ok", "stage": "preprocess", "time_ms": ms, "t_space": p_mod,
                "prep_data": prep_data, "offline_metrics": xs.get_offline_metrics(prep_data)
            })

        elif stage == "encrypt":
            m1_val = int(req.get("m1", 3)) % p_mod
            m2_val = int(req.get("m2", 2)) % p_mod
            t0 = time.perf_counter()
            c1, _ = xs.encrypt(m1_val)
            c2, _ = xs.encrypt(m2_val)
            ms = round((time.perf_counter() - t0) * 1000.0, 4)
            n1 = core.noise_of(c1, m1_val)
            n2 = core.noise_of(c2, m2_val)
            self._send_json(200, {
                "status": "ok", "stage": "encrypt", "time_ms": ms, "t_space": p_mod,
                "m1": m1_val, "m2": m2_val, "c1": [c1[0], c1[1]], "c2": [c2[0], c2[1]],
                "fresh_noise": [int(n1), int(n2)], "Delta": int(core.Delta), "modulus_bits": int(core.M.bit_length())
            })

        elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
            m1_val = int(req.get("m1", 3)) % p_mod
            m2_val = int(req.get("m2", 2)) % p_mod
            if stage == "run_all" and not req.get("c1"):
                c1, _ = xs.encrypt(m1_val)
                c2, _ = xs.encrypt(m2_val)
            else:
                c1 = normalize_fn(req.get("c1", []), xs)
                c2 = normalize_fn(req.get("c2", []), xs)
                m1_val = core.decrypt_direct(c1)
                m2_val = core.decrypt_direct(c2)
            op_mode = req.get("op_mode", "eval_mul")

            t0 = time.perf_counter()
            if op_mode == "eval_mul":
                ct_eval = xs.eval_mul(c1, c2)
                expected_mu = (m1_val * m2_val) % p_mod
                op_label = f"{tag} 同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
            elif op_mode == "eval_add":
                ct_eval = xs.eval_add(c1, c2)
                expected_mu = (m1_val + m2_val) % p_mod
                op_label = f"{tag} 同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
            elif op_mode == "dec_1":
                ct_eval = c1
                expected_mu = m1_val
                op_label = f"{tag} 單獨解密 Dec(c₁) (T={p_mod})"
            else:
                ct_eval = c2
                expected_mu = m2_val
                op_label = f"{tag} 單獨解密 Dec(c₂) (T={p_mod})"
            eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            eval_noise = int(core.noise_of(ct_eval, expected_mu))

            if stage == "eval":
                self._send_json(200, {
                    "status": "ok", "stage": "eval", "time_ms": eval_ms, "op_label": op_label,
                    "t_space": p_mod, "ct_eval": [ct_eval[0], ct_eval[1]], "expected_mu": expected_mu,
                    "eval_noise": eval_noise, "Delta": int(core.Delta)
                })
                return

            mu_dec, pdec_ms, agg_ms = xs.decrypt_with_stages(
                ct_eval, malicious_ratio=malicious_ratio, attack_type=attack_type,
            )
            is_tampered = (malicious_ratio > 0 and attack_type != "none")
            verified = (mu_dec == expected_mu)
            self._send_json(200, {
                "status": "ok", "stage": stage, "t_space": p_mod, "op_mode": op_mode, "op_label": op_label,
                "num_parties": num_parties, "malicious_ratio": malicious_ratio, "attack_type": attack_type,
                "m1": m1_val, "m2": m2_val, "expected_plaintext": expected_mu,
                "decrypted_plaintext": mu_dec, "verified": verified, "is_tampered": is_tampered,
                "eval_noise": eval_noise, "Delta": int(core.Delta),
                "audit_info": xs.last_audit,
                "timings": {
                    "setup_time_ms": LIVE_LAB[f"{key}_setup_ms"],
                    "keygen_time_ms": LIVE_LAB[f"{key}_keygen_ms"],
                    "prep_time_ms": LIVE_LAB[f"{key}_prep_ms"],
                    "eval_time_ms": eval_ms,
                    "partial_dec_time_ms": round(pdec_ms, 3),
                    "agg_time_ms": round(agg_ms, 3),
                    "total_online_ms": round(pdec_ms + agg_ms, 3)
                }
            })

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
            LIVE_LAB["noah_scheme"] = None
            LIVE_LAB["ot25_scheme"] = None
            LIVE_LAB["ajax_scheme"] = None
            LIVE_LAB["bs23_scheme"] = None
            LIVE_LAB["ps24_scheme"] = None
            scheme = ensure_ccs_initialized(num_parties=num_parties, k=k, m=m)
            pscheme = ensure_pelta_initialized(num_parties=num_parties, m=m)
            hscheme = ensure_hqfs_initialized(num_parties=num_parties, m=m)
            nscheme = ensure_noah_initialized(num_parties=num_parties, m=m)
            otscheme = ensure_ot25_initialized(num_parties=num_parties, m=m)
            ajscheme = ensure_ajax_initialized(num_parties=num_parties, m=m)
            bsscheme = ensure_bs23_initialized(num_parties=num_parties, m=m)
            psscheme = ensure_ps24_initialized(num_parties=num_parties, m=m)

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

            m1_int = int(m1_parsed if isinstance(m1_parsed, int) else m1_parsed[0])
            m2_int = int(m2_parsed if isinstance(m2_parsed, int) else m2_parsed[0])
            nct1, _ = nscheme.encrypt(m1_int)
            nct2, _ = nscheme.encrypt(m2_int)
            otct1, _ = otscheme.encrypt(m1_int)
            otct2, _ = otscheme.encrypt(m2_int)
            ajct1, _ = ajscheme.encrypt(m1_int)
            ajct2, _ = ajscheme.encrypt(m2_int)
            bsct1, _ = bsscheme.encrypt(m1_int % bsscheme.p)
            bsct2, _ = bsscheme.encrypt(m2_int % bsscheme.p)
            psct1, _ = psscheme.encrypt(m1_int % psscheme.p)
            psct2, _ = psscheme.encrypt(m2_int % psscheme.p)

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
                "noah_setup_ms": LIVE_LAB["noah_setup_ms"],
                "noah_keygen_ms": LIVE_LAB["noah_keygen_ms"],
                "noah_prep_ms": LIVE_LAB["noah_prep_ms"],
                "ot25_setup_ms": LIVE_LAB["ot25_setup_ms"],
                "ot25_keygen_ms": LIVE_LAB["ot25_keygen_ms"],
                "ot25_prep_ms": LIVE_LAB["ot25_prep_ms"],
                "ajax_setup_ms": LIVE_LAB["ajax_setup_ms"],
                "ajax_keygen_ms": LIVE_LAB["ajax_keygen_ms"],
                "ajax_prep_ms": LIVE_LAB["ajax_prep_ms"],
                "bs23_setup_ms": LIVE_LAB["bs23_setup_ms"],
                "bs23_keygen_ms": LIVE_LAB["bs23_keygen_ms"],
                "bs23_prep_ms": LIVE_LAB["bs23_prep_ms"],
                "ps24_setup_ms": LIVE_LAB["ps24_setup_ms"],
                "ps24_keygen_ms": LIVE_LAB["ps24_keygen_ms"],
                "ps24_prep_ms": LIVE_LAB["ps24_prep_ms"],
                "c1": c1,
                "c2": c2,
                "pelta_c1": [pct1[0], pct1[1]],
                "pelta_c2": [pct2[0], pct2[1]],
                "hqfs_c1": [hct1[0], hct1[1]],
                "hqfs_c2": [hct2[0], hct2[1]],
                "noah_c1": nct1,
                "noah_c2": nct2,
                "ot25_c1": [otct1[0], otct1[1]],
                "ot25_c2": [otct2[0], otct2[1]],
                "ajax_c1": [ajct1[0], ajct1[1]],
                "ajax_c2": [ajct2[0], ajct2[1]],
                "bs23_c1": [bsct1[0], bsct1[1]],
                "bs23_c2": [bsct2[0], bsct2[1]],
                "ps24_c1": [psct1[0], psct1[1]],
                "ps24_c2": [psct2[0], psct2[1]]
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
            elif target == "noah":
                nscheme = ensure_noah_initialized(num_parties=num_parties, m=m_bits)
                p_mod = nscheme.lwe.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                val = int(parsed if isinstance(parsed, int) else parsed[0])
                ct, _ = nscheme.encrypt(val)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "noah",
                    "simd_mode": False,
                    "message": val,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "ciphertext": ct,
                    "enc_time_ms": round(enc_ms, 4)
                })
            elif target == "ot25":
                otscheme = ensure_ot25_initialized(num_parties=num_parties, m=m_bits)
                p_mod = otscheme.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                val = int(parsed if isinstance(parsed, int) else parsed[0])
                ct, _ = otscheme.encrypt(val)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "ot25",
                    "simd_mode": False,
                    "message": val,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "ciphertext": [ct[0], ct[1]],
                    "enc_time_ms": round(enc_ms, 4)
                })
            elif target == "ajax":
                ajscheme = ensure_ajax_initialized(num_parties=num_parties, m=m_bits)
                p_mod = ajscheme.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                val = int(parsed if isinstance(parsed, int) else parsed[0])
                ct, _ = ajscheme.encrypt(val)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": "ajax",
                    "simd_mode": False,
                    "message": val,
                    "p_mod": p_mod,
                    "t_space": p_mod,
                    "ciphertext": [ct[0], ct[1]],
                    "enc_time_ms": round(enc_ms, 4)
                })
            elif target in ("bs23", "ps24"):
                xscheme = ensure_bs23_initialized(num_parties=num_parties, m=m_bits) if target == "bs23" else ensure_ps24_initialized(num_parties=num_parties, m=m_bits)
                p_mod = xscheme.p
                is_simd, parsed = parse_message_or_slots(req.get("message", 12), p_mod, simd_mode=simd_mode)
                t0 = time.perf_counter()
                val = int(parsed if isinstance(parsed, int) else parsed[0])
                ct, _ = xscheme.encrypt(val)
                enc_ms = (time.perf_counter() - t0) * 1000.0
                self._send_json(200, {
                    "status": "ok",
                    "target": target,
                    "simd_mode": False,
                    "message": val,
                    "p_mod": p_mod,
                    "t_space": p_mod,
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

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                raw_c1 = req.get("c1", [])
                raw_c2 = req.get("c2", [])
                op_mode = req.get("op_mode", "eval_mul")
                use_simd = simd_mode or is_ccs_simd_batch(raw_c1) or is_ccs_simd_batch(raw_c2)
                if stage == "run_all" and not raw_c1 and not raw_c2 and not use_simd:
                    _, m1_p = parse_message_or_slots(req.get("m1", 12), p_mod, simd_mode=False)
                    _, m2_p = parse_message_or_slots(req.get("m2", 25), p_mod, simd_mode=False)
                    raw_c1, _ = scheme.encrypt(int(m1_p))
                    raw_c2, _ = scheme.encrypt(int(m2_p))

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
                    aborted = bool(scheme.last_audit.get("aborted", False))
                    dec_out = "ABORT (SPDZ2^k MAC Failed)" if aborted else mu_slots
                    verified_out = False if aborted else (mu_slots == expected_mu)
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
                        "decrypted_plaintext": dec_out,
                        "expected_plaintext": expected_mu,
                        "aborted": aborted,
                        "verified": verified_out
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
                aborted = bool(scheme.last_audit.get("aborted", False))
                dec_out = "ABORT (SPDZ2^k MAC Failed)" if aborted else mu_party
                verified_out = False if aborted else (mu_party == expected_mu)
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
                    "decrypted_plaintext": dec_out,
                    "expected_plaintext": expected_mu,
                    "aborted": aborted,
                    "verified": verified_out
                })
            else:
                self._send_json(400, {"error": f"Unknown stage '{stage}' for /api/ccs/stage"})

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
                    aborted = bool(audit.get("aborted", False))
                    dec_simd_out: Any = "ABORT (Cheater Rejected)" if aborted else mu_slots
                    verified_simd = (not aborted) and bool(audit.get("schwartz_zippel_passed", False)) and (mu_slots == expected_mu)
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
                        "decrypted_plaintext": dec_simd_out,
                        "verified": verified_simd,
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
                aborted = bool(audit.get("aborted", False) or mu_party < 0)
                dec_out: Any = "ABORT (Cheater Rejected)" if aborted else mu_party
                verified_scalar = (not aborted) and bool(audit.get("schwartz_zippel_passed", False)) and (mu_party == expected_mu)
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
                    "decrypted_plaintext": dec_out,
                    "verified": verified_scalar,
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
                aborted = bool(scheme.last_audit.get("aborted", False))
                dec_out = "ABORT (SPDZ2^k MAC Failed)" if aborted else mu_slots
                verified_out = False if aborted else (mu_slots == expected_mu)

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
                    "decrypted_plaintext": dec_out,
                    "aborted": aborted,
                    "verified": verified_out,
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
            aborted = bool(scheme.last_audit.get("aborted", False))
            dec_out = "ABORT (SPDZ2^k MAC Failed)" if aborted else mu_party
            verified_out = False if aborted else (mu_party == expected_mu)

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
                "decrypted_plaintext": dec_out,
                "aborted": aborted,
                "verified": verified_out,
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
                    "rlk_info": {"B_bgv": prep_data.get("B_bgv", 0), "l_bgv": prep_data.get("l_bgv", 6)},
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

        elif path == "/api/noah/stage":
            stage = req.get("stage", "run_all")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            nscheme = ensure_noah_initialized(num_parties=num_parties, m=m_bits)
            p_mod = nscheme.lwe.p

            if stage == "setup":
                t0 = time.perf_counter()
                params = nscheme.setup(k=32, m=m_bits, num_parties=num_parties, malicious_ratio=malicious_ratio, attack_type=attack_type)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["noah_setup_ms"] = ms
                nscheme.keygen()
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = nscheme.encrypt(m1_val)
                c2, _ = nscheme.encrypt(m2_val)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "params": params,
                    "c1": c1,
                    "c2": c2
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = nscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["noah_keygen_ms"] = ms
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = nscheme.encrypt(m1_val)
                c2, _ = nscheme.encrypt(m2_val)
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
                prep_data = nscheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["noah_prep_ms"] = ms
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "prep_data": prep_data,
                    "offline_metrics": nscheme.get_offline_metrics()
                })

            elif stage == "encrypt":
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                t0 = time.perf_counter()
                c1, _ = nscheme.encrypt(m1_val)
                c2, _ = nscheme.encrypt(m2_val)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "m1": m1_val,
                    "m2": m2_val,
                    "c1": c1,
                    "c2": c2
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                c1 = normalize_noah_ciphertext(req.get("c1", []), nscheme)
                c2 = normalize_noah_ciphertext(req.get("c2", []), nscheme)
                m1_val = nscheme.lwe.decrypt_direct(c1)
                m2_val = nscheme.lwe.decrypt_direct(c2)
                op_mode = req.get("op_mode", "eval_mul")

                t0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = nscheme.eval_mul(c1, c2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"LWE 同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    ct_eval = nscheme.eval_add(c1, c2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"LWE 同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    ct_eval = c1
                    expected_mu = m1_val
                    op_label = f"LWE 單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    ct_eval = c2
                    expected_mu = m2_val
                    op_label = f"LWE 單獨解密 Dec(c₂) (T={p_mod})"
                eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "time_ms": eval_ms,
                        "op_label": op_label,
                        "t_space": p_mod,
                        "ct_eval": ct_eval,
                        "expected_mu": expected_mu
                    })
                    return

                mu_dec, pdec_ms, agg_ms = nscheme.decrypt_with_stages(
                    ct_eval, malicious_ratio=malicious_ratio, attack_type=attack_type
                )
                audit_info = dict(getattr(nscheme, "last_audit_info", {}))
                is_tampered = (malicious_ratio > 0 and attack_type != "none")
                aborted = bool(audit_info.get("aborted", False) or mu_dec < 0)
                verified = (not aborted) and (mu_dec == expected_mu)
                dec_out: Any = "ABORT (Exceeds t < n/3)" if aborted else mu_dec

                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "t_space": p_mod,
                    "op_mode": op_mode,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "m1": m1_val,
                    "m2": m2_val,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": dec_out,
                    "verified": verified,
                    "is_tampered": is_tampered,
                    "protocol_mode": nscheme.protocol_mode,
                    "t_threshold": nscheme.t,
                    "audit_info": audit_info,
                    "timings": {
                        "setup_time_ms": LIVE_LAB["noah_setup_ms"],
                        "keygen_time_ms": LIVE_LAB["noah_keygen_ms"],
                        "prep_time_ms": LIVE_LAB["noah_prep_ms"],
                        "eval_time_ms": eval_ms,
                        "partial_dec_time_ms": round(pdec_ms, 3),
                        "agg_time_ms": round(agg_ms, 3),
                        "total_online_ms": round(pdec_ms + agg_ms, 3)
                    }
                })

        elif path == "/api/ot25/stage":
            stage = req.get("stage", "run_all")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            otscheme = ensure_ot25_initialized(num_parties=num_parties, m=m_bits)
            p_mod = otscheme.p

            if stage == "setup":
                t0 = time.perf_counter()
                params = otscheme.setup(k=32, m=m_bits, num_parties=num_parties)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ot25_setup_ms"] = ms
                otscheme.keygen()
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = otscheme.encrypt(m1_val)
                c2, _ = otscheme.encrypt(m2_val)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "params": params,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = otscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ot25_keygen_ms"] = ms
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = otscheme.encrypt(m1_val)
                c2, _ = otscheme.encrypt(m2_val)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "keygen_info": kg_info,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage == "preprocess":
                t0 = time.perf_counter()
                prep_data = otscheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ot25_prep_ms"] = ms
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "prep_data": prep_data,
                    "offline_metrics": otscheme.get_offline_metrics(prep_data)
                })

            elif stage == "encrypt":
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                t0 = time.perf_counter()
                c1, _ = otscheme.encrypt(m1_val)
                c2, _ = otscheme.encrypt(m2_val)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "m1": m1_val,
                    "m2": m2_val,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 7)) % p_mod
                if stage == "run_all" and not req.get("c1"):
                    c1, _ = otscheme.encrypt(m1_val)
                    c2, _ = otscheme.encrypt(m2_val)
                else:
                    c1 = normalize_ot25_ciphertext(req.get("c1", []), otscheme)
                    c2 = normalize_ot25_ciphertext(req.get("c2", []), otscheme)
                    m1_val = otscheme.ot25.decrypt_direct(c1)
                    m2_val = otscheme.ot25.decrypt_direct(c2)
                op_mode = req.get("op_mode", "eval_mul")

                t0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = otscheme.eval_mul(c1, c2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"OT25 LWE 同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    ct_eval = otscheme.eval_add(c1, c2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"OT25 LWE 同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    ct_eval = c1
                    expected_mu = m1_val
                    op_label = f"OT25 單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    ct_eval = c2
                    expected_mu = m2_val
                    op_label = f"OT25 單獨解密 Dec(c₂) (T={p_mod})"
                eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "time_ms": eval_ms,
                        "op_label": op_label,
                        "t_space": p_mod,
                        "ct_eval": [ct_eval[0], ct_eval[1]],
                        "expected_mu": expected_mu
                    })
                    return

                mu_dec, pdec_ms, agg_ms = otscheme.decrypt_with_stages(
                    ct_eval,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type,
                )
                is_tampered = (malicious_ratio > 0 and attack_type != "none")
                verified = (mu_dec == expected_mu)

                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "t_space": p_mod,
                    "op_mode": op_mode,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "m1": m1_val,
                    "m2": m2_val,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": mu_dec,
                    "verified": verified,
                    "is_tampered": is_tampered,
                    "audit_info": otscheme.last_audit,
                    "timings": {
                        "setup_time_ms": LIVE_LAB["ot25_setup_ms"],
                        "keygen_time_ms": LIVE_LAB["ot25_keygen_ms"],
                        "prep_time_ms": LIVE_LAB["ot25_prep_ms"],
                        "eval_time_ms": eval_ms,
                        "partial_dec_time_ms": round(pdec_ms, 3),
                        "agg_time_ms": round(agg_ms, 3),
                        "total_online_ms": round(pdec_ms + agg_ms, 3)
                    }
                })

        elif path == "/api/ajax/stage":
            stage = req.get("stage", "run_all")
            num_parties = max(10, min(1000, int(req.get("num_parties", LIVE_LAB["num_parties"]))))
            malicious_ratio = max(0, min(49, int(req.get("malicious_ratio", 0))))
            attack_type = req.get("attack_type", "none")
            m_bits = int(req.get("m", LIVE_LAB["m"]))
            ajscheme = ensure_ajax_initialized(num_parties=num_parties, m=m_bits)
            p_mod = ajscheme.p

            if stage == "setup":
                t0 = time.perf_counter()
                params = ajscheme.setup(k=32, m=m_bits, num_parties=num_parties)
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ajax_setup_ms"] = ms
                ajscheme.keygen()
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = ajscheme.encrypt(m1_val)
                c2, _ = ajscheme.encrypt(m2_val)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "setup",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "params": params,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage == "keygen":
                t0 = time.perf_counter()
                kg_info = ajscheme.keygen()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ajax_keygen_ms"] = ms
                m1_val = int(req.get("m1", 12)) % p_mod
                m2_val = int(req.get("m2", 25)) % p_mod
                c1, _ = ajscheme.encrypt(m1_val)
                c2, _ = ajscheme.encrypt(m2_val)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "keygen",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "keygen_info": kg_info,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage == "preprocess":
                t0 = time.perf_counter()
                prep_data = ajscheme.preprocess()
                ms = round((time.perf_counter() - t0) * 1000.0, 3)
                LIVE_LAB["ajax_prep_ms"] = ms
                self._send_json(200, {
                    "status": "ok",
                    "stage": "preprocess",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "prep_data": prep_data,
                    "offline_metrics": ajscheme.get_offline_metrics(prep_data)
                })

            elif stage == "encrypt":
                m1_val = int(req.get("m1", 3)) % p_mod
                m2_val = int(req.get("m2", 2)) % p_mod
                t0 = time.perf_counter()
                c1, _ = ajscheme.encrypt(m1_val)
                c2, _ = ajscheme.encrypt(m2_val)
                ms = round((time.perf_counter() - t0) * 1000.0, 4)
                self._send_json(200, {
                    "status": "ok",
                    "stage": "encrypt",
                    "time_ms": ms,
                    "t_space": p_mod,
                    "m1": m1_val,
                    "m2": m2_val,
                    "c1": [c1[0], c1[1]],
                    "c2": [c2[0], c2[1]]
                })

            elif stage in ("eval", "partial_dec", "aggregate", "run_all"):
                m1_val = int(req.get("m1", 3)) % p_mod
                m2_val = int(req.get("m2", 2)) % p_mod
                if stage == "run_all" and not req.get("c1"):
                    c1, _ = ajscheme.encrypt(m1_val)
                    c2, _ = ajscheme.encrypt(m2_val)
                else:
                    c1 = normalize_ajax_ciphertext(req.get("c1", []), ajscheme)
                    c2 = normalize_ajax_ciphertext(req.get("c2", []), ajscheme)
                    m1_val = ajscheme.ajax.decrypt_direct(c1)
                    m2_val = ajscheme.ajax.decrypt_direct(c2)
                op_mode = req.get("op_mode", "eval_mul")

                t0 = time.perf_counter()
                if op_mode == "eval_mul":
                    ct_eval = ajscheme.eval_mul(c1, c2)
                    expected_mu = (m1_val * m2_val) % p_mod
                    op_label = f"Ajax 雙環同態乘法 Dec(c₁ ⊗ c₂) = ({m1_val} × {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "eval_add":
                    ct_eval = ajscheme.eval_add(c1, c2)
                    expected_mu = (m1_val + m2_val) % p_mod
                    op_label = f"Ajax 雙環同態加法 Dec(c₁ ⊕ c₂) = ({m1_val} + {m2_val}) mod {p_mod} (T={p_mod})"
                elif op_mode == "dec_1":
                    ct_eval = c1
                    expected_mu = m1_val
                    op_label = f"Ajax 單獨解密 Dec(c₁) (T={p_mod})"
                else:
                    ct_eval = c2
                    expected_mu = m2_val
                    op_label = f"Ajax 單獨解密 Dec(c₂) (T={p_mod})"
                eval_ms = round((time.perf_counter() - t0) * 1000.0, 4)

                if stage == "eval":
                    self._send_json(200, {
                        "status": "ok",
                        "stage": "eval",
                        "time_ms": eval_ms,
                        "op_label": op_label,
                        "t_space": p_mod,
                        "ct_eval": [ct_eval[0], ct_eval[1]],
                        "expected_mu": expected_mu
                    })
                    return

                mu_dec, pdec_ms, agg_ms = ajscheme.decrypt_with_stages(
                    ct_eval,
                    malicious_ratio=malicious_ratio,
                    attack_type=attack_type,
                )
                is_tampered = (malicious_ratio > 0 and attack_type != "none")
                verified = (mu_dec == expected_mu)

                self._send_json(200, {
                    "status": "ok",
                    "stage": stage,
                    "t_space": p_mod,
                    "op_mode": op_mode,
                    "op_label": op_label,
                    "num_parties": num_parties,
                    "malicious_ratio": malicious_ratio,
                    "attack_type": attack_type,
                    "m1": m1_val,
                    "m2": m2_val,
                    "expected_plaintext": expected_mu,
                    "decrypted_plaintext": mu_dec,
                    "verified": verified,
                    "is_tampered": is_tampered,
                    "audit_info": ajscheme.last_audit,
                    "timings": {
                        "setup_time_ms": LIVE_LAB["ajax_setup_ms"],
                        "keygen_time_ms": LIVE_LAB["ajax_keygen_ms"],
                        "prep_time_ms": LIVE_LAB["ajax_prep_ms"],
                        "eval_time_ms": eval_ms,
                        "partial_dec_time_ms": round(pdec_ms, 3),
                        "agg_time_ms": round(agg_ms, 3),
                        "total_online_ms": round(pdec_ms + agg_ms, 3)
                    }
                })

        elif path in ("/api/bs23/stage", "/api/ps24/stage"):
            self._lab_stage_generic(req, "bs23" if "bs23" in path else "ps24")

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
            ot25_scheme = OT25ThFHEScheme()
            ajax_scheme = AjaxThFHEScheme()
            bs23_scheme = BS23ThFHEScheme()
            ps24_scheme = PS24ThFHEScheme()

            schemes_requested = req.get("schemes", ["ccs25", "noah", "pelta", "hqfs", "ot25", "ajax", "bs23", "ps24"])
            if not isinstance(schemes_requested, list) or not schemes_requested:
                schemes_requested = ["ccs25", "noah", "pelta", "hqfs", "ot25", "ajax", "bs23", "ps24"]

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
                    res_ccs = runner.run_distributed(
                        "ccs25", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["ccs25"] = format_res(res_ccs)
                if "noah" in schemes_requested:
                    res_noah = runner.run_distributed(
                        "noah", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["noah"] = format_res(res_noah)
                if "pelta" in schemes_requested:
                    res_pelta = runner.run_distributed(
                        "pelta", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["pelta"] = format_res(res_pelta)
                if "hqfs" in schemes_requested:
                    res_hqfs = runner.run_distributed(
                        "hqfs", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["hqfs"] = format_res(res_hqfs)
                if "ot25" in schemes_requested:
                    res_ot25 = runner.run_distributed(
                        "ot25", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["ot25"] = format_res(res_ot25)
                if "ajax" in schemes_requested:
                    res_ajax = runner.run_distributed(
                        "ajax", k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type,
                    )
                    results_map["ajax"] = format_res(res_ajax)
                for _key in ("bs23", "ps24"):
                    if _key in schemes_requested:
                        _res = runner.run_distributed(
                            _key, k=k, m=m, num_parties=num_parties, b=b,
                            malicious_ratio=malicious_ratio, attack_type=attack_type,
                        )
                        results_map[_key] = format_res(_res)
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
                if "ot25" in schemes_requested:
                    res_ot25 = runner.run_local(
                        ot25_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["ot25"] = format_res(res_ot25)
                if "ajax" in schemes_requested:
                    res_ajax = runner.run_local(
                        ajax_scheme, k=k, m=m, num_parties=num_parties, b=b,
                        malicious_ratio=malicious_ratio, attack_type=attack_type
                    )
                    results_map["ajax"] = format_res(res_ajax)
                for _key, _sch in (("bs23", bs23_scheme), ("ps24", ps24_scheme)):
                    if _key in schemes_requested:
                        _res = runner.run_local(
                            _sch, k=k, m=m, num_parties=num_parties, b=b,
                            malicious_ratio=malicious_ratio, attack_type=attack_type
                        )
                        results_map[_key] = format_res(_res)

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


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def free_port_if_occupied(port: int):
    try:
        out = subprocess.check_output(["lsof", "-ti", f":{port}"], stderr=subprocess.DEVNULL).decode().strip()
        if out:
            my_pid = os.getpid()
            for line in out.splitlines():
                if not line.strip():
                    continue
                pid = int(line.strip())
                if pid != my_pid:
                    print(f"[*] 檢測到埠號 {port} 正在被舊程序 (PID {pid}) 佔用，正在嘗試自動釋放埠號...")
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
            time.sleep(0.6)
    except Exception:
        pass


def run():
    ensure_ccs_initialized(num_parties=10, k=32, m=10)
    ensure_pelta_initialized(num_parties=10, m=10)
    ensure_hqfs_initialized(num_parties=10, m=10)
    ensure_noah_initialized(num_parties=10, m=10)
    ensure_ot25_initialized(num_parties=10, m=10)
    ensure_ajax_initialized(num_parties=10, m=10)
    ensure_bs23_initialized(num_parties=10, m=10)
    ensure_ps24_initialized(num_parties=10, m=10)

    target_port = PORT
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        target_port = int(sys.argv[1])
    elif "PORT" in os.environ and os.environ["PORT"].isdigit():
        target_port = int(os.environ["PORT"])

    free_port_if_occupied(target_port)

    httpd = None
    actual_port = target_port
    candidate_ports = [target_port] + [target_port + i for i in range(1, 20)]

    for p in candidate_ports:
        try:
            httpd = ReusableHTTPServer(("0.0.0.0", p), ThFHEWebHandler)
            actual_port = p
            break
        except OSError as e:
            if e.errno in (48, 98):  # 48 on macOS, 98 on Linux
                continue
            raise

    if httpd is None:
        raise RuntimeError(f"無法在候選埠號 {candidate_ports} 綁定 Web Server，請檢查系統網路設定。")

    print("=" * 68)
    print(f"  ThFHE Lab Web Dashboard & Live Benchmark Server running at:")
    print(f"  👉 http://localhost:{actual_port}")
    if actual_port != target_port:
        print(f"  (注意: 原預設埠號 {target_port} 已被佔用，已自動切換至可用埠號 {actual_port})")
    print("=" * 68)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping web server...")
        httpd.server_close()


if __name__ == "__main__":
    run()
