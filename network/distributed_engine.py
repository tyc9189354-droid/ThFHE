#!/usr/bin/env python3
"""
================================================================================
Unified Distributed Multi-Port Socket Benchmark Engine
================================================================================
Executes true multi-port distributed Client/Server network benchmarks across
all four target papers:
  1. CCS 2025 (Zyskind et al.) - MPC Rounding
  2. Baseline Noise Flooding (Dahl et al., Noah's Ark 2023) - Statistical Smudging
  3. PELTA (Chatel et al., EPFL) - Ajtai Commitment + Shielded MFHE
  4. HQ-FS (CSF 2027, Our Work) - RNS-GLWE with full 19 RNS primes + Tree ZKP

Key Features:
  - Dynamically binds and connects N independent TCP sockets (base_port ~ base_port + N - 1)
  - True network socket payload transmission (serialization, handshake, evaluation, and verification)
  - HQ-FS uses the authentic 19 RNS primes (6 Q-primes + 13 P-primes)
  - Minimal memory footprint: zero-copy / streaming packet deletion, immediate GC, and socket cleanup
================================================================================
"""

import os
import sys
import time
import math
import socket
import struct
import pickle
import random
import secrets
import datetime
import gc
import tracemalloc
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.metrics import BenchmarkResult, OfflineMetric, OnlineMetric
from tool import (
    ToyLWE, ThresholdFHEDecryptor, PolyRing,
    PeltaMFHE, PeltaProver, PeltaVerifier, AjtaiCommitmentScheme, VerifiableAggregation,
    RNSRing, PlaintextNTTHelper, get_ntt_primes, modinv_jit,
    DecentralizedClientNode, HQFSVerifier, compute_committee_lagrange,
    HQFSSystem, uniform_poly, small_poly, encrypt, add, mul, decode_vec,
    centralized_gen_relin_rns,
    OT25ThFHE, AjaxThFHE
)

# ----------------------------------------------------------------------
# Low-Level Network Helpers
# ----------------------------------------------------------------------

def _send_packet(sock: socket.socket, data: Any) -> int:
    payload = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
    packet = struct.pack(">I", len(payload)) + payload
    sock.sendall(packet)
    n_bytes = len(packet)
    del payload, packet
    return n_bytes

def _recv_packet(sock: socket.socket) -> Tuple[Optional[Any], int]:
    raw_len = sock.recv(4)
    if not raw_len or len(raw_len) < 4:
        return None, 0
    msg_len = struct.unpack(">I", raw_len)[0]
    buf = bytearray()
    while len(buf) < msg_len:
        chunk = sock.recv(min(msg_len - len(buf), 65536))
        if not chunk:
            break
        buf.extend(chunk)
    n_bytes = 4 + len(buf)
    if len(buf) != msg_len:
        del buf
        return None, n_bytes
    data = pickle.loads(buf)
    del buf
    return data, n_bytes

def _bind_multi_ports(num_parties: int, base_port: int) -> Tuple[List[socket.socket], List[int]]:
    server_socks = []
    ports = []
    curr_port = base_port
    while len(server_socks) < num_parties:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", curr_port))
            s.listen(1)
            server_socks.append(s)
            ports.append(curr_port)
            curr_port += 1
        except OSError:
            curr_port += 10
            continue
    return server_socks, ports

def _connect_client_sockets(ports: List[int], server_socks: List[socket.socket]) -> Tuple[List[socket.socket], List[socket.socket]]:
    client_socks = []
    conns = []
    for i, port in enumerate(ports):
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect(("127.0.0.1", port))
        conn, _ = server_socks[i].accept()
        client_socks.append(c)
        conns.append(conn)
    return client_socks, conns

def _cleanup_sockets(server_socks: List[socket.socket], client_socks: List[socket.socket], conns: List[socket.socket]):
    for c in client_socks:
        try: c.close()
        except Exception: pass
    for conn in conns:
        try: conn.close()
        except Exception: pass
    for s in server_socks:
        try: s.close()
        except Exception: pass
    gc.collect()


# ----------------------------------------------------------------------
# 1. CCS 2025 (Zyskind et al.) Distributed Multi-Port Engine
# ----------------------------------------------------------------------

def run_ccs25_distributed(
    num_parties: int = 10,
    k: int = 64,
    m: int = 1,
    b: int = 8,
    base_port: int = 14100,
    iterations: int = 3,
    malicious_ratio: float = 0.0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    """
    CCS 2025 (Zyskind et al.) Distributed Multi-Port Socket Benchmark:
    Executes N-party F_ABB additive secret sharing with SPDZ2^k (s=64) SingleCheck MAC verification
    and 3-round MPC rounding (Mod_{l,k} / LTRand_{l,k}: Round 1 Open([z+r]_l), Round 2 Sign-gate lookup
    + Open([y+r']_{d+1}), Round 3 ModLTZ lookup + Open([z-e]_k)). Aborts on any MAC discrepancy.
    """
    print(f"\n[+] Running DISTRIBUTED Multi-Port Socket Benchmark: 'CCS 2025' (N={num_parties}, Ports={base_port}..{base_port+num_parties-1})")
    tracemalloc.start()
    total_tx = 0
    total_rx = 0
    rng = secrets.SystemRandom()

    t_start_setup = time.perf_counter()
    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    lwe = ToyLWE(n_dim=16, k=k, m=m, num_parties=num_parties)
    decryptor = ThresholdFHEDecryptor(k=k, m=m, b=b, num_parties=num_parties)
    s_mac = 64
    alpha_mac = rng.randrange(1 << s_mac) | 1
    mod_l = 1 << decryptor.l
    mod_k = decryptor.q
    d = math.ceil(decryptor.l / decryptor.b)
    d_plus_1 = d + 1
    mod_d = 1 << d_plus_1
    mod_mac_l = 1 << (decryptor.l + s_mac)
    mod_mac_d = 1 << (d_plus_1 + s_mac)
    mod_mac_k = 1 << (decryptor.k + s_mac)
    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    # KeyGen over N Sockets: distribute each party's local s_i (retained in party_local_state[i])
    t_start_kg = time.perf_counter()
    party_local_state: Dict[int, Dict[str, Any]] = {}
    for i in range(num_parties):
        total_tx += _send_packet(conns[i], {
            "cmd": "KEYGEN_INIT",
            "node_id": i,
            "q": lwe.q,
            "n": 16,
            "s_mac": s_mac,
            "s_share": lwe.party_shares[i],
        })
        req, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b

        party_local_state[i] = {
            "s_share": list(req["s_share"]),
            "q": int(req["q"]),
            "sessions": [],
        }
        # Client confirms key readiness with commitment (never sends raw s_i upstream)
        total_tx += _send_packet(client_socks[i], {
            "cmd": "SHARE_ACK",
            "node_id": i,
            "commit": sum(req["s_share"]) % mod_k,
        })
        resp, rx_b = _recv_packet(conns[i])
        total_rx += rx_b
        del req, resp
    t_keygen_ms = (time.perf_counter() - t_start_kg) * 1000.0

    # Offline Prep over N Sockets: 2 fresh PreprocessedGates sessions ([r]_k, [r']_{d+1}, Sign tables, ModLTZ table)
    t_start_prep = time.perf_counter()
    gates_list = [decryptor.preprocess(), decryptor.preprocess()]

    def _split_additive(val: int, modulus: int) -> List[int]:
        sh = [rng.randrange(modulus) for _ in range(num_parties - 1)]
        sh.append((val - sum(sh)) % modulus)
        return sh

    for op_idx, gates in enumerate(gates_list):
        r_total = gates.r_combined.value % mod_l if gates.r_combined else 0
        r_shares_k = _split_additive(r_total, mod_k)

        r_modltz_var, modltz_table = gates.modltz_gate
        rp_total = r_modltz_var.value % mod_d
        rp_shares_d = _split_additive(rp_total, mod_d)

        # Share each Sign lookup table across N parties over Z_{2^{d+1}}
        sign_tables_per_party: List[List[List[int]]] = [[] for _ in range(num_parties)]
        for j_idx in range(d):
            _, table_j = gates.sign_gates[j_idx]
            party_tbl_j = [[] for _ in range(num_parties)]
            for entry in table_j:
                entry_sh = _split_additive(entry.value % mod_d, mod_d)
                for p_i in range(num_parties):
                    party_tbl_j[p_i].append(entry_sh[p_i])
            for p_i in range(num_parties):
                sign_tables_per_party[p_i].append(party_tbl_j[p_i])

        # Share ModLTZ lookup table across N parties over Z_{2^m}
        modltz_per_party: List[List[int]] = [[] for _ in range(num_parties)]
        for entry in modltz_table:
            entry_sh = _split_additive(entry.value % decryptor.p, decryptor.p)
            for p_i in range(num_parties):
                modltz_per_party[p_i].append(entry_sh[p_i])

        for p_i in range(num_parties):
            pkg = {
                "cmd": "PREP_GATE_SHARES",
                "session": op_idx,
                "r_share": r_shares_k[p_i],
                "rp_share": rp_shares_d[p_i],
                "sign_tables": sign_tables_per_party[p_i],
                "modltz_table": modltz_per_party[p_i],
            }
            total_tx += _send_packet(conns[p_i], pkg)
            rcv, rx_b = _recv_packet(client_socks[p_i])
            total_rx += rx_b
            party_local_state[p_i]["sessions"].append({
                "r_share": rcv["r_share"],
                "rp_share": rcv["rp_share"],
                "sign_tables": rcv["sign_tables"],
                "modltz_table": rcv["modltz_table"],
            })
            del pkg, rcv
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt & Homomorphic Eval (arbitrary m >= 1)
    v1 = 3 % lwe.p if lwe.p > 2 else 1
    v2 = 5 % lwe.p if lwe.p > 2 else 1
    v0 = 0
    ct1, _ = lwe.encrypt(v1)
    ct2, _ = lwe.encrypt(v2)
    ct0, _ = lwe.encrypt(v0)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = lwe.eval_add(ct1, ct0)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = lwe.eval_mul(ct1, ct2)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    mr = max(0, min(49, int(malicious_ratio or 0)))
    at = attack_type or "none"
    mal_count = (num_parties * mr) // 100 if (mr > 0 and at != "none") else 0
    mal_set = set(rng.sample(range(num_parties), mal_count)) if mal_count > 0 else set()

    # Decryption measurements over sockets (3 rounds Mod_{l,k} + SPDZ2^k MAC check)
    pdec_times = []
    agg_times = []
    correctness = True
    aborted = False
    detected_malicious: set = set()
    shift = 1 << (decryptor.l - 1)
    expected_add = (v1 + v0) % lwe.p
    expected_mul = (v1 * v2) % lwe.p

    for op_idx, (target_ct, expected) in enumerate([(ct_add, expected_add), (ct_mul, expected_mul)]):
        t0 = time.perf_counter()
        submitted_z_mask: List[int] = []
        honest_r1_macs: List[int] = []
        z_party_local: List[int] = []

        # Round 1: Local inner product + masked Open([z + r]_l) + SPDZ2^k SingleCheck
        for i in range(num_parties):
            total_tx += _send_packet(conns[i], {"cmd": "PDEC_R1_REQ", "c": target_ct, "session": op_idx})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            st = party_local_state[i]
            s_i = st["s_share"]
            sess = st["sessions"][op_idx]
            r_i = sess["r_share"]
            c_vec = req["c"]

            z_i = sum(c_vec[j] * s_i[j] for j in range(len(s_i))) % mod_k
            if i == 0:
                z_i = (z_i + c_vec[len(s_i)] + shift) % mod_k
            z_party_local.append(z_i)

            honest_zm = ((z_i % mod_l) + (r_i % mod_l)) % mod_l
            mac_r1 = (alpha_mac * honest_zm) % mod_mac_l
            honest_r1_macs.append(mac_r1)

            zm_sub = honest_zm
            if i in mal_set:
                if at == "noise_flooding":
                    zm_sub = (zm_sub + (decryptor.L >> 1) + 99999) % mod_l
                elif at == "invalid_key_share":
                    bad_s = [rng.randint(5, 50) for _ in range(len(s_i))]
                    z_bad = sum(c_vec[j] * bad_s[j] for j in range(len(s_i))) % mod_k
                    if i == 0:
                        z_bad = (z_bad + c_vec[len(s_i)] + shift) % mod_k
                    zm_sub = ((z_bad % mod_l) + (r_i % mod_l)) % mod_l
                elif at == "share_tampering":
                    zm_sub = (zm_sub ^ ((1 << max(1, decryptor.l - 2)) - 1)) % mod_l
                elif at == "equivocation_eval":
                    zm_sub = (zm_sub + rng.randint(1000, mod_l - 1)) % mod_l

            total_tx += _send_packet(client_socks[i], {"cmd": "PDEC_R1_RESP", "zm": zm_sub, "mac": mac_r1})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b

            if ((alpha_mac * resp["zm"]) % mod_mac_l) != resp["mac"]:
                detected_malicious.add(i + 1)
            submitted_z_mask.append(resp["zm"])
            del req, resp

        r1_sum_mac = (sum(honest_r1_macs) - alpha_mac * sum(submitted_z_mask)) % mod_mac_l
        if detected_malicious or r1_sum_mac != 0:
            aborted = True
            correctness = False
            pdec_times.append((time.perf_counter() - t0) * 1000.0)
            agg_times.append(0.0)
            break

        z_prime = sum(submitted_z_mask) % mod_l

        # Base-B digit decomposition of public z_prime
        z_tmp = z_prime
        z_digits = []
        for j_idx in range(d):
            cur_b = decryptor.b if j_idx < d - 1 else (decryptor.l - (d - 1) * decryptor.b)
            z_digits.append(z_tmp & ((1 << cur_b) - 1))
            z_tmp >>= cur_b

        # Round 2: Parties locally evaluate shared Sign tables & Open([y + r']_{d+1})
        y_mask_shares: List[int] = []
        y_macs: List[int] = []
        for i in range(num_parties):
            total_tx += _send_packet(conns[i], {"cmd": "PDEC_R2_REQ", "digits": z_digits, "session": op_idx})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            sess = party_local_state[i]["sessions"][op_idx]
            y_i = sum((1 << j_idx) * sess["sign_tables"][j_idx][req["digits"][j_idx]] for j_idx in range(d)) % mod_d
            ym_i = (y_i + sess["rp_share"]) % mod_d
            mac_r2 = (alpha_mac * ym_i) % mod_mac_d

            total_tx += _send_packet(client_socks[i], {"cmd": "PDEC_R2_RESP", "ym": ym_i, "mac": mac_r2})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b
            y_mask_shares.append(resp["ym"])
            y_macs.append(resp["mac"])
            del req, resp

        if (sum(y_macs) - alpha_mac * sum(y_mask_shares)) % mod_mac_d != 0:
            aborted = True
            correctness = False
            pdec_times.append((time.perf_counter() - t0) * 1000.0)
            agg_times.append(0.0)
            break

        y_prime = sum(y_mask_shares) % mod_d
        t_pdec_step = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_pdec_step)

        # Round 3: Parties look up [u_i]_m = modltz_table_i[y_prime], form [z - e]_k, Open & MAC check
        t1 = time.perf_counter()
        mu_shares: List[int] = []
        mu_macs: List[int] = []
        for i in range(num_parties):
            total_tx += _send_packet(conns[i], {"cmd": "PDEC_R3_REQ", "y_prime": y_prime, "z_prime": z_prime, "session": op_idx})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            sess = party_local_state[i]["sessions"][op_idx]
            u_i = sess["modltz_table"][req["y_prime"]]
            e_i = ((req["z_prime"] if i == 0 else 0) - sess["r_share"] + (1 << decryptor.l) * u_i) % mod_k
            mu_i = (z_party_local[i] - e_i) % mod_k
            mac_r3 = (alpha_mac * mu_i) % mod_mac_k

            total_tx += _send_packet(client_socks[i], {"cmd": "PDEC_R3_RESP", "mu": mu_i, "mac": mac_r3})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b
            mu_shares.append(resp["mu"])
            mu_macs.append(resp["mac"])
            del req, resp

        if (sum(mu_macs) - alpha_mac * sum(mu_shares)) % mod_mac_k != 0:
            aborted = True
            correctness = False
            agg_times.append((time.perf_counter() - t1) * 1000.0)
            break

        mu_prime = sum(mu_shares) % mod_k
        dec = (mu_prime // decryptor.L) % decryptor.p
        t_agg_step = (time.perf_counter() - t1) * 1000.0
        agg_times.append(t_agg_step)
        if dec != expected:
            correctness = False

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mean_pdec = sum(pdec_times) / len(pdec_times) if pdec_times else 0.0
    mean_agg = sum(agg_times) / len(agg_times) if agg_times else 0.0
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="CCS25_MPC_Rounding",
        k=k,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            gate_storage_bits=getattr(gates_list[0].r_combined, "length", 312) if gates_list[0].r_combined else 312,
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=3,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)},
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "security_model": "SPDZ2^k UC-Secure with Abort (s=64)",
            "malicious_injected": len(mal_set),
            "malicious_detected": len(detected_malicious),
            "aborted": aborted,
        },
    )


# ----------------------------------------------------------------------
# 2. Noah's Ark (Dahl et al., 2023) Distributed Multi-Port Engine
# ----------------------------------------------------------------------

def run_noah_distributed(
    num_parties: int = 10,
    k: int = 64,
    m: int = 1,
    base_port: int = 14200,
    iterations: int = 3,
    malicious_ratio: int = 0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    from schemes.baseline_noise_flooding import BaselineNoiseFloodingScheme

    print(
        f"\n[+] Running DISTRIBUTED Multi-Port Socket Benchmark: 'Noah's Ark' "
        f"(N={num_parties}, m={m}, Ports={base_port}..{base_port+num_parties-1}, mal={malicious_ratio}%)"
    )
    tracemalloc.start()
    total_tx = 0
    total_rx = 0

    t_start_setup = time.perf_counter()
    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    noah = BaselineNoiseFloodingScheme()
    noah.setup(k=k, m=m, num_parties=num_parties, malicious_ratio=malicious_ratio, attack_type=attack_type)
    gr = noah.gr
    lwe = noah.lwe
    t_thresh = noah.t
    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    # KeyGen over N Sockets: distribute ONLY Galois Ring Shamir shares [s'_j]^{<t, Q>}
    t_start_kg = time.perf_counter()
    noah.keygen()
    for i in range(num_parties):
        total_tx += _send_packet(
            conns[i],
            {"cmd": "INIT_GR", "K": noah.K, "d": noah.galois_deg, "t": t_thresh, "protocol": noah.protocol_mode},
        )
        _, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b

        s_gr_i = noah.party_key_shares[i]
        total_tx += _send_packet(client_socks[i], {"cmd": "SHARE_GR_KEY", "s_gr": s_gr_i})
        _, rx_b = _recv_packet(conns[i])
        total_rx += rx_b
    t_keygen_ms = (time.perf_counter() - t_start_kg) * 1000.0

    # Offline Preprocessing: PRSS (Protocol 1) or Hensel Shared Bits (Protocol 2)
    t_start_prep = time.perf_counter()
    noah.preprocess()
    # Distribute initial offline mask shares [E]_i^{<t, Q>} over sockets
    for i in range(num_parties):
        e_i = noah._prep_mask_pool[0][i] if noah._prep_mask_pool else gr.zero()
        total_tx += _send_packet(conns[i], {"cmd": "OFFLINE_MASK", "e_share": e_i})
        _, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt & Homomorphic Eval (works for arbitrary m >= 1)
    p_mod = lwe.p
    v1 = 3 % p_mod if p_mod > 4 else 1
    v2 = 5 % p_mod if p_mod > 4 else 1
    ct1, m1 = noah.encrypt(v1)
    ct2, m2 = noah.encrypt(v2)
    ct0, m0 = noah.encrypt(0)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = noah.eval_add(ct1, ct0)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = noah.eval_mul(ct1, ct2)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    expected_add = (m1 + m0) % p_mod
    expected_mul = (m1 * m2) % p_mod

    mal_count = int(round(num_parties * malicious_ratio / 100.0)) if (malicious_ratio > 0 and attack_type != "none") else 0
    mal_count = min(num_parties, max(0, mal_count))
    mal_indices = set(secrets.SystemRandom().sample(range(num_parties), mal_count)) if mal_count > 0 else set()

    # Partial Decryption + RobustOpen over Sockets
    pdec_times = []
    agg_times = []
    correctness = True
    rejected_total: List[int] = []
    aborted_any = False

    for target_ct, expected in [(ct_add, expected_add), (ct_mul, expected_mul)]:
        t0 = time.perf_counter()
        a_prime, b_prime = lwe.switch_n_squash(target_ct)
        e_shares = noah._consume_mask_shares()
        b_prime_gr = gr.from_int(b_prime)

        shares_recv: List[Tuple[int, ...]] = []
        for i in range(num_parties):
            total_tx += _send_packet(conns[i], {"cmd": "SQUASH_CT_REQ", "a_prime": a_prime, "b_prime": b_prime})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            k_sh = noah.party_key_shares[i]
            dot_gr = gr.zero()
            for u, au in enumerate(req["a_prime"]):
                if au:
                    dot_gr = gr.add(dot_gr, gr.mul_scalar(k_sh[u], au))
            vi = gr.add(gr.sub(gr.from_int(req["b_prime"]), dot_gr), e_shares[i])

            if i in mal_indices:
                vi = gr.zero() if attack_type == "zero_share" else gr.rand_elem()

            total_tx += _send_packet(client_socks[i], {"cmd": "GR_PARTIAL_RESP", "v_share": vi})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b
            shares_recv.append(tuple(resp["v_share"]))
            del req, resp
        t_pdec_step = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_pdec_step)

        # RobustOpen over GR(2^K, d)
        t0 = time.perf_counter()
        ok, v_open, rejected = gr.robust_open(shares_recv, t_thresh)
        t_agg_step = (time.perf_counter() - t0) * 1000.0
        agg_times.append(t_agg_step)
        if not ok or v_open is None:
            correctness = False
            aborted_any = True
        else:
            rejected_total = rejected
            Q_sq = lwe.Q_squash
            dec = ((v_open * p_mod + (Q_sq >> 1)) // Q_sq) % p_mod
            if dec != expected:
                correctness = False

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    off_info = noah.get_offline_metrics()
    mean_pdec = sum(pdec_times) / len(pdec_times)
    mean_agg = sum(agg_times) / len(agg_times)
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="Baseline_Dahl23_NoiseFlooding",
        k=noah.k,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            num_mults=off_info.get("num_mults", 0),
            gate_storage_bits=off_info.get("gate_storage_bits", 0),
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=1,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)}
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "protocol_mode": noah.protocol_mode,
            "t_threshold": t_thresh,
            "galois_deg": noah.galois_deg,
            "K_squash": noah.K,
            "malicious_injected": mal_count,
            "malicious_rejected": len(rejected_total),
            "aborted": aborted_any,
        }
    )


# ----------------------------------------------------------------------
# 3. PELTA (Chatel et al., EPFL) Distributed Multi-Port Engine
# ----------------------------------------------------------------------

def run_pelta_distributed(
    num_parties: int = 10,
    k: int = 64,
    m: int = 1,
    base_port: int = 14300,
    iterations: int = 3,
    malicious_ratio: int = 0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    from tool import PeltaMFHE, VerifiableAggregation, hash_commitment

    print(
        f"\n[+] Running DISTRIBUTED Multi-Port Socket Benchmark: 'PELTA' "
        f"(N={num_parties}, m={m}, Ports={base_port}..{base_port+num_parties-1}, mal={malicious_ratio}%)"
    )
    tracemalloc.start()
    total_tx = 0
    total_rx = 0

    t_start_setup = time.perf_counter()
    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    N_poly = 16
    p = 1 << m
    B = 4
    mfhe = PeltaMFHE(N=N_poly, q=65536, p=p, B=B, num_parties=num_parties)
    mfhe.setup(num_parties)
    ring = mfhe.ring
    prover = mfhe.prover
    verifier = mfhe.verifier
    ajtai = mfhe.ajtai
    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    # KeyGen + Ajtai Commitments on unified ternary shares s_i over N Sockets
    t_start_kg = time.perf_counter()
    mfhe.keygen()
    t_keygen_ms = (time.perf_counter() - t_start_kg) * 1000.0

    t_start_prep = time.perf_counter()
    public_c_ajtai: List[List[int]] = []
    for i in range(num_parties):
        c_ajtai_i, _ = mfhe.party_ajtai_commits[i]
        public_c_ajtai.append(c_ajtai_i)
        # Transmit public commitment ONLY (never s_i, r_i, or k_vec!)
        total_tx += _send_packet(client_socks[i], {"cmd": "AJTAI_COMMIT", "c_ajtai": c_ajtai_i})
        _, rx_b = _recv_packet(conns[i])
        total_rx += rx_b
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt & Homomorphic Eval (works for any m >= 1)
    v1 = 3 % p if p > 4 else 1
    v2 = 5 % p if p > 4 else 1
    ct1 = mfhe.encrypt(v1)
    ct2 = mfhe.encrypt(v2)
    ct0 = mfhe.encrypt(0)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = mfhe.eval_add(ct1, ct0)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = mfhe.eval_mul(ct1, ct2)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    expected_add = (v1 + 0) % p
    expected_mul = (v1 * v2) % p

    mal_count = (num_parties * int(malicious_ratio)) // 100 if (malicious_ratio > 0 and attack_type != "none") else 0
    mal_indices = set(secrets.SystemRandom().sample(range(num_parties), mal_count)) if mal_count > 0 else set()

    # Partial Dec + ZK NIZK Verify + 4-point Schwartz-Zippel Aggregation over Sockets
    pdec_times = []
    agg_times = []
    correctness = True
    rejected_nodes = set()
    aborted_any = False

    for target_ct, expected in [(ct_add, expected_add), (ct_mul, expected_mul)]:
        c0, c1 = target_ct
        t0 = time.perf_counter()
        accepted_shares = []
        h_commits = []
        alpha_pt = mfhe.alpha

        for i in range(num_parties):
            # Coordinator sends public c1 over socket to Party i
            total_tx += _send_packet(conns[i], {"cmd": "PELTA_DEC_REQ", "c1": c1, "alpha": alpha_pt})
            req_pkt, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            s_i = mfhe.party_s_shares[i]
            r_i = mfhe.party_r_shares[i]
            c_ajtai_i, k_vec_i = mfhe.party_ajtai_commits[i]
            e_smdg = ring.sample_gaussian(bound=mfhe.B_smdg)

            if i in mal_indices:
                if attack_type == "noise_flooding":
                    d_i, proof = prover.prove_share(
                        req_pkt["c1"], s_i, [x * 60 for x in e_smdg], req_pkt["alpha"],
                        ajtai=ajtai, c_ajtai=c_ajtai_i, r_secret=r_i, k_vec=k_vec_i, sign_a=+1,
                    )
                elif attack_type == "invalid_key_share":
                    s_bad = [random.randint(20, 60) for _ in range(N_poly)]
                    d_i, proof = prover.prove_share(
                        req_pkt["c1"], s_bad, e_smdg, req_pkt["alpha"],
                        ajtai=ajtai, c_ajtai=c_ajtai_i, r_secret=r_i, k_vec=k_vec_i, sign_a=+1,
                    )
                else:
                    d_i, proof = prover.prove_share(
                        req_pkt["c1"], s_i, e_smdg, req_pkt["alpha"],
                        ajtai=ajtai, c_ajtai=c_ajtai_i, r_secret=r_i, k_vec=k_vec_i, sign_a=+1,
                    )
                    d_i = [(c + 777) % ring.q for c in d_i]
            else:
                d_i, proof = prover.prove_share(
                    req_pkt["c1"], s_i, e_smdg, req_pkt["alpha"],
                    ajtai=ajtai, c_ajtai=c_ajtai_i, r_secret=r_i, k_vec=k_vec_i, sign_a=+1,
                )

            h_i = hash_commitment(d_i)
            total_tx += _send_packet(
                client_socks[i],
                {"cmd": "PELTA_PROOF_SUBMIT", "d_i": d_i, "proof": proof.to_dict(), "h_commit": h_i},
            )
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b

            from tool import PeltaProof
            proof_obj = PeltaProof.from_dict(resp["proof"])
            # Verifier checks purely public commitments and ZK transcript (no secrets!)
            proof_ok = verifier.verify_share(
                c1, resp["d_i"], proof_obj, alpha_pt,
                ajtai=ajtai, expected_c_ajtai=public_c_ajtai[i],
            )
            if proof_ok:
                accepted_shares.append(resp["d_i"])
                h_commits.append(resp["h_commit"])
            else:
                rejected_nodes.add(i)
            del req_pkt, resp
        t_pdec_step = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_pdec_step)

        # Aggregation + 4-point Schwartz-Zippel Verification (Full-Threshold Abort on reject)
        t0 = time.perf_counter()
        if len(accepted_shares) != num_parties:
            correctness = False
            aborted_any = True
        else:
            agg_d = VerifiableAggregation.aggregate(ring, accepted_shares)
            sz_ok, _ = VerifiableAggregation.verify_sum_multi_alpha(ring, accepted_shares, h_commits, agg_d, k_points=4)
            phase = ring.add(c0, agg_d)
            half_delta = mfhe.delta // 2
            val0 = phase[0] % mfhe.q
            dec = (((val0 + half_delta) // mfhe.delta) % mfhe.p_ntt) % mfhe.p
            if (not sz_ok) or (dec != expected):
                correctness = False
        t_agg_step = (time.perf_counter() - t0) * 1000.0
        agg_times.append(t_agg_step)

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    q_bits = max(16, int(mfhe.q).bit_length())
    mean_pdec = sum(pdec_times) / len(pdec_times)
    mean_agg = sum(agg_times) / len(agg_times)
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="PELTA_Malicious_MFHE",
        k=k,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            gate_storage_bits=num_parties * N_poly * q_bits
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=2,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)}
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "malicious_injected": mal_count,
            "malicious_rejected": len(rejected_nodes),
            "aborted": aborted_any,
            "q_bits": q_bits,
        }
    )


# ----------------------------------------------------------------------
# 4. HQ-FS (CSF 2027) Distributed Multi-Port Engine (Authentic 19 Primes)
# ----------------------------------------------------------------------

def run_hqfs_distributed(
    num_parties: int = 10,
    d: int = 16,
    T: int = 65537,
    m: int = 16,
    base_port: int = 14400,
    iterations: int = 3,
    malicious_ratio: int = 0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    print(f"\n[+] Running DISTRIBUTED Multi-Port Socket Benchmark: 'HQ-FS' (N={num_parties}, Ports={base_port}..{base_port+num_parties-1}, 19 RNS Primes)")
    tracemalloc.start()
    total_tx = 0
    total_rx = 0

    t_start_setup = time.perf_counter()
    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    n_glwe = 2
    m_glwe = 3
    threshold_t = max(2, int(num_parties * 0.6))
    flood_bound = 1024
    mr = max(0, min(49, int(malicious_ratio)))
    at = attack_type or "none"

    # Match 30-bit NTT primes from uploaded scripts for N <= 50; widen for N > 50 under Lagrange denominators
    start_bit = 48 if num_parties > 50 else 30
    all_primes = get_ntt_primes(19, start_bit, d)
    q_primes = all_primes[:6]
    p_primes = all_primes[6:]

    R = RNSRing(d, q_primes, p_primes, T)
    NTT = PlaintextNTTHelper(d, T)
    Delta = R.Q_big // T
    p_zkp = int(R.P_q[0]) * int(R.P_q[1])

    A_global = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(m_glwe)]
    A_crs_global = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(m_glwe)]
    A_rlk_global = {}
    A_rlk_crs = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            A_rlk_global[(a, b_idx)] = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(R.s_q)]
            A_rlk_crs[(a, b_idx)] = [uniform_poly(R) for _ in range(R.s_q)]

    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    # KeyGen over N Sockets: Feldman DKG Dealer & Receiver
    t_start_kg = time.perf_counter()
    nodes = {
        i: DecentralizedClientNode(i, threshold_t, num_parties, R, A_global, A_crs_global, p_zkp=p_zkp)
        for i in range(1, num_parties + 1)
    }

    pk_global = [R.zero() for _ in range(m_glwe)]
    C_coeffs_global = [[R.zero() for _ in range(m_glwe)] for _ in range(threshold_t)]
    acc_s = {i: [R.zero() for _ in range(n_glwe)] for i in range(1, num_parties + 1)}
    acc_e = {i: [R.zero() for _ in range(m_glwe)] for i in range(1, num_parties + 1)}

    for idx, (node_id, node) in enumerate(nodes.items()):
        pub_k, sub_s, sub_e, C_c = node.execute_dkg_dealer_phase()
        total_tx += _send_packet(client_socks[idx], {"cmd": "DKG_PUBKEY", "node_id": node_id, "pub_k": pub_k})
        resp, rx_b = _recv_packet(conns[idx])
        total_rx += rx_b

        for k_dim in range(m_glwe):
            pk_global[k_dim] = R.add(pk_global[k_dim], pub_k[k_dim])
        for deg in range(threshold_t):
            for k_dim in range(m_glwe):
                C_coeffs_global[deg][k_dim] = R.add(C_coeffs_global[deg][k_dim], C_c[deg][k_dim])
        for j in range(1, num_parties + 1):
            for dim in range(n_glwe):
                acc_s[j][dim] = R.add(acc_s[j][dim], sub_s[j][dim])
            for dim in range(m_glwe):
                acc_e[j][dim] = R.add(acc_e[j][dim], sub_e[j][dim])
        del sub_s, sub_e, C_c

    public_commitments = {}
    for idx, (node_id, node) in enumerate(nodes.items()):
        total_tx += _send_packet(conns[idx], {"cmd": "ROUTED_COMMIT", "C_coeffs": C_coeffs_global})
        _, rx_b = _recv_packet(client_socks[idx])
        total_rx += rx_b

        comm = node.execute_dkg_receiver_phase(acc_s[node.id], acc_e[node.id], C_coeffs_global)
        total_tx += _send_packet(client_socks[idx], {"cmd": "FINAL_COMMIT", "comm": comm})
        resp, rx_b = _recv_packet(conns[idx])
        total_rx += rx_b
        public_commitments[node.id] = resp["comm"]
        del resp

    t_keygen_ms = (time.perf_counter() - t_start_kg) * 1000.0

    # Offline Prep: 2-Round Distributed Collective RLK Generation over Sockets (Zero Secret Leakage)
    t_start_prep = time.perf_counter()
    H_agg = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            H_agg[(a, b_idx)] = [(R.zero(), R.zero()) for _ in range(R.s_q)]

    for idx, node in enumerate(nodes.values()):
        total_tx += _send_packet(conns[idx], {"cmd": "RLK_R1_REQ", "a_crs": A_rlk_crs})
        _, rx_b = _recv_packet(client_socks[idx])
        total_rx += rx_b

        r1_shares = node.rlk_round1(A_rlk_crs)
        total_tx += _send_packet(client_socks[idx], {"cmd": "RLK_R1_SHARE", "r1": r1_shares})
        resp, rx_b = _recv_packet(conns[idx])
        total_rx += rx_b
        for a in range(n_glwe):
            for b_idx in range(n_glwe):
                for limb_i in range(R.s_q):
                    h0_c, h1_c = H_agg[(a, b_idx)][limb_i]
                    h0_j, h1_j = resp["r1"][(a, b_idx)][limb_i]
                    H_agg[(a, b_idx)][limb_i] = (R.add(h0_c, h0_j), R.add(h1_c, h1_j))
        del r1_shares, resp

    rlk = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            rlk[(a, b_idx)] = [(A_rlk_global[(a, b_idx)][limb_i], R.zero()) for limb_i in range(R.s_q)]

    for idx, node in enumerate(nodes.values()):
        total_tx += _send_packet(conns[idx], {"cmd": "RLK_R2_REQ", "H_agg": H_agg})
        _, rx_b = _recv_packet(client_socks[idx])
        total_rx += rx_b

        r2_shares = node.rlk_round2(A_rlk_global, H_agg, clear_s_base=True)
        total_tx += _send_packet(client_socks[idx], {"cmd": "RLK_R2_SHARE", "r2": r2_shares})
        resp, rx_b = _recv_packet(conns[idx])
        total_rx += rx_b
        for a in range(n_glwe):
            for b_idx in range(n_glwe):
                for limb_i in range(R.s_q):
                    av, bv = rlk[(a, b_idx)][limb_i]
                    rlk[(a, b_idx)][limb_i] = (av, R.add(bv, resp["r2"][(a, b_idx)][limb_i]))
        del r2_shares, resp

    rlk_bytes = len(pickle.dumps(rlk, protocol=pickle.HIGHEST_PROTOCOL))
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt & Homomorphic Eval (with Zero-Ciphertext Superposition)
    ct1 = encrypt(np.ones(d, dtype=np.int64), A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe, 3, flood_bound)
    ct0 = encrypt(np.zeros(d, dtype=np.int64), A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe, 3, flood_bound)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = add(ct1, ct0, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe, 3, flood_bound)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = mul(ct1, ct1, rlk, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe, 3, flood_bound)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    # Partial Decryption with Multi-HQ-FS ZKP Proof over Sockets + Malicious BFT Verification
    pdec_times = []
    agg_times = []
    correctness = True
    num_mal = (num_parties * mr) // 100 if at != "none" else 0
    num_mal = min(num_mal, max(0, num_parties - threshold_t))
    malicious_ids = set(random.sample(range(1, num_parties + 1), num_mal)) if num_mal > 0 else set()
    last_rejected = []

    for target_ct, expected in [(ct_add, 1), (ct_mul, 1)]:
        t0 = time.perf_counter()
        submitted_data = {}
        for idx, (node_id, node) in enumerate(nodes.items()):
            total_tx += _send_packet(conns[idx], {"cmd": "PDEC_REQ", "u": target_ct[0]})
            req, rx_b = _recv_packet(client_socks[idx])
            total_rx += rx_b

            p_sh, pf = HQFSSystem.partial_decrypt_with_multi_hq_fs(
                req["u"], node.final_s, node.final_e, A_crs_global, node.zkp_commitment,
                R, p_zkp, m_glwe, n_glwe, flood_bound
            )
            if node_id in malicious_ids:
                p_sh[0][0] = (p_sh[0][0] + 999999) % int(R.P_q[0])
                if at != "zero_share":
                    pf["z_s_limbs"][0][0][0] = (pf["z_s_limbs"][0][0][0] + 999999) % int(R.P_q[0])
            total_tx += _send_packet(client_socks[idx], {"cmd": "PDEC_RESP", "p_sh": p_sh, "pf": pf})
            resp, rx_b = _recv_packet(conns[idx])
            total_rx += rx_b
            submitted_data[node_id] = (resp["p_sh"], resp["pf"])
            del req, resp

        t_pdec_step = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_pdec_step)

        # Aggregation: 4-ary Tree-Bisection Verifier + Committee Lagrange
        t0 = time.perf_counter()
        valid_ids = HQFSVerifier.verify_n_tree(
            target_ct[0], submitted_data, list(submitted_data.keys()),
            A_crs_global, public_commitments, R,
            p_zkp, m_glwe, n_glwe, [0, 1], n_branch=4
        )
        last_rejected = sorted(list(set(submitted_data.keys()) - set(valid_ids)))
        if len(valid_ids) < threshold_t:
            correctness = False
            agg_times.append((time.perf_counter() - t0) * 1000.0)
            continue

        # Select tightest-span honest committee of size threshold_t
        sv = sorted(valid_ids)
        active_set = sv[:threshold_t]
        best_span = active_set[-1] - active_set[0]
        for s_idx in range(1, len(sv) - threshold_t + 1):
            cand = sv[s_idx:s_idx + threshold_t]
            if cand[-1] - cand[0] < best_span:
                best_span = cand[-1] - cand[0]
                active_set = cand

        lams_int_map, Delta_int = compute_committee_lagrange(active_set)

        agg_sum = [np.zeros(d, dtype=np.int64) for _ in range(R.s_q)]
        for uid in active_set:
            part_s = submitted_data[uid][0]
            lam_int = lams_int_map[uid]
            for mi in range(R.s_q):
                p_qi = int(R.P_q[mi])
                lam_mod = lam_int % p_qi
                agg_sum[mi] = (agg_sum[mi] + (part_s[mi] * lam_mod) % p_qi) % p_qi

        v_scaled = [np.zeros(d, dtype=np.int64) for _ in range(R.s_q)]
        for mi in range(R.s_q):
            p_qi = int(R.P_q[mi])
            delta_mod = Delta_int % p_qi
            v_scaled[mi] = (target_ct[1][mi] * delta_mod) % p_qi

        v_sub_agg = R.sub(v_scaled, agg_sum)
        dec_scaled = decode_vec(v_sub_agg, R, NTT, Delta, T)
        inv_delta_T = modinv_jit(Delta_int % T, T)
        dec = (dec_scaled * inv_delta_T) % T
        dec_val = int(dec[0])
        t_agg_step = (time.perf_counter() - t0) * 1000.0
        agg_times.append(t_agg_step)
        if dec_val != expected:
            correctness = False

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mean_pdec = sum(pdec_times) / len(pdec_times)
    mean_agg = sum(agg_times) / len(agg_times)
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="HQ-FS (RNS-GLWE + Homomorphic Quotient ZKP + Zero-CT, Our Work)",
        k=start_bit * 6,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            gate_storage_bits=rlk_bytes * 8
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=1,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)}
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "rns_primes_count": 19,
            "malicious_injected": num_mal,
            "malicious_rejected": len(last_rejected),
            "rejected_ids": last_rejected[:8],
            "collective_rlk": "2-round Mouchet"
        }
    )


# ----------------------------------------------------------------------
# 5. OT25 (Okada & Takagi, Asiacrypt 2025) Distributed Multi-Port Engine
# ----------------------------------------------------------------------

def run_ot25_distributed(
    num_parties: int = 10,
    k: int = 64,
    m: int = 1,
    base_port: int = 14500,
    malicious_ratio: float = 0.0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    r"""
    OT25 (Asiacrypt 2025: Okada & Takagi) Distributed Multi-Port Socket Benchmark.
    Simulates real TCP network distribution of:
      1. KeyGen: Shamir secret shares, padding noises \zeta^{(sid)}, PRF seeds
      2. ServerDec: untrusted server performs flood-and-round (Enc(pk, 0), half-int flooding,
         Def. 3.13 randomized Gaussian rounding, PRF sum) and broadcasts ct_dec
      3. PartDec: active parties compute pd_i with Lagrange weights and PRF masks over sockets
      4. FinDec: Server reconstructs plaintext
    """
    tracemalloc.start()
    total_tx = 0
    total_rx = 0

    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    p_plain = int(kwargs.get("p_plain", min(1 << max(1, int(m)), 16)))
    t_thresh = max(1, int(num_parties * 0.6))

    t_start_setup = time.perf_counter()
    ot25 = OT25ThFHE(n_dim=16, q=65537, p=p_plain, num_parties=num_parties, threshold=t_thresh)
    ot25.setup()
    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    t_start_keygen = time.perf_counter()
    ot25.keygen()
    # Distribute Shamir shares and PRF seeds across sockets to each party
    party_local_state: Dict[int, Dict[str, Any]] = {}
    for i in range(num_parties):
        p_id = i + 1
        pkg = {
            "cmd": "INIT_OT25",
            "s_share": ot25.s_shares[p_id],
            "seed": ot25.seeds[p_id],
            "threshold": ot25.threshold,
            "q": ot25.q,
        }
        total_tx += _send_packet(conns[i], pkg)
        rcv, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b
        party_local_state[p_id] = {
            "s_share": rcv["s_share"],
            "seed": rcv["seed"],
            "q": rcv["q"],
            "zeta_shares": {},
        }
    t_keygen_ms = (time.perf_counter() - t_start_keygen) * 1000.0

    # Offline prep: distribute padding noise shares for decryption sessions (sid=1, 2)
    t_start_prep = time.perf_counter()
    for i in range(num_parties):
        p_id = i + 1
        pkg = {
            "cmd": "PREP_ZETA_SHARES",
            "zeta_map": {
                1: ot25.zeta_shares[1][p_id],
                2: ot25.zeta_shares[2][p_id],
            },
        }
        total_tx += _send_packet(conns[i], pkg)
        rcv, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b
        party_local_state[p_id]["zeta_shares"].update(rcv["zeta_map"])
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt (public-key) & Homomorphic Eval (BFV tensor + gadget relin)
    v1 = 1
    v2 = 1
    ct1 = ot25.encrypt(v1)
    ct0 = ot25.encrypt(0)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = ot25.eval_add(ct1, ct0)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = ot25.eval_mul(ct1, ct1)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    # Online Decryption over sockets
    pdec_times = []
    agg_times = []
    correctness = True
    active_parties = list(range(1, ot25.threshold + 1))

    mr = max(0, min(49, int(malicious_ratio or 0)))
    at = attack_type or "none"
    mal_count = (num_parties * mr) // 100 if (mr > 0 and at != "none") else 0
    mal_set = set(secrets.SystemRandom().sample(active_parties, min(mal_count, len(active_parties)))) if mal_count > 0 else set()

    for target_ct, expected in [(ct_add, v1 % p_plain), (ct_mul, (v1 * v2) % p_plain)]:
        t0 = time.perf_counter()
        a_bar, b_bar, sid = ot25.server_dec(target_ct, active_parties)
        shares = []
        for p_id in active_parties:
            sock_idx = p_id - 1
            total_tx += _send_packet(conns[sock_idx], {"cmd": "PART_DEC_REQ", "a_bar": a_bar, "sid": sid, "active": active_parties})
            req, rx_b = _recv_packet(client_socks[sock_idx])
            total_rx += rx_b

            # Party computes pd_i strictly from its socket-received s_share, zeta_share, and PRF seed
            if p_id in mal_set:
                pd_i = ot25.part_dec_with_attack(p_id, req["a_bar"], req["active"], req["sid"], at)
            else:
                st = party_local_state[p_id]
                q_loc = st["q"]
                lam = ot25._lagrange_coeff(p_id, req["active"])
                zeta_loc = st["zeta_shares"][req["sid"]]
                term = (int(np.dot(np.asarray(req["a_bar"], dtype=np.int64), st["s_share"])) + int(zeta_loc)) % q_loc
                m_i = ot25._prf(st["seed"], req["sid"])
                pd_i = (lam * term + m_i) % q_loc

            total_tx += _send_packet(client_socks[sock_idx], {"cmd": "PART_DEC_RESP", "pd_i": pd_i})
            resp, rx_b = _recv_packet(conns[sock_idx])
            total_rx += rx_b
            shares.append(resp["pd_i"])
            del req, resp
        t_pdec_step = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_pdec_step)

        t0 = time.perf_counter()
        dec = ot25.fin_dec(b_bar, shares)
        t_agg_step = (time.perf_counter() - t0) * 1000.0
        agg_times.append(t_agg_step)
        if dec != expected:
            correctness = False

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mean_pdec = sum(pdec_times) / len(pdec_times)
    mean_agg = sum(agg_times) / len(agg_times)
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="OT25 (Asiacrypt 2025: Noise Padding + PRF Masking)",
        k=k,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            gate_storage_bits=(16 * 17 + ot25.l_dec * 17) * num_parties,
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=2,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)},
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "rns_primes_count": 2,
            "malicious_injected": len(mal_set),
            "aborted": False,
        },
    )


# ----------------------------------------------------------------------
# 6. Ajax (Hu et al., USENIX Security 2025) Distributed Multi-Port Engine
# ----------------------------------------------------------------------

def run_ajax_distributed(
    num_parties: int = 10,
    k: int = 64,
    m: int = 1,
    base_port: int = 14600,
    malicious_ratio: float = 0.0,
    attack_type: str = "none",
    **kwargs
) -> BenchmarkResult:
    r"""
    Ajax (USENIX Security 2025: Hu et al.) Distributed Multi-Port Socket Benchmark.
    Simulates real TCP network distribution of:
      1. Noise-Compressing KeyGen: Shamir [[s]]_q converted to additive <s>_q for t + 1 committee
      2. Offline Double Ring Sharing: distributes fresh (<r>_\eta, <r>_\Phi) per decryption
      3. Two-Round Online Decryption ("Mask-Then-Open"):
         - Round 1: parties compute <v_i>_\Phi, transmit to coordinator, coordinator broadcasts v_open
         - Round 2: parties compute <\Phi * m_i>_\eta in Z_\eta, transmit to receiver, receiver decodes
    """
    tracemalloc.start()
    total_tx = 0
    total_rx = 0

    server_socks, ports = _bind_multi_ports(num_parties, base_port)
    client_socks, conns = _connect_client_sockets(ports, server_socks)

    t_start_setup = time.perf_counter()
    p_plain = int(kwargs.get("p_plain", min(1 << max(1, int(m)), 4)))
    t_corrupt = max(0, (num_parties - 1) // 2)
    t_plus_1 = min(num_parties, t_corrupt + 1)
    ajax = AjaxThFHE(n_dim=16, q=None, p=p_plain, num_parties=num_parties, threshold=t_plus_1, sigma=3.2)
    ajax.setup()
    t_setup_ms = (time.perf_counter() - t_start_setup) * 1000.0

    t_start_keygen = time.perf_counter()
    ajax.keygen()
    party_local_state: Dict[int, Dict[str, Any]] = {}
    for i in range(t_plus_1):
        pkg = {
            "cmd": "INIT_AJAX",
            "s_share": ajax.s_shares[i],
            "threshold": ajax.threshold,
            "q": ajax.q,
            "eta": ajax.eta,
            "Phi": ajax.Phi,
        }
        total_tx += _send_packet(conns[i], pkg)
        rcv, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b
        party_local_state[i] = {
            "s_share": np.asarray(rcv["s_share"], dtype=object),
            "q": rcv["q"],
            "eta": rcv["eta"],
            "Phi": rcv["Phi"],
            "double_rings": [],
        }
    t_keygen_ms = (time.perf_counter() - t_start_keygen) * 1000.0

    # Offline prep: distribute 2 FRESH double-ring pairs (one per decryption session)
    t_start_prep = time.perf_counter()
    pair_0 = ajax.preprocessed_double_rings.pop(0)
    pair_1 = ajax.preprocessed_double_rings.pop(0)
    for i in range(t_plus_1):
        pkg = {
            "cmd": "PREP_DOUBLE_RING",
            "pairs": [
                (pair_0[0][i], pair_0[1][i]),
                (pair_1[0][i], pair_1[1][i]),
            ],
        }
        total_tx += _send_packet(conns[i], pkg)
        rcv, rx_b = _recv_packet(client_socks[i])
        total_rx += rx_b
        party_local_state[i]["double_rings"] = list(rcv["pairs"])
    t_prep_ms = (time.perf_counter() - t_start_prep) * 1000.0

    # Encrypt (public-key) & Homomorphic Eval (BFV tensor + gadget relin)
    v1 = 1
    v2 = 2 % p_plain if p_plain > 2 else 1
    ct1 = ajax.encrypt(v1)
    ct2 = ajax.encrypt(v2)
    ct_bytes = len(pickle.dumps(ct1))

    t0 = time.perf_counter()
    ct_add = ajax.eval_add(ct1, ct2)
    t_add_ms = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ct_mul = ajax.eval_mul(ct1, ct2)
    t_mul_ms = (time.perf_counter() - t0) * 1000.0

    mr = max(0, min(49, int(malicious_ratio or 0)))
    at = attack_type or "none"
    mal_count = (num_parties * mr) // 100 if (mr > 0 and at != "none") else 0
    mal_set = set(secrets.SystemRandom().sample(range(t_plus_1), min(mal_count, t_plus_1))) if mal_count > 0 else set()
    primary_mal = min(mal_set) if mal_set else -1
    rng = secrets.SystemRandom()

    pdec_times = []
    agg_times = []
    correctness = True

    for op_idx, (target_ct, expected) in enumerate([(ct_add, (v1 + v2) % p_plain), (ct_mul, (v1 * v2) % p_plain)]):
        # Round 1: Mask then Open mod Phi using FRESH double-ring pair[op_idx]
        t0 = time.perf_counter()
        a, b = target_ct
        v_shares = []
        u_prime_shares = []

        for i in range(t_plus_1):
            total_tx += _send_packet(conns[i], {"cmd": "ROUND1_REQ", "a": a, "b": b, "idx": i})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            st = party_local_state[i]
            q_loc, eta_loc, phi_loc = st["q"], st["eta"], st["Phi"]
            r_eta_i, r_phi_i = st["double_rings"][op_idx]
            s_loc = st["s_share"]
            if i in mal_set and at == "invalid_key_share":
                s_loc = np.array([rng.randrange(q_loc) for _ in range(ajax.n_dim)], dtype=object)

            a_obj = np.asarray(req["a"], dtype=object)
            if i == 0:
                u_i = (int(req["b"]) - int(np.dot(a_obj, s_loc))) % q_loc
            else:
                u_i = (-int(np.dot(a_obj, s_loc))) % q_loc
            u_p = int(round((eta_loc / float(q_loc)) * u_i)) % eta_loc
            e_p = u_p % phi_loc
            if i in mal_set and at == "noise_flooding":
                sec_bound = max(1, phi_loc // max(4, 2 * len(mal_set)))
                shift_eta = phi_loc if i == primary_mal else rng.randrange(sec_bound)
                u_p = (u_p + shift_eta) % eta_loc
            v_i = (e_p + r_phi_i) % phi_loc

            total_tx += _send_packet(client_socks[i], {"cmd": "ROUND1_RESP", "v_i": v_i, "u_p": u_p})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b
            v_shares.append(resp["v_i"])
            u_prime_shares.append(resp["u_p"])
            del req, resp

        v_open = sum(v_shares) % ajax.Phi
        v_centered = v_open if v_open <= ajax.Phi // 2 else v_open - ajax.Phi
        t_round1 = (time.perf_counter() - t0) * 1000.0
        pdec_times.append(t_round1)

        # Round 2: Subtraction in Z_eta and Reconstruction
        t0 = time.perf_counter()
        phi_m_shares = []
        for i in range(t_plus_1):
            total_tx += _send_packet(conns[i], {"cmd": "ROUND2_REQ", "v_open": v_centered})
            req, rx_b = _recv_packet(client_socks[i])
            total_rx += rx_b

            st = party_local_state[i]
            eta_loc, phi_loc = st["eta"], st["Phi"]
            r_eta_i, _ = st["double_rings"][op_idx]
            if i == 0:
                e_p_eta_i = (int(req["v_open"]) - r_eta_i) % eta_loc
            else:
                e_p_eta_i = (-r_eta_i) % eta_loc
            phi_m_i = (u_prime_shares[i] - e_p_eta_i) % eta_loc
            if i in mal_set and at in ("share_tampering", "equivocation_eval"):
                sec_bound = max(1, phi_loc // max(4, 2 * len(mal_set)))
                shift_eta = phi_loc if i == primary_mal else rng.randrange(sec_bound)
                phi_m_i = (phi_m_i + shift_eta) % eta_loc
            elif i in mal_set and at not in ("none", "invalid_key_share", "noise_flooding"):
                phi_m_i = (phi_m_i + rng.randint(1, eta_loc - 1)) % eta_loc

            total_tx += _send_packet(client_socks[i], {"cmd": "ROUND2_RESP", "phi_m_i": phi_m_i})
            resp, rx_b = _recv_packet(conns[i])
            total_rx += rx_b
            phi_m_shares.append(resp["phi_m_i"])
            del req, resp

        tot = sum(phi_m_shares) % ajax.eta
        dec = int(round(tot / ajax.Phi)) % ajax.p
        t_round2 = (time.perf_counter() - t0) * 1000.0
        agg_times.append(t_round2)
        if dec != expected:
            correctness = False

    _cleanup_sockets(server_socks, client_socks, conns)
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mean_pdec = sum(pdec_times) / len(pdec_times)
    mean_agg = sum(agg_times) / len(agg_times)
    mean_lat = mean_pdec + mean_agg

    return BenchmarkResult(
        scheme_name="Ajax (USENIX Security 2025: Mask-Then-Open without Noise Flooding)",
        k=k,
        m=m,
        mode="distributed",
        timestamp=datetime.datetime.now().isoformat(),
        num_parties=num_parties,
        offline=OfflineMetric(
            setup_time_ms=round(t_setup_ms, 3),
            keygen_time_ms=round(t_keygen_ms, 3),
            prep_time_ms=round(t_prep_ms, 3),
            gate_storage_bits=ajax.q.bit_length() * num_parties,
        ),
        online=OnlineMetric(
            eval_add_time_ms=round(t_add_ms, 4),
            eval_mul_time_ms=round(t_mul_ms, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            throughput_dec_per_sec=round(1000.0 / mean_lat if mean_lat > 0 else 0, 1),
            num_rounds=2,
            comm_sent_bytes=total_tx,
            comm_recv_bytes=total_rx,
            details={"peak_mem_mb": round(peak_mem / (1024 * 1024), 2)},
        ),
        ciphertext_size_bytes=ct_bytes,
        correctness_verified=correctness,
        metadata={
            "ports_range": f"{base_port}..{base_port+num_parties-1}",
            "sockets_count": num_parties,
            "rns_primes_count": 2,
            "threshold_t_plus_1": t_plus_1,
            "malicious_injected": len(mal_set),
            "aborted": False,
        },
    )


# ----------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------

DISTRIBUTED_RUNNERS = {
    "ccs25": run_ccs25_distributed,
    "baseline_noise_flooding": run_noah_distributed,
    "noah": run_noah_distributed,
    "pelta": run_pelta_distributed,
    "hqfs": run_hqfs_distributed,
    "ot25": run_ot25_distributed,
    "ajax": run_ajax_distributed
}

def run_scheme_distributed(scheme_name: str, num_parties: int = 10, **kwargs) -> BenchmarkResult:
    s_key = scheme_name.lower()
    for k, runner in DISTRIBUTED_RUNNERS.items():
        if k in s_key:
            return runner(num_parties=num_parties, **kwargs)
    raise ValueError(f"Unknown distributed scheme: {scheme_name}")
