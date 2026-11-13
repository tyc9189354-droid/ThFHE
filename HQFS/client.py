#!/usr/bin/env python3
"""
================================================================================
HQ-FS: Client Module (Data Owner [DO] & Decentralized Computing Network [DCN] Node)
Paper: "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic
        Quotient Proofs"
================================================================================
Responsibilities (Fig. 1 & Section III):
  - DCN Node:
      * Algorithm 2 (KeyGen & ZKP Commitment): Samples secret s^{(i)}, error e^{(i)},
        ZKP error e_zkp^{(i)}, computes pk_i = A*s^{(i)} + e^{(i)} (mod Q) and
        commitment C_i = A_zkp * s^{(i)} + e_zkp^{(i)} (mod Q).
      * Algorithm 3 (RLKGen): Generates RNS relinearization key shares with
        high-variance flooding noise.
      * Algorithm 5 (Partial Decryption & HQ-FS ZKP): Computes raw share
        sh_raw^{(i)} = <u, s^{(i)}>, adds K_Q-multiple ideal flooding noise
        e_flood^{(i)}, and constructs HQ-FS ZKP proof pi^{(i)} = (ch, z_s, z_e, T_u, T_A)
        confined to baseline prime K_Q = q_1.
  - Data Owner (DO):
      * Algorithm 4 (Encryption): Encodes message vector m_vec via iNTT(m) and
        encrypts under pk_global with flooding noise y_0, y_1.
================================================================================
"""

import os
import sys
import json
import time
import random
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

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


class HQFSClient:
    """HTTP Client interacting with the HQ-FS CSP/DR Server."""

    def __init__(self, server_url: str = "http://127.0.0.1:8002"):
        self.server_url = server_url.rstrip("/")

    def _get(self, endpoint: str) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def fetch_params(self) -> Dict[str, Any]:
        return self._get("/params")

    def encrypt_simd(self, slots: List[int]) -> Dict[str, Any]:
        return self._post("/encrypt", {"slots": slots})

    def eval_add(self, c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/eval_add", {"c1": c1, "c2": c2})

    def eval_mul(self, c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        return self._post("/eval_mul", {"c1": c1, "c2": c2})

    def decrypt_bfs(
        self,
        ciphertext: Dict[str, Any],
        malicious_nodes: Optional[List[int]] = None,
        attack_type: str = "share_tampering",
        slot_count: int = 4
    ) -> Dict[str, Any]:
        return self._post("/decrypt_bfs", {
            "ciphertext": ciphertext,
            "malicious_nodes": malicious_nodes or [],
            "attack_type": attack_type,
            "slot_count": slot_count
        })


def run_local_simulation(num_parties: int = 10, T_plain: int = 1024):
    print("=" * 78)
    print(f"  HQ-FS Local Full-Protocol Verification (Algorithms 1..8 | N={num_parties}, T={T_plain})")
    print("=" * 78)

    # 1. Algorithm 1: Setup
    t0 = time.perf_counter()
    hqfs = HQFSRNSGLWE(
        d=16,
        n_glwe=2,
        m_glwe=2,
        T_plain=T_plain,
        eta=1,
        B_flood=64,
        num_parties=num_parties
    )
    setup_ms = (time.perf_counter() - t0) * 1000.0
    print(f"\n[Algorithm 1: Setup] RNS Primes Q = {hqfs.rns.q_primes} | Baseline K_Q = {hqfs.K_Q}")
    print(f"  • Composite Q bits = {hqfs.rns.Q_big.bit_length()} bits | Plaintext T = {hqfs.T} | Setup = {setup_ms:.3f} ms")

    # 2. Algorithm 2: KeyGen & ZKP Commitment
    t1 = time.perf_counter()
    kg_info = hqfs.keygen_and_commitment()
    keygen_ms = (time.perf_counter() - t1) * 1000.0
    print(f"\n[Algorithm 2: KeyGen & ZKP Commitment] Generated {kg_info['num_parties']} node keys & commitments C_i")
    print(f"  • Aggregated pk_global = sum(pk_i) mod Q | KeyGen = {keygen_ms:.3f} ms")

    # 3. Algorithm 3: RLKGen
    t2 = time.perf_counter()
    rlk_info = hqfs.rlk_gen()
    rlkgen_ms = (time.perf_counter() - t2) * 1000.0
    print(f"\n[Algorithm 3: RLKGen] Generated {rlk_info['rlk_entries']} RNS-decomposed RLK entries with flooding noise")
    print(f"  • RLKGen = {rlkgen_ms:.3f} ms")

    # 4. Algorithm 4: Encryption (with iNTT SIMD slot encoding & flooding noise)
    slots_alpha = [12, 25, 100, 512]
    slots_beta = [3, 40, 10, 2]
    t3 = time.perf_counter()
    ct_alpha = hqfs.encrypt_simd(slots_alpha)
    ct_beta = hqfs.encrypt_simd(slots_beta)
    enc_ms = (time.perf_counter() - t3) * 1000.0
    print(f"\n[Algorithm 4: Encryption (DO)] Encoded via iNTT & encrypted with flooding noise (y_0, y_1)")
    print(f"  • m_alpha = {slots_alpha}, m_beta = {slots_beta} | Encrypt = {enc_ms:.3f} ms")

    # 5. Algorithm 7: Homomorphic Addition + Zero-Ciphertext Superposition
    t4 = time.perf_counter()
    ct_add = hqfs.eval_add(ct_alpha, ct_beta)
    add_ms = (time.perf_counter() - t4) * 1000.0
    dec_add = hqfs.decrypt_simd(ct_add, slot_count=4)
    expected_add = [(a + b) % T_plain for a, b in zip(slots_alpha, slots_beta)]
    assert dec_add == expected_add, f"Add mismatch: {dec_add} != {expected_add}"
    print(f"\n[Algorithm 7: Addition + Zero-Ciphertext Superposition]")
    print(f"  • Dec(c_alpha (+) c_beta + c_zero) = {dec_add} (Expected: {expected_add}) | Time = {add_ms:.3f} ms")

    # 6. Algorithm 8: Homomorphic Multiplication + RNS Digit Decomposition + Zero-CT Superposition
    t5 = time.perf_counter()
    ct_mul = hqfs.eval_mul(ct_alpha, ct_beta)
    mul_ms = (time.perf_counter() - t5) * 1000.0
    expected_mul = [(a * b) % T_plain for a, b in zip(slots_alpha, slots_beta)]
    print(f"\n[Algorithm 8: Multiplication + RNS Digit Decomposition + Zero-Ciphertext Superposition]")
    print(f"  • Homo Mul Time = {mul_ms:.3f} ms")

    # 7. Algorithm 5 & 6: Partial Decryption with HQ-FS ZKP & BFS Batch-Filtering Queue under Active Attack
    num_mal = max(1, (num_parties * 20) // 100)
    malicious_nodes = sorted(random.sample(range(num_parties), num_mal))
    u_mul, _ = ct_mul
    shares_map = {}
    proofs_map = {}

    t6 = time.perf_counter()
    for i in range(num_parties):
        atk = "share_tampering" if i in malicious_nodes else None
        sh_i, pi_i = hqfs.partial_decrypt_node(i, u_mul, malicious_attack=atk)
        shares_map[i] = sh_i
        proofs_map[i] = pi_i
    prove_total_ms = (time.perf_counter() - t6) * 1000.0

    t7 = time.perf_counter()
    dec_mul_full, audit = hqfs.decrypt_with_bfs(ct_mul, shares_map, proofs_map)
    bfs_dec_ms = (time.perf_counter() - t7) * 1000.0
    dec_mul = dec_mul_full[:4]

    assert audit["dropped_malicious_nodes"] == malicious_nodes
    assert dec_mul == expected_mul, f"Mul mismatch: {dec_mul} != {expected_mul}"

    print(f"\n[Algorithm 5 & 6: Partial Decryption, HQ-FS ZKP (mod K_Q={hqfs.K_Q}) & BFS Queue Filtering]")
    print(f"  • Injected random malicious nodes: {malicious_nodes}")
    print(f"  • BFS Queue isolated & dropped:    {audit['dropped_malicious_nodes']} (in {audit['bfs_steps']} BFS subset checks)")
    print(f"  • Per-node HQ-FS ZKP Prove Time:   {prove_total_ms / num_parties:.4f} ms/node (Total: {prove_total_ms:.3f} ms)")
    print(f"  • BFS Verify + CRT + NTT Dec Time: {bfs_dec_ms:.3f} ms")
    print(f"  • Final Decrypted SIMD Slots:      {dec_mul} == {expected_mul} [VERIFIED!]")

    print("\n" + "=" * 78)
    print("  [SUCCESS] All 8 Algorithms of HQ-FS Verified 100%!")
    print("=" * 78)


def run_demo(server_url: str = "http://127.0.0.1:8002", num_parties: int = 10):
    client = HQFSClient(server_url)
    try:
        params = client.fetch_params()
    except Exception as e:
        print(f"[!] Server connection failed ({e}). Falling back to local full-protocol simulation...\n")
        run_local_simulation(num_parties=num_parties)
        return

    print("=" * 78)
    print(f"  HQ-FS Networked Client-Server Demo (Connected to {server_url})")
    print(f"  RNS Q={params['q_primes']} | Baseline K_Q={params['K_Q']} | T={params['T']}")
    print("=" * 78)

    s1 = [12, 25, 100, 512]
    s2 = [3, 40, 10, 2]
    c1 = client.encrypt_simd(s1)["ciphertext"]
    c2 = client.encrypt_simd(s2)["ciphertext"]

    mul_res = client.eval_mul(c1, c2)
    dec_res = client.decrypt_bfs(mul_res["ciphertext"], malicious_nodes=[1, 4], attack_type="share_tampering", slot_count=4)
    print(f"  • Homo Mul + Zero-CT Time: {mul_res['eval_time_ms']} ms")
    print(f"  • BFS Isolated Malicious:  {dec_res['audit']['dropped_malicious_nodes']}")
    print(f"  • Decrypted SIMD Slots:    {dec_res['decrypted_slots']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HQ-FS Client (DO & DCN Node)")
    parser.add_argument("--server-url", default="http://127.0.0.1:8002", help="HQ-FS Server URL")
    parser.add_argument("--parties", type=int, default=10, help="Number of DCN nodes N (default: 10)")
    parser.add_argument("--T", type=int, default=1024, help="Plaintext modulus T (default: 1024)")
    parser.add_argument("--local", action="store_true", help="Run local simulation directly")
    args = parser.parse_args()

    if args.local:
        run_local_simulation(num_parties=args.parties, T_plain=args.T)
    else:
        run_demo(server_url=args.server_url, num_parties=args.parties)
