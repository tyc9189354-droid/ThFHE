#!/usr/bin/env python3
"""
================================================================================
PELTA: Client Module (Multiparty FHE Party / Prover)
Paper: "PELTA - Shielding Multiparty-FHE against Malicious Adversaries"
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

# Add paths to locate tool.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import (
    PolyRing,
    PeltaProver,
    PeltaVerifier,
    VerifiableAggregation,
    PeltaMFHE,
    hash_commitment
)

class PeltaClient:
    def __init__(self, server_url: str = "http://127.0.0.1:8001", party_id: str = "Party_1"):
        self.server_url = server_url.rstrip("/")
        self.party_id = party_id
        self.ring: Optional[PolyRing] = None
        self.prover: Optional[PeltaProver] = None
        self.crs_a: Optional[List[int]] = None
        self.alpha: Optional[int] = None
        self.B: int = 16

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            try:
                return json.loads(err_body)
            except Exception:
                raise RuntimeError(f"HTTP Error {e.code}: {err_body}")

    def fetch_params(self):
        url = f"{self.server_url}/params"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        self.ring = PolyRing(N=data["N"], q=data["q"])
        self.B = data["B"]
        self.crs_a = data["crs_a"]
        self.alpha = data["alpha"]
        self.prover = PeltaProver(self.ring, B_noise_bound=self.B)
        return data

    def generate_and_submit_honest_share(self) -> Dict[str, Any]:
        print(f"[*] [{self.party_id}] Generating honest share and NIZK proof...")
        s = self.ring.sample_ternary()
        e = self.ring.sample_gaussian(bound=self.B)

        t0 = time.perf_counter()
        b_share, proof = self.prover.prove_share(self.crs_a, s, e, self.alpha)
        h_commit = hash_commitment(b_share)
        prover_time_ms = (time.perf_counter() - t0) * 1000.0
        print(f"    Prover time: {prover_time_ms:.2f} ms")

        payload = {
            "party_id": self.party_id,
            "share": b_share,
            "proof": proof.to_dict(),
            "h_commit": h_commit
        }
        return self._post("/submit", payload)

    def generate_and_submit_malicious_share(self, attack_type: str = "large_noise") -> Dict[str, Any]:
        print(f"[!] [{self.party_id}] Simulating MALICIOUS behavior (Attack: {attack_type})...")
        if attack_type == "large_noise":
            s = self.ring.sample_ternary()
            e_huge = [val * 50 for val in self.ring.sample_gaussian(bound=self.B)]
            b_share, proof = self.prover.prove_share(self.crs_a, s, e_huge, self.alpha)
            h_commit = hash_commitment(b_share)
        elif attack_type == "non_ternary_key":
            s_bad = [random.randint(10, 50) for _ in range(self.ring.N)]
            e = self.ring.sample_gaussian(bound=self.B)
            b_share, proof = self.prover.prove_share(self.crs_a, s_bad, e, self.alpha)
            h_commit = hash_commitment(b_share)
        elif attack_type == "tampered_share":
            s = self.ring.sample_ternary()
            e = self.ring.sample_gaussian(bound=self.B)
            b_share, proof = self.prover.prove_share(self.crs_a, s, e, self.alpha)
            b_tampered = [(c + 999) % self.ring.q for c in b_share]
            h_commit = hash_commitment(b_tampered)
            b_share = b_tampered

        payload = {
            "party_id": self.party_id,
            "share": b_share,
            "proof": proof.to_dict(),
            "h_commit": h_commit
        }
        return self._post("/submit", payload)

    def request_aggregation(self) -> Dict[str, Any]:
        return self._post("/aggregate", {})


def run_local_simulation(num_parties: int = 10):
    print("=" * 75)
    print(f"  PELTA Local Multi-Party Verification & Homomorphic Eval (Parties={num_parties})")
    print("=" * 75)
    ring = PolyRing(N=64, q=12289)
    B = 16
    crs_a = ring.sample_uniform()
    alpha = 42

    prover = PeltaProver(ring, B_noise_bound=B)
    verifier = PeltaVerifier(ring, B_noise_bound=B)

    # 1. Honest Party 1
    print("\n[+] [Party 1 (Honest)] Generating share & NIZK proof...")
    s1 = ring.sample_ternary()
    e1 = ring.sample_gaussian(bound=B)
    b1, proof1 = prover.prove_share(crs_a, s1, e1, alpha)
    v1 = verifier.verify_share(crs_a, b1, proof1, alpha)
    print(f"    Verifier Check: {v1} (Accepted)")
    assert v1

    # 2. Honest Party 2
    print("\n[+] [Party 2 (Honest)] Generating share & NIZK proof...")
    s2 = ring.sample_ternary()
    e2 = ring.sample_gaussian(bound=B)
    b2, proof2 = prover.prove_share(crs_a, s2, e2, alpha)
    v2 = verifier.verify_share(crs_a, b2, proof2, alpha)
    print(f"    Verifier Check: {v2} (Accepted)")
    assert v2

    # 3. Malicious Party 3 (Attack: Injecting Massive Noise Flooding)
    print("\n[!] [Party 3 (Malicious Attacker)] Attempting Large Noise Attack (Noise Flooding)...")
    s3 = ring.sample_ternary()
    e3_malicious = [c * 50 for c in ring.sample_gaussian(bound=B)]
    b3, proof3 = prover.prove_share(crs_a, s3, e3_malicious, alpha)
    v3 = verifier.verify_share(crs_a, b3, proof3, alpha)
    print(f"    Verifier Check: {v3} (BLOCKED! Malicious noise flooding detected and rejected)")
    assert not v3, "Malicious party should have been rejected!"

    # 4. Verifiable Aggregation (Section 5: Schwartz-Zippel)
    print("\n[*] [Aggregator] Aggregating verified honest shares (Party 1 + Party 2)...")
    agg_poly = VerifiableAggregation.aggregate(ring, [b1, b2])
    agg_eval = ring.eval(agg_poly, alpha)
    is_agg_valid = VerifiableAggregation.verify_sum_at_alpha([proof1.eval_proof, proof2.eval_proof], agg_eval, ring.q)
    print(f"  -> Schwartz-Zippel Verifiable Aggregation Result: {is_agg_valid}")
    assert is_agg_valid

    # 5. RLWE Homomorphic Addition & Multiplication
    print(f"\n[*] [PELTA RLWE] Testing Homomorphic Add & Multiply across {num_parties} parties...")
    mfhe = PeltaMFHE(N=32, q=65536, p=2, B=4, num_parties=num_parties)
    mfhe.keygen()
    ct1 = mfhe.encrypt(1)
    ct2 = mfhe.encrypt(1)

    t_add = time.perf_counter()
    ct_add = mfhe.eval_add(ct1, ct2)
    add_ms = (time.perf_counter() - t_add) * 1000.0
    dec_add = mfhe.decrypt(ct_add)
    assert dec_add == 0
    print(f"  -> RLWE Homo Add (1 + 1 mod 2) = {dec_add} ({add_ms:.4f} ms)")

    t_mul = time.perf_counter()
    ct_mul = mfhe.eval_mul(ct1, ct2)
    mul_ms = (time.perf_counter() - t_mul) * 1000.0
    dec_mul = mfhe.decrypt(ct_mul)
    assert dec_mul == 1
    print(f"  -> RLWE Homo Mul (1 * 1 mod 2) = {dec_mul} ({mul_ms:.4f} ms)")

    print("\n" + "=" * 75)
    print("  [SUCCESS] PELTA Multi-Party Verification & Homomorphic Eval Complete!")
    print("=" * 75)


def run_demo(server_url: str = "http://127.0.0.1:8001", num_parties: int = 10):
    print("=" * 70)
    print("  PELTA Multiparty FHE Zero-Knowledge Verification Demo")
    print("=" * 70)
    client1 = PeltaClient(server_url, party_id="Party_1_Honest")
    try:
        client1.fetch_params()
    except Exception as e:
        print(f"[!] Server connection failed ({e}). Running local simulation demo...\n")
        run_local_simulation(num_parties=num_parties)
        return

    res1 = client1.generate_and_submit_honest_share()
    print(f"  -> Party 1 Status: {res1.get('status')}")

    client2 = PeltaClient(server_url, party_id="Party_2_Honest")
    client2.fetch_params()
    res2 = client2.generate_and_submit_honest_share()
    print(f"  -> Party 2 Status: {res2.get('status')}")

    client3_evil = PeltaClient(server_url, party_id="Party_3_Attacker")
    client3_evil.fetch_params()
    res3 = client3_evil.generate_and_submit_malicious_share(attack_type="large_noise")
    print(f"  -> Party 3 Status: {res3.get('status')} | Reason: {res3.get('reason')}")

    print("\n[*] Requesting Verifiable Aggregation from Server...")
    agg_res = client1.request_aggregation()
    print(f"  -> Participating parties: {agg_res.get('participating_parties')}")
    print(f"  -> Schwartz-Zippel Verifiable Aggregation Check: {agg_res.get('verifiable_aggregation_passed')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PELTA Client")
    parser.add_argument("--server-url", default="http://127.0.0.1:8001", help="Server URL")
    parser.add_argument("--parties", type=int, default=10, help="Number of parties (10..1000)")
    parser.add_argument("--local", action="store_true", help="Run local simulation")
    args = parser.parse_args()

    if args.local:
        run_local_simulation(num_parties=args.parties)
    else:
        run_demo(args.server_url, num_parties=args.parties)
