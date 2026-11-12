#!/usr/bin/env python3
"""
================================================================================
CCS 2025: Client Module (Threshold FHE Decryption Client)
Paper: "High-Throughput Universally Composable Threshold FHE Decryption"
Supports:
  - Encryption, Homomorphic Addition (eval_add), Homomorphic Multiplication (eval_mul)
  - One-shot and 3-round Interactive Threshold Decryption
================================================================================
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List, Tuple, Optional

# Add paths to locate tool.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import (
    ToyLWE,
    ThresholdFHEDecryptor,
    encode_ciphertext,
    decode_ciphertext
)

class CommStats:
    def __init__(self):
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.num_requests = 0

    def reset(self):
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.num_requests = 0

    def record_tx(self, sent_len: int, recv_len: int):
        self.bytes_sent += sent_len
        self.bytes_recv += recv_len
        self.num_requests += 1


class ThresholdFHEClient:
    def __init__(self, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url.rstrip("/")
        self.stats = CommStats()
        self.lwe: Optional[ToyLWE] = None
        self.server_params: Dict[str, Any] = {}

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        sent_size = len(body)
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_bytes = resp.read()
                recv_size = len(resp_bytes)
                self.stats.record_tx(sent_size, recv_size)
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to communicate with server at {url}: {e}")

    def check_health(self) -> Dict[str, Any]:
        url = f"{self.server_url}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.server_params = data.get("params", {})
                return data
        except Exception as e:
            raise ConnectionError(f"Cannot connect to server at {self.server_url}: {e}")

    def setup_server(self, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16, num_parties: int = 10, pool_size: int = 5):
        resp = self._post("/setup", {
            "k": k,
            "m": m,
            "b": b,
            "n_dim": n_dim,
            "num_parties": num_parties,
            "pool_size": pool_size
        })
        self.server_params = {"k": k, "m": m, "b": b, "n_dim": n_dim, "num_parties": num_parties}
        return resp

    def get_demo_ciphertext(self, message: int) -> str:
        resp = self._post("/encrypt_demo", {"message": message})
        return resp["ciphertext"]

    def eval_add(self, ciphertext1_b64: str, ciphertext2_b64: str) -> str:
        resp = self._post("/eval_add", {"ciphertext1": ciphertext1_b64, "ciphertext2": ciphertext2_b64})
        return resp["ciphertext"]

    def eval_mul(self, ciphertext1_b64: str, ciphertext2_b64: str) -> str:
        resp = self._post("/eval_mul", {"ciphertext1": ciphertext1_b64, "ciphertext2": ciphertext2_b64})
        return resp["ciphertext"]

    def decrypt_one_shot(self, ciphertext_b64: str) -> Tuple[int, Dict[str, Any]]:
        self.stats.reset()
        t_start = time.perf_counter()
        resp = self._post("/decrypt", {"ciphertext": ciphertext_b64})
        total_rtt_ms = (time.perf_counter() - t_start) * 1000.0
        msg = resp["decrypted_message"]
        metrics = {
            "decrypted_message": msg,
            "total_rtt_ms": round(total_rtt_ms, 3),
            "server_latency_ms": resp.get("latency_ms", 0),
            "bytes_sent": self.stats.bytes_sent,
            "bytes_recv": self.stats.bytes_recv,
            "server_metrics": resp.get("metrics", {})
        }
        return msg, metrics

    def decrypt_interactive(self, ciphertext_b64: str) -> Tuple[int, Dict[str, Any]]:
        self.stats.reset()
        t_start = time.perf_counter()
        round_latencies = []

        # Round 1
        t0 = time.perf_counter()
        r1 = self._post("/decrypt_interactive/start", {"ciphertext": ciphertext_b64})
        session_id = r1["session_id"]
        round_latencies.append((time.perf_counter() - t0) * 1000.0)

        # Round 2
        t0 = time.perf_counter()
        r2 = self._post("/decrypt_interactive/step2", {"session_id": session_id})
        round_latencies.append((time.perf_counter() - t0) * 1000.0)

        # Round 3
        t0 = time.perf_counter()
        r3 = self._post("/decrypt_interactive/finish", {"session_id": session_id})
        round_latencies.append((time.perf_counter() - t0) * 1000.0)

        total_rtt_ms = (time.perf_counter() - t_start) * 1000.0
        msg = r3["decrypted_message"]

        metrics = {
            "decrypted_message": msg,
            "total_rtt_ms": round(total_rtt_ms, 3),
            "round_latencies_ms": [round(t, 3) for t in round_latencies],
            "bytes_sent": self.stats.bytes_sent,
            "bytes_recv": self.stats.bytes_recv,
            "total_rounds": 3
        }
        return msg, metrics


def run_local_simulation(num_parties: int = 10):
    """Fallback local simulation demonstrating CCS 2025 Homomorphic Add, Multiply & MPC Decryption."""
    print("=" * 75)
    print(f"  [CCS25] Local Simulation (Parties={num_parties}, Add + Multiply + MPC Rounding)")
    print("=" * 75)
    k, m, b = 64, 1, 8
    t_setup = time.perf_counter()
    decryptor = ThresholdFHEDecryptor(k=k, m=m, b=b, num_parties=num_parties)
    lwe = ToyLWE(n_dim=16, k=k, m=m, num_parties=num_parties)
    s_ext = [decryptor.abb.store(val, k) for val in lwe.s] + [decryptor.abb.store(1, k)]
    setup_ms = (time.perf_counter() - t_setup) * 1000.0
    print(f"[✓] Setup & KeyGen (with Gadget RelinKey for {num_parties} parties) completed in {setup_ms:.2f} ms")

    print(f"[*] Preprocessing gates offline (k={k}, m={m}, b={b})...")
    t0 = time.perf_counter()
    gates = decryptor.preprocess()
    print(f"[✓] Offline Gates Ready in {(time.perf_counter() - t0)*1000:.2f} ms")

    for m1, m2 in [(1, 0), (1, 1)]:
        c1, _ = lwe.encrypt(m1)
        c2, _ = lwe.encrypt(m2)

        # Homomorphic Addition
        t_add = time.perf_counter()
        c_add = lwe.eval_add(c1, c2)
        add_ms = (time.perf_counter() - t_add) * 1000.0
        dec_add = decryptor.decrypt(c_add, s_ext, gates)
        assert dec_add == (m1 + m2) % 2
        print(f"  [Homo Add] {m1} (+) {m2} -> Decrypted: {dec_add} (Eval: {add_ms:.4f} ms)")
        gates = decryptor.preprocess()

        # Homomorphic Multiplication
        t_mul = time.perf_counter()
        c_mul = lwe.eval_mul(c1, c2)
        mul_ms = (time.perf_counter() - t_mul) * 1000.0
        dec_mul = decryptor.decrypt(c_mul, s_ext, gates)
        assert dec_mul == (m1 * m2) % 2
        print(f"  [Homo Mul] {m1} (x) {m2} -> Decrypted: {dec_mul} (Eval: {mul_ms:.4f} ms)")
        gates = decryptor.preprocess()

    print("\n[SUCCESS] CCS 2025 Local Simulation (Add + Multiply + Decrypt) Completed Successfully!")


def run_client_demo(server_url: str = "http://127.0.0.1:8000", num_parties: int = 10):
    print("=" * 70)
    print("  Threshold FHE Client Demo (CCS 2025 Protocol)")
    print("=" * 70)
    client = ThresholdFHEClient(server_url=server_url)

    print(f"[*] Connecting to server at {server_url}...")
    try:
        health = client.check_health()
    except Exception as e:
        print(f"[!] Server connection failed ({e}). Running local simulation demo...\n")
        run_local_simulation(num_parties=num_parties)
        return

    print(f"[✓] Connected! Server params: {health['params']}")

    c1_b64 = client.get_demo_ciphertext(1)
    c2_b64 = client.get_demo_ciphertext(1)

    c_add_b64 = client.eval_add(c1_b64, c2_b64)
    rec_add, info_add = client.decrypt_interactive(c_add_b64)
    print(f"  Homo Add (1 + 1 mod 2) -> Decrypted: {rec_add} (RTT: {info_add['total_rtt_ms']} ms)")
    assert rec_add == 0

    c_mul_b64 = client.eval_mul(c1_b64, c2_b64)
    rec_mul, info_mul = client.decrypt_interactive(c_mul_b64)
    print(f"  Homo Mul (1 * 1 mod 2) -> Decrypted: {rec_mul} (RTT: {info_mul['total_rtt_ms']} ms)")
    assert rec_mul == 1

    print("\n[SUCCESS] Client demonstration completed successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCS 2025 Threshold FHE Client")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000", help="Server URL")
    parser.add_argument("--parties", type=int, default=10, help="Number of parties (10..1000)")
    parser.add_argument("--local", action="store_true", help="Run local simulation")
    args = parser.parse_args()

    if args.local:
        run_local_simulation(num_parties=args.parties)
    else:
        run_client_demo(args.server_url, num_parties=args.parties)
