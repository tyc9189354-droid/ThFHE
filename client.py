#!/usr/bin/env python3
"""
================================================================================
Client Module: Client for Threshold FHE Decryption
Based on CCS 2025: "High-Throughput Universally Composable Threshold FHE Decryption"
================================================================================

Role:
  - Connects to the Cloud / Coordinator Server
  - Encrypts messages into LWE ciphertexts
  - Sends decryption requests (both One-Shot and 3-Round Interactive MPC modes)
  - Measures communication overhead (bytes sent/received) and network latency
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List, Tuple, Optional

from tool import (
    ToyLWE,
    encode_ciphertext,
    decode_ciphertext
)

class CommStats:
    """Tracks network communication metrics."""
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
    """Client for Threshold FHE Decryption Server."""

    def __init__(self, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url.rstrip("/")
        self.stats = CommStats()
        self.lwe: Optional[ToyLWE] = None
        self.server_params: Dict[str, Any] = {}

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        sent_size = len(body)

        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_bytes = resp.read()
                recv_size = len(resp_bytes)
                self.stats.record_tx(sent_size, recv_size)
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to communicate with server at {url}: {e}")

    def check_health(self) -> Dict[str, Any]:
        """Checks if the server is healthy and fetches parameters."""
        url = f"{self.server_url}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.server_params = data.get("params", {})
                return data
        except Exception as e:
            raise ConnectionError(f"Cannot connect to server at {self.server_url}: {e}")

    def setup_server(self, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16, pool_size: int = 5):
        """Instructs the server to initialize parameters and secret key."""
        resp = self._post("/setup", {
            "k": k, "m": m, "b": b, "n_dim": n_dim, "pool_size": pool_size
        })
        self.server_params = {"k": k, "m": m, "b": b, "n_dim": n_dim}
        return resp

    def get_demo_ciphertext(self, message: int) -> str:
        """Requests an encrypted sample ciphertext from the server."""
        resp = self._post("/encrypt_demo", {"message": message})
        return resp["ciphertext"]

    def decrypt_one_shot(self, ciphertext_b64: str) -> Tuple[int, Dict[str, Any]]:
        """
        One-Shot Decryption: Sends ciphertext to server, which performs all
        rounds and returns the decrypted message.
        """
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
        """
        Interactive MPC Decryption (3 Sequential Rounds):
        Corresponds to the 3 public openings in Section 3.4:
          Round 1: Open [z]_l + [r]_l -> z'
          Round 2: Look up Sign gates, Open [y]_{d+1} + [r_modltz]_{d+1} -> y'
          Round 3: Apply ModLTZ gate, Open [z]_k - [e]_k -> mu
        """
        self.stats.reset()
        t_start = time.perf_counter()
        round_latencies = []

        # --- Round 1 ---
        t0 = time.perf_counter()
        r1 = self._post("/decrypt_interactive/start", {"ciphertext": ciphertext_b64})
        session_id = r1["session_id"]
        round_latencies.append((time.perf_counter() - t0) * 1000.0)

        # --- Round 2 ---
        t0 = time.perf_counter()
        r2 = self._post("/decrypt_interactive/step2", {"session_id": session_id})
        round_latencies.append((time.perf_counter() - t0) * 1000.0)

        # --- Round 3 ---
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


def run_client_demo(server_url: str = "http://127.0.0.1:8000"):
    print("=" * 70)
    print("  Threshold FHE Client Demo (CCS 2025 Protocol)")
    print("=" * 70)

    client = ThresholdFHEClient(server_url=server_url)

    # 1. Health check
    print(f"[*] Connecting to server at {server_url}...")
    health = client.check_health()
    print(f"[✓] Connected! Server status: {health['status']}, params: {health['params']}")

    # 2. Test messages
    test_messages = [0, 1]

    print("\n" + "-" * 70)
    print("  Mode 1: One-Shot Decryption")
    print("-" * 70)
    for msg in test_messages:
        # Request demo ciphertext from server
        c_b64 = client.get_demo_ciphertext(msg)
        recovered, info = client.decrypt_one_shot(c_b64)
        print(f"  Input: {msg} -> Decrypted: {recovered} | Correct: {recovered == msg}")
        print(f"    Total RTT: {info['total_rtt_ms']} ms | Server: {info['server_latency_ms']} ms")
        print(f"    Network: Sent={info['bytes_sent']} B, Recv={info['bytes_recv']} B")
        print(f"    Server ABB Openings: {info['server_metrics'].get('num_opens', 3)}")

    print("\n" + "-" * 70)
    print("  Mode 2: 3-Round Interactive MPC Decryption (Exact Paper Protocol)")
    print("-" * 70)
    for msg in test_messages:
        c_b64 = client.get_demo_ciphertext(msg)
        recovered, info = client.decrypt_interactive(c_b64)
        print(f"  Input: {msg} -> Decrypted: {recovered} | Correct: {recovered == msg}")
        print(f"    Total RTT: {info['total_rtt_ms']} ms (Rounds: {info['round_latencies_ms']} ms)")
        print(f"    Network: Sent={info['bytes_sent']} B, Recv={info['bytes_recv']} B")

    print("\n" + "=" * 70)
    print("  [SUCCESS] Client demonstration completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCS 2025 Threshold FHE Client")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000", help="Server URL")
    parser.add_argument("--message", type=int, choices=[0, 1], help="Specific message to test")
    args = parser.parse_args()

    if args.message is not None:
        client = ThresholdFHEClient(server_url=args.server_url)
        client.check_health()
        c_b64 = client.get_demo_ciphertext(args.message)
        recovered, info = client.decrypt_interactive(c_b64)
        print(f"Decrypted: {recovered} (Expected: {args.message}) in {info['total_rtt_ms']} ms")
    else:
        run_client_demo(args.server_url)
