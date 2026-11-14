#!/usr/bin/env python3
r"""
================================================================================
BS23: Client Module (Threshold FHE Party)
Paper: "Simple Threshold (Fully Homomorphic) Encryption From LWE With Polynomial Modulus"
       (Katharina Boudgoust & Peter Scholl, ASIACRYPT 2023)
================================================================================
Implements PartDec (Fig. 7):
    d_{i,j} = <ct_a, sk_{i,j}> + e_{i,j},   e_{i,j} <- D_flood   for j = 1..L
The flooding width sigma_flood is only a POLYNOMIAL factor larger than the ciphertext noise
(Renyi-divergence analysis), instead of 2^lambda times larger.
================================================================================
"""

import os
import sys
import json
import urllib.request
from typing import Dict, Any, List, Optional
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import BS23ThFHE


class BS23Client:
    def __init__(self, server_url: str = "http://127.0.0.1:8006", party_id: int = 1):
        self.server_url = server_url.rstrip("/")
        self.party_id = party_id

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{self.server_url}{endpoint}", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def compute_part_dec(self, ct_a: List[int], bs23: BS23ThFHE) -> List[int]:
        """PartDec of this party using the share elements held by the in-process BS23ThFHE instance."""
        return bs23.part_dec(self.party_id, (np.asarray(ct_a, dtype=object), 0))


if __name__ == "__main__":
    print("[*] Testing BS23 client against server...")
    client = BS23Client()
    try:
        info = client._post("/api/start_dec", {"msg": 2})
        print("  -> start_dec OK, threshold:", info.get("threshold"))
    except Exception as e:
        print(f"  [!] Note: Server may not be running locally ({e}). Client ready.")
