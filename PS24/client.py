#!/usr/bin/env python3
r"""
================================================================================
PS24: Client Module (Threshold FHE Party)
Paper: "Low Communication Threshold Fully Homomorphic Encryption"
       (Alain Passelegue & Damien Stehle, ePrint 2024/1984)
================================================================================
Implements PartDec (Fig. 3):
    p_i = <ct_dec,0, sk_i> + d_i  mod q_dec,    d_i <- D_{Z, eta}
The ciphertext handed to the parties lives modulo the SMALL q_dec (about 22 bits in this demo),
so the added noise eta is tiny and each decryption share is a single q_dec-sized integer.
================================================================================
"""

import os
import sys
import json
import urllib.request
from typing import Dict, Any, List
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import PS24ThFHE


class PS24Client:
    def __init__(self, server_url: str = "http://127.0.0.1:8007", party_id: int = 1):
        self.server_url = server_url.rstrip("/")
        self.party_id = party_id

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{self.server_url}{endpoint}", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def compute_part_dec(self, a_dec: List[int], ps24: PS24ThFHE) -> int:
        """PartDec of this party using the key share held by the in-process PS24ThFHE instance."""
        return ps24.part_dec(self.party_id, np.asarray(a_dec, dtype=object))


if __name__ == "__main__":
    print("[*] Testing PS24 client against server...")
    client = PS24Client()
    try:
        info = client._post("/api/start_dec", {"msg": 2})
        print("  -> start_dec OK, N:", info.get("num_parties"))
    except Exception as e:
        print(f"  [!] Note: Server may not be running locally ({e}). Client ready.")
