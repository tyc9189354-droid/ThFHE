#!/usr/bin/env python3
r"""
================================================================================
Ajax: Client Module (Threshold FHE Party / Decryptor)
Paper: "Ajax: Fast Threshold Fully Homomorphic Encryption without Noise Flooding"
       (Hu et al., USENIX Security 2025)
================================================================================
Implements:
  - Protocol \Pi_Dec (Section 4.3):
    1. Local computation of <u_i>_q = b - <a, <s_i>_q>
    2. Modulus switching to <u'_i>_\eta and extraction of <e'_i>_\Phi mod \Phi
    3. Round 1: Masking with double-ring share <r_i>_\Phi and opening <v_i>_\Phi
    4. Round 2: Subtraction of noise in Z_\eta: <\Phi * m>_\eta = <u'_i>_\eta - (v - <r_i>_\eta)
================================================================================
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
for p in [CURRENT_DIR, PARENT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from tool import AjaxThFHE

class AjaxClient:
    def __init__(self, server_url: str = "http://127.0.0.1:8004", party_id: int = 0):
        self.server_url = server_url.rstrip("/")
        self.party_id = party_id
        self.s_i: Optional[np.ndarray] = None
        self.r_eta_i: int = 0
        self.r_phi_i: int = 0
        _default = AjaxThFHE()
        self.q = _default.q
        self.p = _default.p
        self.eta = _default.eta
        self.Phi = _default.Phi
        self.u_prime_i: int = 0

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def compute_round1_share(self, a_vec: List[int], b_scalar: int, s_i: np.ndarray, r_phi_i: int) -> int:
        self.s_i = s_i
        self.r_phi_i = r_phi_i
        if self.party_id == 0:
            u_i = (b_scalar - int(np.dot(a_vec, s_i))) % self.q
        else:
            u_i = (- int(np.dot(a_vec, s_i))) % self.q

        # Modulus switch to eta
        self.u_prime_i = int(round((self.eta / self.q) * u_i)) % self.eta
        e_prime_i = self.u_prime_i % self.Phi
        v_share = (e_prime_i + r_phi_i) % self.Phi
        return v_share

    def compute_round2_share(self, v_open: int, r_eta_i: int) -> int:
        self.r_eta_i = r_eta_i
        v_centered = v_open if v_open <= self.Phi // 2 else v_open - self.Phi
        if self.party_id == 0:
            e_p_eta_i = (v_centered - r_eta_i) % self.eta
        else:
            e_p_eta_i = (- r_eta_i) % self.eta

        phi_m_i = (self.u_prime_i - e_p_eta_i) % self.eta
        return phi_m_i

if __name__ == "__main__":
    print("[*] Testing Ajax Client against Server...")
    client = AjaxClient()
    try:
        dec_req = client._post("/api/start_dec", {"msg": 2})
        print("  -> start_dec OK, threshold:", dec_req.get("threshold"))
    except Exception as e:
        print(f"  [!] Note: Server may not be running locally ({e}). Client ready.")
