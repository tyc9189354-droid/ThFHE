#!/usr/bin/env python3
r"""
================================================================================
OT25: Client Module (Threshold FHE Party)
Paper: "Low Communication Threshold FHE from Standard (Module-)LWE"
       (Hiroki Okada & Tsuyoshi Takagi, Asiacrypt 2025)
================================================================================
Implements:
  - PartDec (Algorithm 3 / Algorithm 6):
    pd_i := \lambda_{act, i} * (a_bar^T * s_i + \zeta_i^{(sid)}) + m_i mod q
  - PRF masking m_i = PRF(seed_i, sid) mod q
  - Lagrange polynomial interpolation weight \lambda_{act, i}
  - HTTP client for remote benchmark / distributed interaction
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

from tool import OT25ThFHE

class OT25Client:
    def __init__(self, server_url: str = "http://127.0.0.1:8003", party_id: int = 1):
        self.server_url = server_url.rstrip("/")
        self.party_id = party_id
        self.s_i: Optional[np.ndarray] = None
        self.seed: Optional[int] = None
        self.zeta_i_map: Dict[int, int] = {}
        self.q = 65537

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def compute_part_dec(
        self,
        a_bar: List[int],
        active_parties: List[int],
        sid: int,
        ot25_instance: Optional[OT25ThFHE] = None
    ) -> int:
        if ot25_instance is not None:
            a_arr = np.array(a_bar, dtype=np.int64)
            return ot25_instance.part_dec(self.party_id, a_arr, active_parties, sid)

        # Fallback local Lagrange and PRF
        num = 1
        den = 1
        for j in active_parties:
            if j != self.party_id:
                num = (num * (-j)) % self.q
                den = (den * (self.party_id - j)) % self.q
        lam = (num * pow(den, self.q - 2, self.q)) % self.q

        zeta_i = self.zeta_i_map.get(sid, 0)
        s_i = self.s_i if self.s_i is not None else np.zeros(len(a_bar), dtype=np.int64)
        term = (int(np.dot(a_bar, s_i)) + zeta_i) % self.q
        import hmac, hashlib
        h = hmac.new(str(self.seed or 12345).encode(), str(sid).encode(), hashlib.sha256).digest()
        m_i = int.from_bytes(h[:4], "big") % self.q
        return (lam * term + m_i) % self.q

    def submit_part_dec(self, pd_share: int) -> Dict[str, Any]:
        return self._post("/api/submit_share", {
            "party_id": self.party_id,
            "pd_share": pd_share
        })

    def request_server_dec(self, msg: int = 1) -> Dict[str, Any]:
        return self._post("/api/server_dec", {"msg": msg})

    def request_fin_dec(self) -> Dict[str, Any]:
        return self._post("/api/fin_dec", {})

if __name__ == "__main__":
    print("[*] Testing OT25 Client against Server...")
    client = OT25Client()
    try:
        sdec = client.request_server_dec(msg=1)
        print("  -> ServerDec OK, sid:", sdec.get("sid"))
        pd_val = client.compute_part_dec(sdec["a_bar"], sdec["active_parties"], sdec["sid"])
        client.submit_part_dec(pd_val)
        fin = client.request_fin_dec()
        print("  -> FinDec result:", fin)
    except Exception as e:
        print(f"  [!] Note: Server may not be running locally ({e}). Client ready.")
