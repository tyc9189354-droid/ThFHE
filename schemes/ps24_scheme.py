#!/usr/bin/env python3
r"""
================================================================================
PS24 Benchmark Adapter: "Low Communication Threshold Fully Homomorphic Encryption"
(Alain Passelegue & Damien Stehle, ePrint 2024/1984, revised March 2025)
================================================================================
Unified Benchmark Adapter for the Double-Flood-and-Round construction (Figures 2 and 3):
  - Setup        : Q = p * q_dec, sigma_flood = 2^lambda * B_eval, eta, sigma_0, sigma_1
  - KeyGen       : LWE/BFV key over Z_Q (pk, evk), additive sharing sk = sk_1 + ... + sk_N mod q_dec
  - Offline Prep : fresh encryptions Enc(pk, 0) consumed by ServerDec (public-key only)
  - Homomorphic  : addition and BFV multiplication with gadget relinearisation over Z_Q
  - Partial Dec  : ServerDec (flood E, rescale Z_Q -> Z_qdec by randomised Gaussian rounding) + PartDec (tiny noise eta)
  - Aggregation  : FinDec  z = sum_i p_i + ct_dec,1 mod q_dec, then Decode
================================================================================
"""

import math
import time
import secrets
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import PS24ThFHE


class PS24ThFHEScheme(BaseThFHEScheme):
    """Adapter for Passelegue & Stehle (ePrint 2024/1984)."""

    def __init__(self, name: str = "PS24 (ePrint 2024/1984: Double-Flood-and-Round)"):
        super().__init__(name)
        self.n_dim = 16
        self.k = 64
        self.m = 1
        self.p = 4
        self.num_parties = 10
        self.threshold = 10
        self.malicious_ratio = 0
        self.attack_type = "none"
        self.ps24: Optional[PS24ThFHE] = None
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        n_dim: int = 16,
        threshold: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        r"""[Stage 1: Setup] Q = p * q_dec, sigma_flood = 2^lambda B_eval, eta, sigma_0, sigma_1"""
        self.k = k
        self.m = m
        self.n_dim = n_dim
        self.num_parties = max(3, min(1000, int(num_parties)))
        self.threshold = self.num_parties            # N-out-of-N
        self.malicious_ratio = int(kwargs.get("malicious_ratio", 0))
        self.attack_type = str(kwargs.get("attack_type", "none") or "none")
        self.p = int(kwargs.get("p_plain", min(1 << max(1, int(m)), 16)))
        self.ps24 = PS24ThFHE(
            n_dim=self.n_dim,
            p=self.p,
            num_parties=self.num_parties,
            lambda_flood=20,
        )
        self.q = self.ps24.Q
        self.params = self.ps24.setup()
        return self.params

    def keygen(self) -> Dict[str, Any]:
        r"""[Stage 2: KeyGen] (sk, pk, evk) over Z_Q and additive shares of sk modulo q_dec"""
        if self.ps24 is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties, n_dim=self.n_dim)
        info = self.ps24.keygen()
        self.last_audit["keygen"] = info
        return info

    def preprocess(self) -> Any:
        r"""[Stage 3: Offline Prep] pre-compute ct_fresh = Enc(pk, 0) used by ServerDec"""
        if self.ps24 is None or self.ps24.s is None:
            self.keygen()
        pool = self.ps24.preprocess(count=2)
        return {
            "type": "ps24_fresh_zero_pool",
            "parties": self.num_parties,
            "threshold": self.threshold,
            "pool": pool,
        }

    def encrypt(self, message: int) -> Tuple[Any, Any]:
        if self.ps24 is None or self.ps24.s is None:
            self.keygen()
        ct = self.ps24.encrypt(message)
        return ct, {"message": message}

    def eval_add(self, ct1: Any, ct2: Any) -> Any:
        return self.ps24.eval_add(ct1, ct2)

    def eval_mul(self, ct1: Any, ct2: Any) -> Any:
        return self.ps24.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> int:
        res, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return res

    def decrypt_with_stages(
        self,
        ciphertext: Any,
        preprocessed_data: Optional[Any] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None,
    ) -> Tuple[int, float, float]:
        r"""
        PS24 N-out-of-N threshold decryption:
          - partial_dec_ms: ServerDec (flood + Gaussian rescale Z_Q -> Z_qdec) and every party's PartDec
          - agg_ms        : FinDec (sum of the N shares + ct_dec,1, then Decode)
        PS24 is a semi-honest construction, injected corrupted shares therefore corrupt the output.
        """
        if self.ps24 is None or self.ps24.s is None:
            self.keygen()

        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio or 0)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        mal_count = (self.num_parties * mr) // 100 if (mr > 0 and at != "none") else 0
        mal_set = set()
        if mal_count > 0:
            rng = secrets.SystemRandom()
            mal_set = set(rng.sample(range(1, self.num_parties + 1), min(mal_count, self.num_parties)))

        res, pdec_ms, agg_ms = self.ps24.decrypt_full(ciphertext, malicious_set=mal_set, attack_type=at)
        self.last_audit = {
            "security_model": "Semi-Honest N-out-of-N Threshold FHE with ServerDec (no ZK / no MAC)",
            "malicious_parties": sorted(mal_set),
            "malicious_count": len(mal_set),
            "attack_type": at if mal_set else "none",
            "Q": self.ps24.Q,
            "Q_bits": self.ps24.Q.bit_length(),
            "p_round": self.ps24.p_round,
            "q_dec": self.ps24.q_dec,
            "q_dec_bits": self.ps24.q_dec.bit_length(),
            "sigma_flood": self.ps24.sigma_flood,
            "sigma_0": self.ps24.sigma_0,
            "sigma_1": self.ps24.sigma_1,
            "eta": self.ps24.eta,
            "sigma_dec": round(self.ps24.sigma_dec, 3),
            "decode_margin": int(self.ps24.q_dec // (2 * self.ps24.p_plain)),
            "aborted": False,
        }
        return res, pdec_ms, agg_ms

    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        if self.ps24 is None:
            return {"gate_storage_bits": 0}
        return {
            "gate_storage_bits": int(self.ps24.q_dec.bit_length() * self.n_dim * self.num_parties),
            "ct_dec_bits": int(self.ps24.q_dec.bit_length() * (self.n_dim + 1)),
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        bits = (self.ps24.q_dec.bit_length() * self.num_parties) if self.ps24 else 0
        return {
            "num_rounds": 1,
            "num_opens": 1,
            "opened_bits": int(bits),
            "num_mults": 0,
        }
