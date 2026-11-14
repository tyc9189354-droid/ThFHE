#!/usr/bin/env python3
r"""
================================================================================
BS23 Benchmark Adapter: "Simple Threshold (Fully Homomorphic) Encryption From LWE
With Polynomial Modulus"  (Katharina Boudgoust & Peter Scholl, ASIACRYPT 2023)
================================================================================
Unified Benchmark Adapter for the BS23 scheme (Fig. 7 of the paper):
  - Setup        : modulus q, Renyi order a, flooding width sigma_flood, LSSS parameters (L, tau_max, tau_min)
  - KeyGen       : LWE/BFV key (pk, evk) and LSS.Share(sk)  (replicated / additive sharing, {0,1}-reconstruction)
  - Offline Prep : pre-sampling of the Renyi flooding noise e_{i,j} <- D_flood (independent of the ciphertext)
  - Homomorphic  : addition and BFV multiplication with gadget relinearisation (public data only)
  - Partial Dec  : d_{i,j} = <ct, sk_{i,j}> + e_{i,j}              (NO server-side randomisation, NO exponential noise)
  - Aggregation  : Combine = 0/1 selection of share elements + round(p/q * y)
================================================================================
"""

import math
import time
import secrets
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import BS23ThFHE


class BS23ThFHEScheme(BaseThFHEScheme):
    """Adapter for Boudgoust & Scholl (ASIACRYPT 2023)."""

    def __init__(self, name: str = "BS23 (ASIACRYPT 2023: Renyi Noise Flooding + LSSS)"):
        super().__init__(name)
        self.n_dim = 16
        self.k = 64
        self.m = 1
        self.p = 4
        self.num_parties = 10
        self.threshold = 5
        self.malicious_ratio = 0
        self.attack_type = "none"
        self.bs23: Optional[BS23ThFHE] = None
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
        r"""[Stage 1: Setup] q, Renyi order a, sigma_flood = beta*sqrt(l*(nL-tau_max)*(a-1)), LSSS parameters"""
        self.k = k
        self.m = m
        self.n_dim = n_dim
        self.num_parties = max(3, min(1000, int(num_parties)))
        self.malicious_ratio = int(kwargs.get("malicious_ratio", 0))
        self.attack_type = str(kwargs.get("attack_type", "none") or "none")
        self.p = int(kwargs.get("p_plain", min(1 << max(1, int(m)), 16)))
        self.bs23 = BS23ThFHE(
            n_dim=self.n_dim,
            p=self.p,
            num_parties=self.num_parties,
            threshold=threshold,
            ell=64,
            renyi_order=16,
        )
        self.threshold = self.bs23.threshold
        self.q = self.bs23.q
        self.params = self.bs23.setup()
        return self.params

    def keygen(self) -> Dict[str, Any]:
        r"""[Stage 2: KeyGen] LWE key pair, evk and LSS.Share(sk)"""
        if self.bs23 is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties, n_dim=self.n_dim)
        info = self.bs23.keygen()
        self.last_audit["keygen"] = info
        return info

    def preprocess(self) -> Any:
        r"""[Stage 3: Offline Prep] pre-sample Renyi flooding noise e_{i,j} for upcoming decryptions"""
        if self.bs23 is None or self.bs23.s is None:
            self.keygen()
        pool = self.bs23.preprocess(count=2)
        return {
            "type": "bs23_flood_noise_pool",
            "parties": self.num_parties,
            "effective_parties": self.bs23.n_eff,
            "threshold": self.threshold,
            "pool": pool,
        }

    def encrypt(self, message: int) -> Tuple[Any, Any]:
        if self.bs23 is None or self.bs23.s is None:
            self.keygen()
        ct = self.bs23.encrypt(message)
        return ct, {"message": message}

    def eval_add(self, ct1: Any, ct2: Any) -> Any:
        return self.bs23.eval_add(ct1, ct2)

    def eval_mul(self, ct1: Any, ct2: Any) -> Any:
        return self.bs23.eval_mul(ct1, ct2)

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
        BS23 threshold decryption (single non-interactive round):
          - partial_dec_ms: every active party computes d_{i,j} = <ct, sk_{i,j}> + e_{i,j}  (j = 1..L)
          - agg_ms        : Combine = sum of a 0/1 selection of the d_{i,j}, then round(p/q * y)
        BS23's main construction is semi-honest (robustness only via the extra Section 4/App. D tools);
        injected share corruption therefore really corrupts the reconstructed phase.
        """
        if self.bs23 is None or self.bs23.s is None:
            self.keygen()

        active = list(range(1, self.bs23.threshold + 1))
        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio or 0)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        mal_count = (self.num_parties * mr) // 100 if (mr > 0 and at != "none") else 0
        mal_set = set()
        if mal_count > 0:
            rng = secrets.SystemRandom()
            mal_set = set(rng.sample(active, min(mal_count, len(active))))

        res, pdec_ms, agg_ms = self.bs23.decrypt_full(
            ciphertext, active_parties=active, malicious_set=mal_set, attack_type=at
        )
        tr = getattr(self.bs23, "last_trace", {})
        phase = int(tr.get("phase_after_combine", 0))
        residual = self.bs23._center(phase - self.bs23.Delta * res)
        self.last_audit = {
            "security_model": "Semi-Honest Renyi-Flooded Threshold FHE (OW-CPA core, no ZK / no MAC)",
            "sharing": self.bs23.sharing,
            "active_parties": active,
            "malicious_parties": sorted(mal_set),
            "malicious_count": len(mal_set),
            "attack_type": at if mal_set else "none",
            "q": self.bs23.q,
            "q_bits": self.bs23.q.bit_length(),
            "sigma_flood": self.bs23.sigma_flood,
            "beta_fhe": self.bs23.beta_fhe,
            "renyi_order": self.bs23.renyi_order,
            "eps_rd": round(self.bs23.eps_rd, 6),
            "L": self.bs23.L,
            "tau_min": self.bs23.tau_min,
            "tau_max": self.bs23.tau_max,
            "terms_summed": tr.get("terms_summed", self.bs23.tau_min),
            "effective_parties": self.bs23.n_eff,
            "residual_noise": int(residual),
            "decode_margin": int(self.bs23.Delta // 2),
            "queries_used": self.bs23.queries,
            "query_bound": self.bs23.ell,
            "aborted": False,
        }
        return res, pdec_ms, agg_ms

    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        if self.bs23 is None:
            return {"gate_storage_bits": 0}
        elems = self.bs23.n_eff * self.bs23.L * self.n_dim
        return {
            "gate_storage_bits": int(elems * self.bs23.q.bit_length()),
            "share_elements_per_party": self.bs23.L,
            "share_bits_requested_log2": self.bs23.share_bits_requested,
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        l_bits = (self.bs23.L * self.bs23.q.bit_length() * self.bs23.threshold) if self.bs23 else 0
        return {
            "num_rounds": 1,
            "num_opens": 1,
            "opened_bits": int(l_bits),
            "num_mults": 0,
        }
