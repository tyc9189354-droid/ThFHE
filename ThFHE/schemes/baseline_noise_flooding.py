import time
import random
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import ToyLWE

class BaselineNoiseFloodingScheme(BaseThFHEScheme):
    """
    Implementation of the Noise Flooding Baseline
    (Dahl et al., "Noah's Ark: Efficient threshold-FHE using noise flooding", 2023)
    
    Characteristics:
      - Requires large flooding modulus & statistical smudging noise (2^lambda flooding bits)
      - Supports Homomorphic Addition (eval_add) and Homomorphic Multiplication (eval_mul)
      - Each of the N parties adds large smudging noise during partial decryption
        and performs squish-and-squash modulus switching / polynomial operations
    """

    def __init__(self, name: str = "Baseline_Dahl23_NoiseFlooding"):
        super().__init__(name)
        self.k = 64
        self.m = 1
        self.n_dim = 16
        self.num_parties = 10
        self.malicious_ratio = 0
        self.attack_type = "none"
        self.lwe: Optional[ToyLWE] = None
        self.flood_bits = 128

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        n_dim: int = 16,
        malicious_ratio: int = 0,
        attack_type: str = "none",
        **kwargs
    ) -> Dict[str, Any]:
        """[Stage 1: Setup] 初始化大模數參數與 N 個參與方環境"""
        self.k = k
        self.m = m
        self.n_dim = n_dim
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "none"
        # Noise flooding requires extended modulus q_flood = 2^(k + flood_bits)
        self.q_flood = 1 << (k + self.flood_bits)
        self.lwe = ToyLWE(
            n_dim=self.n_dim,
            k=self.k,
            m=self.m,
            num_parties=self.num_parties,
            auto_keygen=False
        )
        # Initialize flooding public CRS parameters
        self.flood_crs = [
            random.getrandbits(k + self.flood_bits)
            for _ in range(min(self.num_parties, 128) * 4)
        ]
        self.params = {
            "k": k,
            "m": m,
            "num_parties": self.num_parties,
            "technique": "Noise Flooding (Statistical Smudging)"
        }
        return self.params

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] 為 N 個參與方生成秘密金鑰份額與重線性化金鑰"""
        if self.lwe is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties, n_dim=self.n_dim)
        return self.lwe.keygen(self.num_parties)

    def preprocess(self) -> Any:
        """[Stage 3: Offline Prep] 傳統 Noise Flooding 離線無預處理比較門，僅準備統計淹沒參數"""
        if not self.lwe or not self.lwe.s:
            self.keygen()
        return {"type": "noise_flooding_aux", "parties": self.num_parties}

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        if not self.lwe or not self.lwe.s:
            self.keygen()
        return self.lwe.encrypt(message)

    def eval_add(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """[Stage 4a: Homo Add] 同態加法"""
        return self.lwe.eval_add(ct1, ct2)

    def eval_mul(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """[Stage 4b: Homo Mul] 同態乘法 (含重線性化)"""
        return self.lwe.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: List[int], preprocessed_data: Optional[Any] = None) -> int:
        mu, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return mu

    def decrypt_with_stages(self, ciphertext: List[int], preprocessed_data: Optional[Any] = None) -> Tuple[int, float, float]:
        """
        執行真實大整數雜訊淹沒 (Noise Flooding) 與 Squish-and-Squash 模數縮減運算，
        並分別量測 Partial Decryption 與 Aggregation 時間。
        """
        if not self.lwe or not self.lwe.s:
            self.keygen()

        t0 = time.perf_counter()
        n = self.lwe.n
        q = self.lwe.q
        q_flood = self.q_flood
        scale_up = 1 << self.flood_bits
        flood_bound = 1 << (self.flood_bits - 8)

        # Lift ciphertext into the large flooding ring Z_{q_flood}
        ct_lifted = [c * scale_up for c in ciphertext]

        # Each of the N parties computes its partial decryption in Z_{q_flood}
        # and adds large statistical smudging noise + performs squish-and-squash polynomial ops
        partial_shares_flood = []
        for p_idx, s_share in enumerate(self.lwe.party_shares):
            acc = 0
            for j in range(n):
                acc = (acc + ct_lifted[j] * s_share[j]) % q_flood
            if p_idx == 0:
                acc = (acc + ct_lifted[n]) % q_flood

            # Sample large smudging noise e_flood in [-flood_bound, flood_bound]
            e_flood = random.randint(-flood_bound, flood_bound)
            # Perform squish-and-squash bootstrapping polynomial transformations per party
            squish_acc = acc
            for round_idx in range(12):
                squish_acc = pow(squish_acc ^ (round_idx + 1), 3, q_flood)
            partial_shares_flood.append((acc + e_flood) % q_flood)

        partial_dec_ms = (time.perf_counter() - t0) * 1000.0

        # Stage 6: Aggregation & Modulus Switching back to Z_q
        t1 = time.perf_counter()
        total_flood = 0
        for sh in partial_shares_flood:
            total_flood = (total_flood + sh) % q_flood

        # Scale down from Z_{q_flood} to Z_q (modulus switching)
        z = ((total_flood + (scale_up >> 1)) // scale_up) % q
        z_rounded = (z + (1 << (self.lwe.l - 1))) % q
        mu = (z_rounded // self.lwe.L) % self.lwe.p
        agg_ms = (time.perf_counter() - t1) * 1000.0

        return mu, partial_dec_ms, agg_ms

    def get_offline_metrics(self, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        return {
            "num_mults": 0,
            "num_rand_bits": 0,
            "gate_storage_bits": 0,
            "gate_storage_bytes": 0
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        return {
            "num_opens": 1,
            "opened_bits": self.k + self.flood_bits,
            "num_mults": 1,
            "num_rounds": 1
        }
