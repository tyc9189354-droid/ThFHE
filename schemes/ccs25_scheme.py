import math
import random
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import (
    ThresholdFHEDecryptor,
    ToyLWE,
    PreprocessedGates,
    StoredVar
)

class CCS25ThFHEScheme(BaseThFHEScheme):
    """
    Adapter for CCS 2025:
    "High-Throughput Universally Composable Threshold FHE Decryption"
    (Guy Zyskind, Doron Zarchy, Max Leibovich, Chris Peikert)
    """

    def __init__(self, name: str = "CCS25_MPC_Rounding"):
        super().__init__(name)
        self.k = 64
        self.m = 1
        self.b = 8
        self.n_dim = 16
        self.num_parties = 10
        self.malicious_ratio = 0
        self.attack_type = "none"
        self.decryptor: Optional[ThresholdFHEDecryptor] = None
        self.lwe: Optional[ToyLWE] = None
        self.s_ext_stored: List[StoredVar] = []
        self._last_gates: Optional[PreprocessedGates] = None
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        b: Optional[int] = None,
        n_dim: int = 16,
        malicious_ratio: int = 0,
        attack_type: str = "none",
        **kwargs
    ) -> Dict[str, Any]:
        """
        [Stage 1: Setup]
        初始化公開模數 q = 2^k, p = 2^m, 捨入基底 B = 2^b, F_ABB 環境與 N 個參與方通訊通道描述。
        """
        self.k = k
        self.m = m
        self.l = k - m
        self.b = b or max(1, int(round(math.sqrt(self.l))))
        self.n_dim = n_dim
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "none"

        self.decryptor = ThresholdFHEDecryptor(
            k=self.k,
            m=self.m,
            b=self.b,
            num_parties=self.num_parties
        )
        # Setup initializes the LWE parameters without running keygen yet
        self.lwe = ToyLWE(
            n_dim=self.n_dim,
            k=self.k,
            m=self.m,
            num_parties=self.num_parties,
            auto_keygen=False
        )
        # Initialize per-party CRS / public matrix A for N parties
        self.crs_matrix = [
            [random.randint(0, self.lwe.q - 1) for _ in range(self.n_dim)]
            for _ in range(min(self.num_parties, 64))
        ]

        self.params = {
            "k": self.k,
            "m": self.m,
            "l": self.l,
            "b": self.b,
            "d": math.ceil(self.l / self.b),
            "n_dim": self.n_dim,
            "num_parties": self.num_parties
        }
        return self.params

    def keygen(self) -> Dict[str, Any]:
        """
        [Stage 2: KeyGen]
        為 N 個參與方生成秘密金鑰份額 s^{(i)} (使得 sum s^{(i)} = s mod q)、
        存入 F_ABB，並生成用於同態乘法的 Gadget 重線性化金鑰 (evk)。
        """
        if self.lwe is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties, b=self.b, n_dim=self.n_dim)

        kg_info = self.lwe.keygen(self.num_parties)
        self.s_ext_stored = [self.decryptor.abb.store(val, self.k) for val in self.lwe.s] + [self.decryptor.abb.store(1, self.k)]
        return kg_info

    def preprocess(self) -> PreprocessedGates:
        """
        [Stage 3: Offline Prep]
        離線預處理：產生 Sign 門與 ModLTZ 門，並將隨機遮罩分發給 N 個參與方。
        """
        if not self.s_ext_stored:
            self.keygen()
        self.decryptor.abb.reset_metrics()
        gates = self.decryptor.preprocess()
        # Distribute mask shares across N parties
        r_val = gates.r_combined.value
        mod_q = 1 << self.k
        acc = 0
        for _ in range(self.num_parties - 1):
            acc = (acc + random.randint(0, mod_q - 1)) % mod_q
        _last = (r_val - acc) % mod_q
        self._last_gates = gates
        return gates

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        """明文加密"""
        if not self.s_ext_stored:
            self.keygen()
        return self.lwe.encrypt(message)

    def encrypt_simd(self, messages: List[int]) -> List[List[int]]:
        """SIMD 批次明文加密"""
        if not self.s_ext_stored:
            self.keygen()
        return self.lwe.encrypt_simd(messages)

    def eval_add(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """[Stage 4a: Homo Add] 同態加法 c1 (+) c2"""
        return self.lwe.eval_add(ct1, ct2)

    def eval_add_simd(self, batch_c1: List[List[int]], batch_c2: List[List[int]]) -> List[List[int]]:
        """[Stage 4a: SIMD Homo Add] SWAR 暫存器打包平行同態加法"""
        return self.lwe.eval_add_simd(batch_c1, batch_c2)

    def eval_mul(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """[Stage 4b: Homo Mul] 同態乘法 c1 (x) c2 (含張量積縮放與 Gadget 重線性化)"""
        return self.lwe.eval_mul(ct1, ct2)

    def eval_mul_simd(self, batch_c1: List[List[int]], batch_c2: List[List[int]]) -> List[List[int]]:
        """[Stage 4b: SIMD Homo Mul] 多槽平行同態乘法 (含 Gadget 重線性化)"""
        return self.lwe.eval_mul_simd(batch_c1, batch_c2)

    def decrypt(self, ciphertext: List[int], preprocessed_data: Optional[PreprocessedGates] = None) -> int:
        """線上解密"""
        if not self.s_ext_stored:
            self.keygen()
        gates = preprocessed_data or self._last_gates or self.preprocess()
        self.decryptor.abb.reset_metrics()
        return self.decryptor.decrypt(ciphertext, self.s_ext_stored, gates)

    def decrypt_simd_with_stages(
        self,
        batch_ciphertext: List[List[int]],
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[List[int], float, float]:
        """SIMD 多槽平行門檻解密"""
        if not self.s_ext_stored:
            self.keygen()
        mr = self.malicious_ratio if malicious_ratio is None else malicious_ratio
        at = self.attack_type if attack_type is None else attack_type
        decrypted_slots = []
        total_pdec_ms = 0.0
        total_agg_ms = 0.0
        for ct in batch_ciphertext:
            gates = self._last_gates or self.preprocess()
            mu, pdec_ms, agg_ms = self.decrypt_with_stages(
                ct, gates, malicious_ratio=mr, attack_type=at
            )
            decrypted_slots.append(mu)
            total_pdec_ms += pdec_ms
            total_agg_ms += agg_ms
        return decrypted_slots, total_pdec_ms, total_agg_ms

    def decrypt_with_stages(
        self,
        ciphertext: List[int],
        preprocessed_data: Optional[PreprocessedGates] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[int, float, float]:
        """
        分別量測：
          - Stage 5 (Partial Dec & MPC Rounding): N 個參與方本地內積 + 3 輪 LTRand/Mod_{l,k} + MAC 驗證
          - Stage 6 (Aggregation & Reconstruct): N 個參與方份額聚合與最終明文揭示
        """
        if not self.s_ext_stored:
            self.keygen()
        gates = preprocessed_data or self._last_gates or self.preprocess()
        self.decryptor.abb.reset_metrics()
        mr = self.malicious_ratio if malicious_ratio is None else malicious_ratio
        at = self.attack_type if attack_type is None else attack_type
        mu, pdec_ms, agg_ms, audit_info = self.decryptor.decrypt_with_parties(
            ciphertext,
            self.lwe.party_shares,
            gates,
            malicious_ratio=mr,
            attack_type=at
        )
        self.last_audit = audit_info
        return mu, pdec_ms, agg_ms

    def decrypt_interactive(self, ciphertext: List[int], preprocessed_data: Optional[PreprocessedGates] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """多輪交互解密 (3 Sequential Openings)"""
        if not self.s_ext_stored:
            self.keygen()
        gates = preprocessed_data or self._last_gates or self.preprocess()
        self.decryptor.abb.reset_metrics()

        d = math.ceil(self.l / self.b)
        d_plus_1 = d + 1

        rounds_info = []

        # Round 1: Open [z]_l + [r]_l -> z'
        pairs = [(c_val, s_var) for c_val, s_var in zip(ciphertext, self.s_ext_stored)]
        shift = 1 << (self.l - 1)
        z_k = self.decryptor.abb.lin_comb(shift, pairs, out_len=self.k)
        z_plus_r = self.decryptor.abb.add(z_k, gates.r_combined, out_len=self.l)
        z_prime = self.decryptor.abb.open(z_plus_r, truncated_l=self.l)
        rounds_info.append({"round": 1, "action": "Open masked z'", "bits": self.l, "value": z_prime})

        # Round 2: Base B decomposition & Sign lookups -> Open [y]_{d+1} + [r_modltz]_{d+1} -> y'
        z_temp = z_prime
        z_digits = []
        for i in range(d):
            cur_b = self.b if i < d - 1 else (self.l - (d - 1) * self.b)
            digit = z_temp & ((1 << cur_b) - 1)
            z_digits.append(digit)
            z_temp >>= cur_b

        y_shares = [gates.sign_gates[i][1][z_digits[i]] for i in range(d)]
        comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
        y_sum = self.decryptor.abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

        r_modltz, modltz_table = gates.modltz_gate
        y_masked = self.decryptor.abb.add(y_sum, r_modltz, out_len=d_plus_1)
        y_prime = self.decryptor.abb.open(y_masked, truncated_l=d_plus_1)
        u_k = modltz_table[y_prime]
        rounds_info.append({"round": 2, "action": "Open masked y'", "bits": d_plus_1, "value": y_prime})

        # Round 3: Compute [e]_k, then Open [z]_k - [e]_k -> mu
        e_k = self.decryptor.abb.lin_comb(z_prime, [(-1, gates.r_combined), (1 << self.l, u_k)], out_len=self.k)
        mu_scaled = self.decryptor.abb.sub(z_k, e_k, out_len=self.k)
        mu_prime = self.decryptor.abb.open(mu_scaled, truncated_l=self.k)
        mu = (mu_prime // self.decryptor.L) % self.decryptor.p
        rounds_info.append({"round": 3, "action": "Open unmasked mu'", "bits": self.k, "value": mu})

        return mu, rounds_info

    def get_offline_metrics(self, preprocessed_data: Optional[PreprocessedGates] = None) -> Dict[str, Any]:
        """計算離線儲存與乘法次數 (對齊論文 Formula 5 與 Section 3.4/5.2)"""
        d = math.ceil(self.l / self.b)
        b_prime = self.l - (d - 1) * self.b
        gate_storage_bits = (d + 1) * ((d - 1) * (1 << self.b) + (1 << b_prime)) + self.m * (1 << (d + 1))

        mults_signs = (d - 1) * ((1 << self.b) - self.b - 1) + ((1 << b_prime) - b_prime - 1)
        mults_modltz = (1 << (d + 1)) - (d + 1) - 1
        total_mults = mults_signs + mults_modltz
        rand_bits = self.l + (d + 1)

        return {
            "num_mults": total_mults,
            "num_rand_bits": rand_bits,
            "gate_storage_bits": gate_storage_bits,
            "gate_storage_bytes": (gate_storage_bits + 7) // 8
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        d = math.ceil(self.l / self.b)
        opened_bits = self.l + (d + 1) + self.k
        return {
            "num_opens": 3,
            "opened_bits": opened_bits,
            "num_mults": 0,
            "num_rounds": 3
        }
