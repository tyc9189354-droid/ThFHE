import math
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
        self.decryptor: Optional[ThresholdFHEDecryptor] = None
        self.lwe: Optional[ToyLWE] = None
        self.s_ext_stored: List[StoredVar] = []
        self._last_gates: Optional[PreprocessedGates] = None

    def setup(self, k: int = 64, m: int = 1, b: Optional[int] = None, n_dim: int = 16, **kwargs) -> Dict[str, Any]:
        self.k = k
        self.m = m
        self.l = k - m
        self.b = b or max(1, int(round(math.sqrt(self.l))))
        self.n_dim = n_dim

        self.decryptor = ThresholdFHEDecryptor(k=self.k, m=self.m, b=self.b)
        self.lwe = ToyLWE(n_dim=self.n_dim, k=self.k, m=self.m)

        # 模擬將密鑰向量存入 F_ABB: s_ext = (s_0, ..., s_{n-1}, 1)
        self.s_ext_stored = [self.decryptor.abb.store(val, self.k) for val in self.lwe.s] + [self.decryptor.abb.store(1, self.k)]

        self.params = {
            "k": self.k,
            "m": self.m,
            "l": self.l,
            "b": self.b,
            "d": math.ceil(self.l / self.b),
            "n_dim": self.n_dim
        }
        return self.params

    def preprocess(self) -> PreprocessedGates:
        """離線預處理：產生 Sign 門與 ModLTZ 門"""
        self.decryptor.abb.reset_metrics()
        gates = self.decryptor.preprocess()
        self._last_gates = gates
        return gates

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        """明文加密"""
        return self.lwe.encrypt(message)

    def decrypt(self, ciphertext: List[int], preprocessed_data: Optional[PreprocessedGates] = None) -> int:
        """線上解密"""
        gates = preprocessed_data or self._last_gates or self.preprocess()
        self.decryptor.abb.reset_metrics()
        return self.decryptor.decrypt(ciphertext, self.s_ext_stored, gates)

    def decrypt_interactive(self, ciphertext: List[int], preprocessed_data: Optional[PreprocessedGates] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """多輪交互解密 (3 Sequential Openings)"""
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
        rounds_info.append({"round": 1, "action": "Open masked z'", "bits": self.l})

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
        rounds_info.append({"round": 2, "action": "Open masked y'", "bits": d_plus_1})

        # Round 3: Compute [e]_k, then Open [z]_k - [e]_k -> mu
        e_k = self.decryptor.abb.lin_comb(z_prime, [(-1, gates.r_combined), (1 << self.l, u_k)], out_len=self.k)
        mu_scaled = self.decryptor.abb.sub(z_k, e_k, out_len=self.k)
        mu_prime = self.decryptor.abb.open(mu_scaled, truncated_l=self.k)
        mu = (mu_prime // self.decryptor.L) % self.decryptor.p
        rounds_info.append({"round": 3, "action": "Open unmasked mu'", "bits": self.k})

        return mu, rounds_info

    def get_offline_metrics(self, preprocessed_data: Optional[PreprocessedGates] = None) -> Dict[str, Any]:
        """計算離線儲存與乘法次數 (對齊論文 Formula 5 與 Section 3.4/5.2)"""
        d = math.ceil(self.l / self.b)
        b_prime = self.l - (d - 1) * self.b
        # Formula (5): (d + 1) * ((d - 1) * 2^b + 2^{b'}) + m * 2^{d+1}
        gate_storage_bits = (d + 1) * ((d - 1) * (1 << self.b) + (1 << b_prime)) + self.m * (1 << (d + 1))
        
        # 乘法次數: (d - 1)*(2^b - b - 1) + (2^b' - b' - 1) + (2^{d+1} - (d+1) - 1)
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
