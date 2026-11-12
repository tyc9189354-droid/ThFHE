import time
import random
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme

class BaselineNoiseFloodingScheme(BaseThFHEScheme):
    """
    Simulation of the State-of-the-Art Noise Flooding Baseline
    (e.g., Dahl et al., "Noah's Ark: Efficient threshold-FHE using noise flooding", 2023)
    
    Characteristics:
      - Requires large flooding noise or heavy bootstrapping ("squish-and-squash")
      - Compute-bound on CPU (single-threaded bottleneck)
      - Online latency: hundreds of milliseconds (approx ~300ms)
      - Low throughput (~3-10 dec/sec)
    """

    def __init__(self, name: str = "Baseline_Dahl21_NoiseFlooding"):
        super().__init__(name)
        self.k = 64
        self.m = 1
        self.simulated_cpu_delay_s = 0.05  # 模擬部分計算負擔 (50ms)，避免本地測試過慢

    def setup(self, k: int = 64, m: int = 1, **kwargs) -> Dict[str, Any]:
        self.k = k
        self.m = m
        self.q = 1 << k
        self.p = 1 << m
        self.l = k - m
        self.L = 1 << self.l
        self.s = [random.randint(0, 1) for _ in range(16)]
        self.params = {"k": k, "m": m, "technique": "Noise Flooding"}
        return self.params

    def preprocess(self) -> Any:
        # Noise flooding 傳統方案離線不需要 Sign/ModLTZ preprocessed gates
        return {"type": "noise_flooding_aux"}

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        a = [random.randint(0, self.q - 1) for _ in range(16)]
        inner_prod = sum(a[i] * self.s[i] for i in range(16)) % self.q
        e = random.randint(-self.L // 8, self.L // 8)
        b = (inner_prod + self.L * message + e) % self.q
        c_ext = [(-a_i) % self.q for a_i in a] + [b]
        return c_ext, e

    def decrypt(self, ciphertext: List[int], preprocessed_data: Optional[Any] = None) -> int:
        # 模擬 Noise Flooding 的 bootstrapping 與大雜訊添加計算延遲
        time.sleep(self.simulated_cpu_delay_s)

        # 內積還原
        s_ext = self.s + [1]
        z = sum(c * s for c, s in zip(ciphertext, s_ext)) % self.q
        # 加上 round 偏移
        z = (z + (1 << (self.l - 1))) % self.q
        mu = ((z // self.L)) % self.p
        return mu

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
            "opened_bits": self.k,
            "num_mults": 1,
            "num_rounds": 1
        }
