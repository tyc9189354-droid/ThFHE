from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import json

@dataclass
class OfflineMetric:
    """離線預處理階段 (Offline Preprocessing) 的評測指標"""
    prep_time_ms: float = 0.0
    num_mults: int = 0                  # 離線乘法次數 (Beaver Triples 消耗)
    num_rand_bits: int = 0              # 隨機位元數量
    gate_storage_bits: int = 0          # 門儲存位元數 (Formula 5)
    gate_storage_bytes: int = 0         # 門儲存位元組數
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class OnlineMetric:
    """線上門檻解密階段 (Online Decryption) 的評測指標"""
    latency_ms: float = 0.0             # 單次解密端到端耗時 (ms)
    std_latency_ms: float = 0.0         # 延遲標準差
    throughput_dec_per_sec: float = 0.0 # 吞吐量 (Decryptions per second)
    num_rounds: int = 3                 # 交互輪數 (CCS25 為 3 輪)
    num_opens: int = 3                  # F_ABB Open 次數
    opened_bits: int = 0                # 總揭示位元數 (l + (d+1) + k)
    online_mults: int = 0               # 線上乘法次數 (CCS25 為 0)
    comm_sent_bytes: int = 0            # 網路發送 bytes (Client-Server 模式)
    comm_recv_bytes: int = 0            # 網路接收 bytes (Client-Server 模式)
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BenchmarkResult:
    """一個完整配置下單一方案的評測結果"""
    scheme_name: str
    k: int                              # Ciphertext modulus bit-length (q = 2^k)
    m: int                              # Plaintext modulus bit-length (p = 2^m)
    mode: str                           # 'local' or 'remote'
    timestamp: str
    offline: OfflineMetric = field(default_factory=OfflineMetric)
    online: OnlineMetric = field(default_factory=OnlineMetric)
    ciphertext_size_bytes: int = 0
    correctness_verified: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
