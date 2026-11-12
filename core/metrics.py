from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import json

@dataclass
class StageMetric:
    """單一階段 (例如 KeyGen, Encrypt, EvalAdd 等) 的評測統計數據"""
    stage_name: str
    iterations: int = 0
    mean_time_ms: float = 0.0
    std_time_ms: float = 0.0
    min_time_ms: float = 0.0
    max_time_ms: float = 0.0
    comm_sent_bytes: int = 0
    comm_recv_bytes: int = 0
    memory_peak_kb: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class BenchmarkResult:
    """一個完整實驗配置下的評測結果"""
    scheme_name: str
    security_param: int
    threshold_t: int
    total_n: int
    mode: str  # 'local' or 'remote'
    timestamp: str
    stages: Dict[str, StageMetric] = field(default_factory=dict)
    key_sizes_bytes: Dict[str, int] = field(default_factory=dict)
    ciphertext_size_bytes: int = 0
    share_size_bytes: int = 0
    correctness_verified: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
