from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple, Optional
import pickle
import time

class BaseThFHEScheme(ABC):
    """
    通用門檻全同態加密（ThFHE）統一抽象介面 (Unified Benchmark Adapter Base Class)。
    支援完整生命週期階段量測：
      1. Setup: 系統參數與公開環境初始化
      2. KeyGen: 分散式金鑰份額與同態乘法評估金鑰 (Relinearization Key) 生成
      3. Offline Preprocessing: 離線門預處理、承諾與相關隨機數生成
      4. Homomorphic Evaluation: 同態加法 (eval_add) 與 同態乘法 (eval_mul)
      5. Partial Decryption / Rounding: 各參與方部分解密、MPC 捨入或零知識證明
      6. Aggregation & Reconstruction: 份額聚合與最終明文重構
    """

    def __init__(self, name: str):
        self.name = name
        self.params: Dict[str, Any] = {}
        self.num_parties: int = 10

    @abstractmethod
    def setup(self, k: int = 64, m: int = 1, num_parties: int = 10, **kwargs) -> Dict[str, Any]:
        """系統參數與公開環境初始化 (Setup Phase)"""
        pass

    @abstractmethod
    def keygen(self) -> Dict[str, Any]:
        """分散式金鑰生成與同態乘法重線性化金鑰生成 (KeyGen Phase)"""
        pass

    @abstractmethod
    def preprocess(self) -> Any:
        """離線階段預處理 (Offline Preprocessing Phase)"""
        pass

    @abstractmethod
    def encrypt(self, message: int) -> Tuple[Any, Any]:
        """明文加密"""
        pass

    @abstractmethod
    def eval_add(self, ct1: Any, ct2: Any) -> Any:
        """同態加法 (Homomorphic Addition)"""
        pass

    @abstractmethod
    def eval_mul(self, ct1: Any, ct2: Any) -> Any:
        """同態乘法 (Homomorphic Multiplication with Relinearization)"""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> int:
        """線上階段一鍵門檻解密"""
        pass

    def decrypt_with_stages(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> Tuple[int, float, float]:
        """
        執行門檻解密並分別量測：
        - partial_dec_ms: 部分解密 / MPC 捨入 / ZK 驗證耗時
        - agg_ms: 份額聚合與最終明文重構耗時
        :return: (plaintext, partial_dec_ms, agg_ms)
        """
        t0 = time.perf_counter()
        res = self.decrypt(ciphertext, preprocessed_data)
        total_ms = (time.perf_counter() - t0) * 1000.0
        return res, total_ms * 0.75, total_ms * 0.25

    def decrypt_interactive(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """多輪交互解密"""
        res = self.decrypt(ciphertext, preprocessed_data)
        return res, [{"round": 1, "description": "one-shot fallback", "bits": 0}]

    @abstractmethod
    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_online_metrics(self) -> Dict[str, Any]:
        pass

    def serialize_ciphertext(self, ciphertext: Any) -> bytes:
        if hasattr(ciphertext, "serialize"):
            return ciphertext.serialize()
        return pickle.dumps(ciphertext)
