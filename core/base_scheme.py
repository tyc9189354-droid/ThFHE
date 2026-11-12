from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple, Optional
import pickle
import json

class BaseThFHEScheme(ABC):
    """
    通用門檻全同態加密（ThFHE）統一抽象介面 (Unified Benchmark Adapter Base Class)。
    所有論文的實作（包含 CCS25、未來的新論文以及傳統 Noise-Flooding Baseline）均繼承此類別。
    
    支援三大核心生命週期：
      1. Setup: 系統參數初始化與密鑰生成
      2. Offline Preprocessing: 門預處理、Beaver Triples、隨機遮罩生成
      3. Online Decryption: 線上門檻解密（支援 Local 與 多輪 Interactive 模式）
    """

    def __init__(self, name: str):
        self.name = name
        self.params: Dict[str, Any] = {}

    @abstractmethod
    def setup(self, k: int, m: int, **kwargs) -> Dict[str, Any]:
        """
        系統參數設定與密鑰生成。
        :param k: 密文模數 bit 長度 (q = 2^k)
        :param m: 明文模數 bit 長度 (p = 2^m)
        :param kwargs: 其他特定論文參數 (如 b, threshold_t, total_n)
        :return: 參數字典
        """
        pass

    @abstractmethod
    def preprocess(self) -> Any:
        """
        [離線階段 Offline Phase]
        預處理門 (Preprocessed Gates) 或相關 Correlated Randomness (Beaver triples, random masks)。
        :return: 預處理資料物件 (例如 PreprocessedGates)
        """
        pass

    @abstractmethod
    def encrypt(self, message: int) -> Tuple[Any, Any]:
        """
        明文加密。
        :param message: 明文訊息 (通常在 Z_{2^m})
        :return: (密文物件 ciphertext, 雜訊 noise)
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> int:
        """
        [線上階段 Online Phase - 一鍵解密]
        使用預處理資料對密文執行門檻解密，消除雜訊並重構明文。
        :param ciphertext: 密文物件
        :param preprocessed_data: 離線階段產生的門或輔助資料
        :return: 重構之明文
        """
        pass

    def decrypt_interactive(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> Tuple[int, List[Dict[str, Any]]]:
        """
        [線上階段 Online Phase - 多輪交互解密]
        模擬或執行線上每一輪 (Round) 的揭示 (Open) 與通訊。
        :return: (明文, 每一輪的交互資訊清單 [{round, opened_value, bits, latency_ms}])
        """
        # 預設單輪回退實作，子類別可覆寫以提供精確多輪統計
        res = self.decrypt(ciphertext, preprocessed_data)
        return res, [{"round": 1, "description": "one-shot fallback", "bits": 0}]

    @abstractmethod
    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        """
        獲取離線階段指標：
        - num_mults: 交互乘法次數 (或 Beaver triples 消耗量)
        - num_rand_bits: 消耗的隨機 bit 數量
        - gate_storage_bits: 預處理資料佔用的總儲存位元組數
        """
        pass

    @abstractmethod
    def get_online_metrics(self) -> Dict[str, Any]:
        """
        獲取最近一次線上解密的指標：
        - num_opens: 揭示次數
        - opened_bits: 總揭示位元數
        - num_mults: 線上乘法次數 (本論文應為 0)
        - num_rounds: 交互輪數 (本論文應為 3)
        """
        pass

    # ==========================================================
    # 序列化輔助方法 (用於量測網路傳輸大小)
    # ==========================================================
    def serialize_ciphertext(self, ciphertext: Any) -> bytes:
        """序列化密文以計算大小"""
        if hasattr(ciphertext, "serialize"):
            return ciphertext.serialize()
        return pickle.dumps(ciphertext)
