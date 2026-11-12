"""
================================================================================
自訂方案轉接器模板 (Custom Scheme Adapter Template)
================================================================================
當你有未來的新論文或自研程式碼時，請依照此模板包裝，並繼承 BaseThFHEScheme。
只要實作以下幾個核心生命週期，就能自動接入整個評測框架與論文圖表繪製！
"""

from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme

# TODO: 引入你的論文實作模組 (例如 from your_tool import ...)

class CustomPaperThFHEScheme(BaseThFHEScheme):
    """
    未來其他論文的實作轉接器。
    """

    def __init__(self, name: str = "My_New_Paper_Scheme"):
        super().__init__(name)
        self.k = 64
        self.m = 1

    def setup(self, k: int = 64, m: int = 1, **kwargs) -> Dict[str, Any]:
        """[1] 系統參數設定與密鑰初始化"""
        self.k = k
        self.m = m
        self.params = {"k": k, "m": m, **kwargs}
        # TODO: 呼叫你的 setup 或 keygen
        return self.params

    def preprocess(self) -> Any:
        """[2] 離線預處理階段 (生成門、Beaver triples、隨機數等)"""
        # TODO: 呼叫你的離線預處理
        return {}

    def encrypt(self, message: int) -> Tuple[Any, Any]:
        """[3] 明文加密"""
        # TODO: 呼叫你的加密函式，回傳 (密文, 雜訊)
        raise NotImplementedError("請填入你的 encrypt 實作")

    def decrypt(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> int:
        """[4] 線上門檻解密"""
        # TODO: 呼叫你的線上門檻解密函式，回傳還原的明文
        raise NotImplementedError("請填入你的 decrypt 實作")

    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        """[5] 離線成本統計 (乘法次數、門儲存大小)"""
        return {
            "num_mults": 0,
            "num_rand_bits": 0,
            "gate_storage_bits": 0,
            "gate_storage_bytes": 0
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        """[6] 線上成本統計 (揭示次數、揭示位元數、交互輪數)"""
        return {
            "num_opens": 3,
            "opened_bits": 0,
            "num_mults": 0,
            "num_rounds": 3
        }
