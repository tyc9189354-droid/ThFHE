from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple, Optional
import pickle

class BaseThFHEScheme(ABC):
    """
    通用門檻全同態加密（ThFHE）統一抽象介面 (Adapter Base Class)。
    所有要比較的方案（包含你的自研演算法以及其他論文的方法）都應繼承此類別。
    """

    def __init__(self, name: str):
        self.name = name
        self.params: Dict[str, Any] = {}

    @abstractmethod
    def setup(self, security_param: int, threshold_t: int, total_n: int, **kwargs) -> Dict[str, Any]:
        """
        系統參數初始化。
        :param security_param: 安全級別 (如 80, 128, 256)
        :param threshold_t: 門檻值 t
        :param total_n: 總參與方數量 n
        :return: 參數字典
        """
        pass

    @abstractmethod
    def keygen(self) -> Dict[str, Any]:
        """
        密鑰生成階段（支援一般集中式生成或分散式 DKG）。
        :return: 字典包含：
            - 'pk': 公鑰 (Public Key)
            - 'eval_key': 評估鑰 / 轉鑰 (Evaluation Key / Relin Key)
            - 'sk_shares': 字典或列表，包含各參與方的私鑰份額 {party_id: sk_share}
        """
        pass

    @abstractmethod
    def encrypt(self, plaintext: Any, pk: Any) -> Any:
        """
        將明文加密為密文。
        :param plaintext: 欲加密之資料 (數字、向量或多項式)
        :param pk: 公鑰
        :return: 密文物件
        """
        pass

    @abstractmethod
    def eval_add(self, ct1: Any, ct2: Any, eval_key: Optional[Any] = None) -> Any:
        """
        同態加法運算 (Homomorphic Addition)。
        :param ct1: 密文 1
        :param ct2: 密文 2
        :param eval_key: 可選的評估鑰
        :return: 相加後的密文
        """
        pass

    @abstractmethod
    def eval_mult(self, ct1: Any, ct2: Any, eval_key: Optional[Any] = None) -> Any:
        """
        同態乘法運算 (Homomorphic Multiplication)。
        :param ct1: 密文 1
        :param ct2: 密文 2
        :param eval_key: 評估鑰 (Relin Key / Multiplication Key)
        :return: 相乘後的密文
        """
        pass

    def eval_custom(self, op_name: str, *args, **kwargs) -> Any:
        """
        擴展自定義運算（例如 Bootstrapping, 內積, 矩陣乘法等）。
        若該方案支援特定進階運算，可覆寫此函數。
        """
        raise NotImplementedError(f"Scheme {self.name} does not implement custom operation: {op_name}")

    @abstractmethod
    def partial_decrypt(self, party_id: int, ciphertext: Any, sk_share: Any) -> Any:
        """
        門檻解密 - 單一參與方計算部分解密份額 (Partial Decryption Share)。
        :param party_id: 參與方編號
        :param ciphertext: 欲解密之密文
        :param sk_share: 該參與方持有的私鑰份額
        :return: 部分解密份額 (Decryption Share)
        """
        pass

    @abstractmethod
    def combine_decryption(self, partial_shares: List[Any], ciphertext: Any, pk: Optional[Any] = None) -> Any:
        """
        門檻解密 - 聚合 >= t 個參與方的部分解密份額，重構出最終明文。
        :param partial_shares: 收集到的至少 t 個份額清單
        :param ciphertext: 原始密文
        :param pk: 公鑰 (若重構演算法需要)
        :return: 還原之明文
        """
        pass

    # ==========================================================
    # 序列化與通訊計量介面 (若底層有原生序列化，請覆寫以獲得更精確數值)
    # ==========================================================
    def serialize_ciphertext(self, ciphertext: Any) -> bytes:
        """將密文序列化為 bytes 以量測傳輸大小"""
        if hasattr(ciphertext, "serialize"):
            return ciphertext.serialize()
        return pickle.dumps(ciphertext)

    def serialize_share(self, share: Any) -> bytes:
        """將部分解密份額序列化為 bytes"""
        if hasattr(share, "serialize"):
            return share.serialize()
        return pickle.dumps(share)

    def serialize_key(self, key: Any) -> bytes:
        """將密鑰序列化為 bytes"""
        if hasattr(key, "serialize"):
            return key.serialize()
        return pickle.dumps(key)
