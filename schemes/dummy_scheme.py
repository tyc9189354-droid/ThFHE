import random
import time
from typing import Any, Dict, List, Optional
from core.base_scheme import BaseThFHEScheme

class DummyThFHEScheme(BaseThFHEScheme):
    """
    用於框架自我測試與流程驗證的示範方案 (Toy Threshold Scheme)。
    支援同態加法、乘法，以及 (t, n) 門檻解密模擬。
    """

    def __init__(self, name: str = "dummy_toy_thfhe"):
        super().__init__(name)
        self.t = 2
        self.n = 3
        self.modulus = 1000000007

    def setup(self, security_param: int, threshold_t: int, total_n: int, **kwargs) -> Dict[str, Any]:
        self.t = threshold_t
        self.n = total_n
        self.params = {
            "security_param": security_param,
            "threshold_t": threshold_t,
            "total_n": total_n,
            "modulus": self.modulus
        }
        return self.params

    def keygen(self) -> Dict[str, Any]:
        # 模擬產生全局主私鑰 s，並使用 Shamir 門檻分割成 n 個份額
        master_secret = random.randint(10, 1000)
        # 多項式係數 f(x) = s + a_1*x + ... + a_{t-1}*x^{t-1}
        coeffs = [master_secret] + [random.randint(1, 100) for _ in range(self.t - 1)]

        def eval_poly(x):
            return sum(c * (x ** i) for i, c in enumerate(coeffs)) % self.modulus

        sk_shares = {party_id: eval_poly(party_id) for party_id in range(1, self.n + 1)}
        pk = {"master_public": (master_secret * 7) % self.modulus, "modulus": self.modulus}
        eval_key = {"relin_key": (master_secret ** 2) % self.modulus}

        # 模擬少許運算時間
        time.sleep(0.005)

        return {
            "pk": pk,
            "eval_key": eval_key,
            "sk_shares": sk_shares
        }

    def encrypt(self, plaintext: Any, pk: Any) -> Any:
        # 模擬密文結構 (c0, c1)
        r = random.randint(1, 100)
        c0 = (plaintext + r * pk["master_public"]) % self.modulus
        c1 = r
        time.sleep(0.002)
        return {"c0": c0, "c1": c1, "value_mock": plaintext}

    def eval_add(self, ct1: Any, ct2: Any, eval_key: Optional[Any] = None) -> Any:
        time.sleep(0.001)
        return {
            "c0": (ct1["c0"] + ct2["c0"]) % self.modulus,
            "c1": (ct1["c1"] + ct2["c1"]) % self.modulus,
            "value_mock": ct1["value_mock"] + ct2["value_mock"]
        }

    def eval_mult(self, ct1: Any, ct2: Any, eval_key: Optional[Any] = None) -> Any:
        time.sleep(0.003)
        return {
            "c0": (ct1["c0"] * ct2["c0"]) % self.modulus,
            "c1": (ct1["c1"] * ct2["c1"]) % self.modulus,
            "value_mock": ct1["value_mock"] * ct2["value_mock"]
        }

    def partial_decrypt(self, party_id: int, ciphertext: Any, sk_share: Any) -> Any:
        time.sleep(0.001)
        # 各參與方產出部分解密份額
        return {
            "party_id": party_id,
            "share": (sk_share * ciphertext["c1"]) % self.modulus,
            "value_mock": ciphertext["value_mock"]
        }

    def combine_decryption(self, partial_shares: List[Any], ciphertext: Any, pk: Optional[Any] = None) -> Any:
        time.sleep(0.002)
        if len(partial_shares) < self.t:
            raise ValueError(f"Insufficient shares: got {len(partial_shares)}, required {self.t}")
        # 重構結果
        return partial_shares[0]["value_mock"]
