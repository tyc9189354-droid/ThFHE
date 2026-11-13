#!/usr/bin/env python3
r"""
================================================================================
Ajax Benchmark Adapter: "Fast Threshold FHE without Noise Flooding"
(Hu, Liang, Wang, Xie, Yang, Yu, Zhang - USENIX Security 2025)
================================================================================
Unified Benchmark Adapter for Ajax Scheme:
  - Setup: FHEW/TFHE parameters, Modulus switching parameters \eta and \Phi = \eta / p
  - KeyGen: Noise-compressing KeyGen (\sigma' = \sigma / (n - t))
  - Offline Preprocessing: Random Double Sharings (<r>_\eta, <r>_\Phi)
  - Homomorphic Evaluation: Addition and Multiplication
  - Partial Decryption: Modulus switching to \eta & extraction mod \Phi, Round 1 Mask & Open
  - Aggregation: Round 2 Subtraction of noise in Z_\eta & Plaintext Decoding
================================================================================
"""

import math
import time
import random
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import AjaxThFHE

class AjaxThFHEScheme(BaseThFHEScheme):
    """
    Adapter for Hu et al. (USENIX Security 2025):
    'Ajax: Fast Threshold Fully Homomorphic Encryption without Noise Flooding'
    """

    def __init__(self, name: str = "Ajax (USENIX Security 2025: Mask-Then-Open without Noise Flooding)"):
        super().__init__(name)
        self.n_dim = 16
        self.k = 64
        self.m = 1
        self.q = 65537
        self.p = 4
        self.num_parties = 10
        self.threshold = 5
        self.ajax: Optional[AjaxThFHE] = None
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        n_dim: int = 16,
        threshold: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        r"""[Stage 1: Setup] 初始化小模數 q, p, \Delta, \eta, \Phi 與參與方環境"""
        self.k = k
        self.m = m
        self.n_dim = n_dim
        self.num_parties = max(3, min(1000, int(num_parties)))
        self.threshold = threshold if threshold is not None else max(1, (self.num_parties - 1) // 2)
        self.p = 1 << m if m <= 4 else 4
        self.q = 65537
        self.ajax = AjaxThFHE(
            n_dim=self.n_dim,
            q=self.q,
            p=self.p,
            num_parties=self.num_parties,
            threshold=self.threshold,
            sigma=3.2
        )
        self.params = self.ajax.setup()
        return self.params

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] Noise-compressing 分散式金鑰份額生成"""
        if self.ajax is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties, n_dim=self.n_dim)
        info = self.ajax.keygen()
        self.last_audit["keygen"] = info
        return info

    def preprocess(self) -> Any:
        r"""[Stage 3: Offline Prep] 生成雙環隨機秘密分享 (<r>_\eta, <r>_\Phi)"""
        if self.ajax is None or self.ajax.s is None:
            self.keygen()
        count = self.ajax.preprocess(count=20)
        return {
            "type": "ajax_double_ring_shares",
            "parties": self.num_parties,
            "threshold": self.threshold,
            "available_pairs": count
        }

    def encrypt(self, message: int) -> Tuple[Any, Any]:
        """[Stage 4: Encrypt] LWE 加密至模數 q"""
        if self.ajax is None or self.ajax.s is None:
            self.keygen()
        ct = self.ajax.encrypt(message)
        return ct, {"message": message}

    def eval_add(self, ct1: Any, ct2: Any) -> Any:
        """[Stage 4: Homo Add] 同態加法"""
        return self.ajax.eval_add(ct1, ct2)

    def eval_mul(self, ct1: Any, ct2: Any) -> Any:
        """[Stage 5: Homo Mul] 同態乘法"""
        return self.ajax.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> int:
        """[Stage 6 & 7: Online Decryption] 完整門檻解密"""
        res, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return res

    def decrypt_with_stages(self, ciphertext: Any, preprocessed_data: Optional[Any] = None) -> Tuple[int, float, float]:
        r"""
        執行 Mask-Then-Open 兩輪在線門檻解密：
          - partial_dec_ms: 模數轉換至 \eta, 抽取 mod \Phi, 第一輪遮罩並廣播 v
          - agg_ms: 第二輪扣除雜訊項並重構明文 m
        """
        if self.ajax is None or self.ajax.s is None:
            self.keygen()
        return self.ajax.decrypt_full(ciphertext)

    def get_offline_metrics(self, preprocessed_data: Any) -> Dict[str, Any]:
        return {
            "gate_storage_bits": 16 * self.num_parties,
            "double_ring_pairs": 20
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        return {
            "num_rounds": 2,
            "num_opens": 2,
            "opened_bits": 14,
            "num_mults": 0
        }
