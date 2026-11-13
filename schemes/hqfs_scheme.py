import math
import time
import random
from typing import Any, Dict, Tuple, Optional, List
import numpy as np
from core.base_scheme import BaseThFHEScheme
from tool import DecentralizedHQFS, HQFSVerifier, compute_committee_lagrange


class _DecentralizedHQFSFacade:
    """Adapter exposing attributes & helper methods expected by web/serve.py on hscheme.hqfs."""

    def __init__(self, engine: DecentralizedHQFS):
        self._eng = engine

    @property
    def n_glwe(self) -> int:
        return self._eng.n_glwe

    @property
    def m_glwe(self) -> int:
        return self._eng.m_glwe

    @property
    def p_ntt(self) -> int:
        return self._eng.p_ntt

    @property
    def K_Q(self) -> int:
        return self._eng.p_zkp

    def encrypt(self, message: int):
        return self._eng.encrypt_scalar(message)

    def decrypt(self, ct) -> int:
        return self._eng.decrypt_scalar_clear(ct)

    def decrypt_simd(self, ct, slot_count: int = 4) -> List[int]:
        return self._eng.decrypt_simd(ct, slot_count=slot_count)


class HQFSThFHEScheme(BaseThFHEScheme):
    """
    論文與參考實作轉接器 (Paper + Reference Implementation Adapter):
    "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic Quotient Proofs"
    直接驅動與分散式多埠參考程式一致之 `DecentralizedHQFS` 核心：
      - RNS-GLWE 19 質數基底 (6 Q-primes + 13 P-primes) 與動態 C NTT 加速核心
      - n_glwe = 2, m_glwe = 3, ZKP 雙肢節 K_IDXs = [0, 1], P_ZKP = p_0 * p_1
      - Feldman DKG 門檻秘鑰生成與公開承諾驗證 (C_actual == C_expected)
      - 2-Round 協同分散式 RLK 生成 (Mouchet Collective RLK，不洩漏節點私鑰份額)
      - 零密文疊加 (Zero-Ciphertext Superposition) 與 4 叉樹狀批次驗證 (HQFSVerifier.verify_n_tree)
      - 整數委員會 Lagrange 重構 (compute_committee_lagrange)
    """

    def __init__(self, name: str = "HQ-FS (RNS-GLWE + Homomorphic Quotient ZKP + Zero-CT, Our Work)"):
        super().__init__(name)
        self.d: int = 16
        self.n_glwe: int = 2
        self.m_glwe: int = 3
        self.T: int = 1024
        self.eta: int = 3
        self.B_flood: int = 1024
        self.num_parties: int = 10
        self.malicious_ratio: int = 20
        self.attack_type: str = "share_tampering"
        self.decentralized_hqfs: Optional[DecentralizedHQFS] = None
        self.hqfs: Optional[_DecentralizedHQFSFacade] = None
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 32,
        m: int = 10,
        num_parties: int = 10,
        d: int = 16,
        n_glwe: int = 2,
        m_glwe: int = 3,
        eta: int = 3,
        B_flood: int = 1024,
        malicious_ratio: int = 0,
        attack_type: str = "none",
        **kwargs
    ) -> Dict[str, Any]:
        """[Stage 1: Setup] Algorithm 1: 初始化 19 質數 RNS 基底 (6Q+13P)、P_ZKP 與公開矩陣 CRS"""
        self.d = d
        self.n_glwe = n_glwe
        self.m_glwe = m_glwe
        self.T = 1 << m if m <= 16 else 1024
        self.eta = eta
        self.B_flood = B_flood
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "none"

        threshold_t = max(2, int(self.num_parties * 0.6))
        self.decentralized_hqfs = DecentralizedHQFS(
            d=self.d,
            T=self.T,
            plain_T=self.T,
            n_glwe=self.n_glwe,
            m_glwe=self.m_glwe,
            num_parties=self.num_parties,
            threshold_t=threshold_t,
            flood_bound=self.B_flood,
            eta_enc=self.eta,
            eta_gk=2,
        )
        self.decentralized_hqfs.setup()
        self.hqfs = _DecentralizedHQFSFacade(self.decentralized_hqfs)
        q_list = [int(p) for p in self.decentralized_hqfs.q_primes]
        return {
            "d": self.d,
            "N_poly": self.d,
            "k_glwe": self.n_glwe,
            "n_glwe": self.n_glwe,
            "m_glwe": self.m_glwe,
            "T": self.T,
            "p_ntt": self.decentralized_hqfs.p_ntt,
            "q_primes": q_list,
            "q_limbs": q_list,
            "Q_total": f"{self.decentralized_hqfs.Q_big.bit_length()}-bit (6Q+13P)",
            "K_Q": self.decentralized_hqfs.p_zkp,
            "B_flood": self.B_flood,
            "B_sm": self.B_flood,
            "threshold_t": threshold_t,
            "num_parties": self.num_parties,
            "malicious_ratio": self.malicious_ratio,
            "attack_type": self.attack_type,
            "decentralized_engine": "DecentralizedHQFS"
        }

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] Feldman DKG 門檻分鑰與公開承諾聚合"""
        if self.decentralized_hqfs is None:
            self.setup()
        self.decentralized_hqfs.keygen()
        return {
            "num_parties": self.num_parties,
            "threshold_t": self.decentralized_hqfs.t,
            "commitment_count": len(self.decentralized_hqfs.public_commitments)
        }

    def preprocess(self) -> Dict[str, Any]:
        """[Stage 3: Offline Prep / RLKGen] 2-Round 協同分散式 RNS RLK 生成"""
        if self.decentralized_hqfs is None or self.decentralized_hqfs.pk_global is None:
            self.keygen()
        self.decentralized_hqfs.preprocess()
        s_q = len(self.decentralized_hqfs.q_primes)
        rlk_entries = (self.n_glwe * self.n_glwe) * s_q
        return {
            "rlk_entries": rlk_entries,
            "rns_limbs": s_q,
            "K_Q": self.decentralized_hqfs.p_zkp,
            "B_bgv": int(self.decentralized_hqfs.q_primes[0]),
            "l_bgv": s_q
        }

    def encrypt(self, message: int) -> Tuple[Any, int]:
        """[Stage 4: Encrypt] RNS-GLWE 加密 (含 iNTT 編碼與淹沒雜訊)"""
        if self.decentralized_hqfs is None or self.decentralized_hqfs.pk_global is None:
            self.keygen()
        return self.decentralized_hqfs.encrypt_scalar(message), 0

    def encrypt_simd(self, slots: List[int]):
        """RNS-GLWE iNTT 多槽 SIMD 加密"""
        if self.decentralized_hqfs is None or self.decentralized_hqfs.pk_global is None:
            self.keygen()
        return self.decentralized_hqfs.encrypt_simd(slots)

    def eval_add(self, ct1, ct2):
        """[Stage 4a: Homo Add] 同態加法 + 零密文疊加 (Zero-Ciphertext Superposition)"""
        return self.decentralized_hqfs.eval_add(ct1, ct2)

    def eval_mul(self, ct1, ct2):
        """[Stage 4b: Homo Mul] RNS 重線性化同態乘法 + 零密文疊加"""
        return self.decentralized_hqfs.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext, preprocessed_data: Optional[Any] = None) -> int:
        mu, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return mu

    def decrypt_simd_with_stages(
        self,
        ciphertext,
        slot_count: int = 4,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[List[int], float, float]:
        _, pdec_ms, agg_ms = self.decrypt_with_stages(
            ciphertext,
            malicious_ratio=malicious_ratio,
            attack_type=attack_type
        )
        slots = self.last_audit.get("decoded_simd_slots", [])[:slot_count]
        return slots, pdec_ms, agg_ms

    def decrypt_with_stages(
        self,
        ciphertext,
        preprocessed_data: Optional[Any] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[int, float, float]:
        """
        分別量測：
          - Partial Decryption + 2-Limb HQ-FS ZKP Proof 生成
          - 4-ary Tree-Bisection Verifier (HQFSVerifier.verify_n_tree) + Committee Lagrange 重構
        """
        if self.decentralized_hqfs is None or self.decentralized_hqfs.pk_global is None:
            self.keygen()

        eng = self.decentralized_hqfs
        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        num_mal = (self.num_parties * mr) // 100 if at != "none" else 0
        # Ensure honest nodes remain >= threshold_t if mr > 0 so BFT tolerance holds within threshold
        max_mal = max(0, self.num_parties - eng.t)
        effective_mal = min(num_mal, max_mal)
        malicious_ids = set(random.sample(range(1, self.num_parties + 1), effective_mal)) if effective_mal > 0 else set()

        u_rns, _ = ciphertext
        submitted_data = {}

        t0 = time.perf_counter()
        for uid in range(1, self.num_parties + 1):
            is_mal = uid in malicious_ids
            submitted_data[uid] = eng.partial_decrypt(uid, u_rns, is_malicious=is_mal, attack_type=at)
        t_partial_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        dec_vec, valid_ids, rejected = eng.decrypt(ciphertext, submitted_data, n_branch=4)
        t_agg_ms = (time.perf_counter() - t1) * 1000.0

        bfs_steps = max(1, int(math.ceil(math.log(max(2, self.num_parties), 4)))) if rejected else 1
        self.last_audit = {
            "num_parties": self.num_parties,
            "threshold_t": eng.t,
            "malicious_ratio": mr,
            "num_malicious": effective_mal,
            "attack_type": at,
            "rejected_count": len(rejected),
            "rejected_parties_sample": rejected[:8],
            "honest_aggregated_count": min(eng.t, len(valid_ids)),
            "valid_count": len(valid_ids),
            "bfs_steps": bfs_steps,
            "K_Q": eng.p_zkp,
            "decoded_simd_slots": [int(x) for x in dec_vec[:16]],
            "bft_defense": "4-ary Tree Bisection (HQFSVerifier.verify_n_tree)",
            "reconstruction": "Integer Committee Lagrange (compute_committee_lagrange)",
            "decentralized_engine": "DecentralizedHQFS (19 RNS Primes + 2-Limb ZKP + Collective RLK)"
        }
        return int(dec_vec[0]), t_partial_ms, t_agg_ms

    def get_offline_metrics(self, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        s_q = len(self.decentralized_hqfs.q_primes) if self.decentralized_hqfs else 6
        num_rlk = preprocessed_data.get("rlk_entries", (self.n_glwe ** 2) * s_q) if isinstance(preprocessed_data, dict) else (self.n_glwe ** 2) * s_q
        storage_bits = num_rlk * (self.n_glwe + 1) * self.d * 30
        return {
            "num_mults": num_rlk * self.d,
            "num_rand_bits": num_rlk * self.d * 8,
            "gate_storage_bits": storage_bits,
            "gate_storage_bytes": (storage_bits + 7) // 8
        }

    def get_online_metrics(self, ciphertext: Optional[Any] = None, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        s_q = len(self.decentralized_hqfs.q_primes) if self.decentralized_hqfs else 6
        # Partial share (s_q limbs) + 2-limb ZKP proof (2 * (n_glwe + m_glwe + 2) polys)
        bits_per_party = self.d * 30 * s_q + self.d * 30 * 2 * (self.n_glwe + self.m_glwe + 2)
        total_comm = self.num_parties * bits_per_party
        return {
            "num_rounds": 1,
            "online_rounds": 1,
            "num_opens": 1,
            "opened_bits": total_comm,
            "comm_bits": total_comm,
            "num_openings": self.num_parties
        }
