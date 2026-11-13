import sys
import time
import random
from typing import Any, Dict, Tuple, Optional, List
from core.base_scheme import BaseThFHEScheme
from tool import HQFSRNSGLWE, DecentralizedHQFS, HQFSVerifier, compute_committee_lagrange


class HQFSThFHEScheme(BaseThFHEScheme):
    """
    論文轉接器 (Paper Adapter):
    "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic Quotient Proofs"
    整合：
      - RNS-GLWE 緊湊架構 (Q = {q_1, ..., q_r}, P = {p_1, ..., p_k}) 與動態 C 加速核心
      - HQ-FS ZKP 同態商數 Fiat-Shamir 零知識證明 (限制於小基線模數 K_Q = q_1)
      - 樹狀四分搜尋 (4-ary Tree Bisection) 佇列批次過濾與惡意節點精準隔離 (Algorithm 6 & HQFSVerifier.verify_n_tree)
      - 整數委員會 Lagrange 重構 (compute_committee_lagrange)
      - 零密文疊加 (Zero-Ciphertext Superposition) 截斷代數計算軌跡以抵抗 CPA^D 並達成 IND-FuncCPA 電路隱私 (Algorithm 7 & 8)
      - 分散式多埠節點狀態機與 JSON 資料持久化 (DecentralizedClientNode)
    """

    def __init__(self, name: str = "HQ-FS (RNS-GLWE + Homomorphic Quotient ZKP + Zero-CT, Our Work)"):
        super().__init__(name)
        self.d: int = 16
        self.n_glwe: int = 2
        self.m_glwe: int = 2
        self.T: int = 1024
        self.eta: int = 1
        self.B_flood: int = 64
        self.num_parties: int = 10
        self.malicious_ratio: int = 20
        self.attack_type: str = "share_tampering"
        self.hqfs: Optional[HQFSRNSGLWE] = None
        self.decentralized_hqfs: Optional[DecentralizedHQFS] = None
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 32,
        m: int = 10,
        num_parties: int = 10,
        d: int = 16,
        n_glwe: int = 2,
        m_glwe: int = 2,
        eta: int = 1,
        B_flood: int = 64,
        malicious_ratio: int = 20,
        attack_type: str = "share_tampering",
        **kwargs
    ) -> Dict[str, Any]:
        """[Stage 1: Setup] Algorithm 1: 初始化 RNS 基底、基線模數 K_Q=q_1 與公共矩陣 A, A_zkp"""
        self.d = d
        self.n_glwe = n_glwe
        self.m_glwe = m_glwe
        self.T = 1 << m if m <= 16 else 1024
        self.eta = eta
        self.B_flood = B_flood
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "share_tampering"

        self.hqfs = HQFSRNSGLWE(
            d=self.d,
            n_glwe=self.n_glwe,
            m_glwe=self.m_glwe,
            T_plain=self.T,
            eta=self.eta,
            B_flood=self.B_flood,
            num_parties=self.num_parties
        )
        self.decentralized_hqfs = DecentralizedHQFS(
            d=self.d,
            T=self.T if (self.T > 2 and (self.T - 1) % (2 * self.d) == 0) else 65537,
            n_glwe=self.n_glwe,
            m_glwe=3,
            num_parties=self.num_parties,
            threshold_t=max(1, int(self.num_parties * 0.6))
        )
        return {
            "d": self.d,
            "n_glwe": self.n_glwe,
            "m_glwe": self.m_glwe,
            "T": self.T,
            "p_ntt": self.hqfs.p_ntt,
            "q_primes": self.hqfs.rns.q_primes,
            "K_Q": self.hqfs.K_Q,
            "B_flood": self.B_flood,
            "num_parties": self.num_parties,
            "malicious_ratio": self.malicious_ratio,
            "attack_type": self.attack_type,
            "decentralized_engine": "DecentralizedHQFS"
        }

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] Algorithm 2: 分散式私鑰 s^{(i)}、公鑰 pk_i 與 ZKP 承諾 C_i 生成"""
        if self.hqfs is None:
            self.setup()
        return self.hqfs.keygen_and_commitment()

    def preprocess(self) -> Dict[str, Any]:
        """[Stage 3: Offline Prep / RLKGen] Algorithm 3: 分散式 RNS 重線性化金鑰 RLK_global 生成 (含淹沒雜訊)"""
        if self.hqfs is None or not self.hqfs.node_keys:
            self.keygen()
        rlk_info = self.hqfs.rlk_gen()
        return {
            "rlk_entries": rlk_info["rlk_entries"],
            "rns_limbs": rlk_info["rns_limbs"],
            "K_Q": self.hqfs.K_Q
        }

    def encrypt(self, message: int) -> Tuple[Tuple[List[List[List[int]]], List[List[int]]], int]:
        """[Stage 4: Encrypt] Algorithm 4: RNS-GLWE 加密 (含 iNTT 編碼與淹沒雜訊)"""
        if self.hqfs is None or not self.hqfs.node_keys:
            self.keygen()
        ct = self.hqfs.encrypt(message)
        return ct, 0

    def encrypt_simd(self, slots: List[int]) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """Algorithm 4: RNS-GLWE iNTT 多槽 SIMD 加密"""
        if self.hqfs is None or not self.hqfs.node_keys:
            self.keygen()
        return self.hqfs.encrypt_simd(slots)

    def eval_add(
        self,
        ct1: Tuple[List[List[List[int]]], List[List[int]]],
        ct2: Tuple[List[List[List[int]]], List[List[int]]]
    ) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """[Stage 4a: Homo Add] Algorithm 7: 同態加法 + 零密文疊加 (Zero-Ciphertext Superposition)"""
        return self.hqfs.eval_add(ct1, ct2)

    def eval_mul(
        self,
        ct1: Tuple[List[List[List[int]]], List[List[int]]],
        ct2: Tuple[List[List[List[int]]], List[List[int]]]
    ) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """[Stage 4b: Homo Mul] Algorithm 8: RNS 數位分解同態乘法 + 零密文疊加"""
        return self.hqfs.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: Tuple[List[List[List[int]]], List[List[int]]], preprocessed_data: Optional[Any] = None) -> int:
        mu, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return mu

    def decrypt_simd_with_stages(
        self,
        ciphertext: Tuple[List[List[List[int]]], List[List[int]]],
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
        ciphertext: Tuple[List[List[List[int]]], List[List[int]]],
        preprocessed_data: Optional[Any] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[int, float, float]:
        """
        分別量測：
          - Stage 5 (Algorithm 5 Partial Decryption & HQ-FS ZKP Proof Generation modulo K_Q)
          - Stage 6 (Algorithm 6 BFS Queue / Tree Batch Verification + CRT Reconstruction + NTT Slot Extraction)
        """
        if self.hqfs is None or not self.hqfs.node_keys:
            self.keygen()

        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        num_mal = (self.num_parties * mr) // 100 if at != "none" else 0
        malicious_indices = set(random.sample(range(self.num_parties), num_mal)) if num_mal > 0 else set()

        u_rns, _ = ciphertext
        shares_map = {}
        proofs_map = {}

        t0 = time.perf_counter()
        for node_idx in range(self.num_parties):
            atk = at if node_idx in malicious_indices else None
            sh_i, pi_i = self.hqfs.partial_decrypt_node(node_idx, u_rns, malicious_attack=atk)
            shares_map[node_idx] = sh_i
            proofs_map[node_idx] = pi_i
        t_partial_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        m_vec, audit = self.hqfs.decrypt_with_bfs(ciphertext, shares_map, proofs_map)
        t_agg_ms = (time.perf_counter() - t1) * 1000.0

        self.last_audit = {
            "num_parties": self.num_parties,
            "malicious_ratio": mr,
            "num_malicious": num_mal,
            "attack_type": at,
            "rejected_count": len(audit["dropped_malicious_nodes"]),
            "rejected_parties_sample": [idx + 1 for idx in audit["dropped_malicious_nodes"][:8]],
            "bfs_steps": audit["bfs_steps"],
            "K_Q": audit["K_Q"],
            "decoded_simd_slots": m_vec[:16],
            "bft_defense": "Tree Bisection (Algorithm 6 & HQFSVerifier.verify_n_tree)",
            "reconstruction": "Integer Committee Lagrange (compute_committee_lagrange)",
            "decentralized_engine": "DecentralizedHQFS (RNS-GLWE + Dynamic C-Kernel + JSON Persistence)"
        }
        return m_vec[0], t_partial_ms, t_agg_ms

    def get_offline_metrics(self, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        num_rlk = preprocessed_data.get("rlk_entries", 12) if isinstance(preprocessed_data, dict) else 12
        storage_bits = num_rlk * self.d * 32
        return {
            "num_mults": num_rlk * self.d,
            "num_rand_bits": num_rlk * self.d * 8,
            "gate_storage_bits": storage_bits,
            "gate_storage_bytes": (storage_bits + 7) // 8
        }

    def get_online_metrics(self, ciphertext: Optional[Any] = None, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        rns_r = self.hqfs.rns.r if (self.hqfs and self.hqfs.rns) else 2
        bits_per_party = self.d * 32 * rns_r + self.d * 20 * (self.n_glwe + self.m_glwe + 2)
        total_comm = self.num_parties * bits_per_party
        return {
            "num_rounds": 1,
            "online_rounds": 1,
            "num_opens": 1,
            "opened_bits": total_comm,
            "comm_bits": total_comm,
            "num_openings": self.num_parties
        }
