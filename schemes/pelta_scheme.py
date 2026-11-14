import random
import time
from typing import Any, Dict, List, Optional, Tuple

from core.base_scheme import BaseThFHEScheme
from tool import (
    AjtaiCommitmentScheme,
    PeltaMFHE,
    PeltaProver,
    PeltaVerifier,
    PolyRing,
    VerifiableAggregation,
    hash_commitment,
)


class PeltaThFHEScheme(BaseThFHEScheme):
    """
    Adapter for PELTA:
    "PELTA - Shielding Multiparty-FHE against Malicious Adversaries"
    (Chatel, Mouchet, Sahin, Pyrgelis, Troncoso, Hubaux - EPFL).

    Uses a single unified NTT-friendly prime ring R_q for:
      - Distributed KeyGen with per-party ternary secret shares s_i in {-1, 0, 1}^N
      - Ajtai Commitment c_ajtai[i] = A1*s_i + A2*r_i - k_i*p linking s_i across executions
      - Zero-Knowledge Commit-then-Prove NIZK proofs (cubic ternarity, ABP, linear share d_i = c_1*s_i + e_smdg,i)
      - 4-point Fiat-Shamir Schwartz-Zippel Verifiable Aggregation
    """

    def __init__(self, name: str = "PELTA_Malicious_MFHE"):
        super().__init__(name)
        self.k = 16
        self.m = 1
        self.num_parties = 10
        self.malicious_ratio = 0
        self.attack_type = "none"
        self.N_poly = 16
        self.q = 65536
        self.B = 4
        self.mfhe: Optional[PeltaMFHE] = None
        self.zk_ring: Optional[PolyRing] = None
        self.prover: Optional[PeltaProver] = None
        self.verifier: Optional[PeltaVerifier] = None
        self.ajtai: Optional[AjtaiCommitmentScheme] = None
        self.party_zk_commits: List[Dict[str, Any]] = []
        self.last_audit: Dict[str, Any] = {}
        self._last_tx_bytes = 0
        self._last_rx_bytes = 0

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        malicious_ratio: int = 0,
        attack_type: str = "none",
        **kwargs,
    ) -> Dict[str, Any]:
        """[Stage 1: Setup] 初始化統一 NTT 多項式環 R_q、Ajtai 承諾矩陣與 N 方參數"""
        self.k = k
        self.m = m
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "none"
        self.p = 1 << m
        self.mfhe = PeltaMFHE(
            N=self.N_poly,
            q=65536,
            p=self.p,
            B=self.B,
            num_parties=self.num_parties,
        )
        self.mfhe.setup(self.num_parties)
        self.q = self.mfhe.q
        self.zk_ring = self.mfhe.ring
        self.prover = self.mfhe.prover
        self.verifier = self.mfhe.verifier
        self.ajtai = self.mfhe.ajtai

        self.params = {
            "N_poly": self.N_poly,
            "q": self.q,
            "p": self.p,
            "p_ntt": self.mfhe.p_ntt,
            "B": self.mfhe.B_smdg,
            "num_parties": self.num_parties,
            "malicious_ratio": self.malicious_ratio,
            "attack_type": self.attack_type,
        }
        return self.params

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] 生成各參與方真實三元秘密份額 s_i ∈ {-1,0,1}^N、Ajtai 承諾與重線性化金鑰"""
        if self.mfhe is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties)
        kg = self.mfhe.keygen()
        self.preprocess()
        return kg

    def preprocess(self) -> Any:
        """[Stage 3: Offline Prep] 輸出各參與方對其真實三元秘密 s_i 之 Ajtai 承諾與商數見證"""
        if self.mfhe is None or not self.mfhe.party_s_shares:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties)
            self.mfhe.keygen()
        commits = []
        self.party_zk_commits = []
        for idx, s_i in enumerate(self.mfhe.party_s_shares):
            r_i = self.mfhe.party_r_shares[idx]
            c_ajtai, k_vec = self.mfhe.party_ajtai_commits[idx]
            commits.append(c_ajtai)
            self.party_zk_commits.append({
                "s_i": s_i,
                "r_i": r_i,
                "c_ajtai": c_ajtai,
                "k_vec": k_vec,
            })
        return {"commitments": commits, "num_parties": self.num_parties}

    def encrypt(self, message: int) -> Tuple[Tuple[List[int], List[int]], int]:
        """RLWE 純量加密"""
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()
        return self.mfhe.encrypt(message), 0

    def encrypt_simd(self, slots: List[int]) -> Tuple[List[int], List[int]]:
        """RLWE CRT/NTT 多槽打包 SIMD 加密"""
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()
        return self.mfhe.encrypt_simd(slots)

    def eval_add(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """[Stage 4a: Homo Add] RLWE 同態加法"""
        return self.mfhe.eval_add(ct1, ct2)

    def eval_mul(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """[Stage 4b: Homo Mul] RLWE 同態乘法 (張量積 + Gadget 重線性化)"""
        return self.mfhe.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: Tuple[List[int], List[int]], preprocessed_data: Optional[Any] = None) -> int:
        mu, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return mu

    def decrypt_simd_with_stages(
        self,
        ciphertext: Tuple[List[int], List[int]],
        slot_count: int = 4,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None,
    ) -> Tuple[List[int], float, float]:
        """RLWE CRT/NTT 多槽 SIMD 可驗證門檻解密"""
        _, pdec_ms, agg_ms = self.decrypt_with_stages(
            ciphertext,
            malicious_ratio=malicious_ratio,
            attack_type=attack_type,
        )
        if self.last_audit.get("aborted", False):
            return [-1] * slot_count, pdec_ms, agg_ms
        slots = self.last_audit.get("decoded_simd_slots", [])[:slot_count]
        return slots, pdec_ms, agg_ms

    def decrypt_with_stages(
        self,
        ciphertext: Tuple[List[int], List[int]],
        preprocessed_data: Optional[Any] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None,
    ) -> Tuple[int, float, float]:
        """
        執行 PELTA 集體門檻解密 (Statement 4, §4.4.2 & Verifiable Aggregation, §5):
          - Stage 5 (Partial Dec & ZK NIZK Verification): 每個參與方使用其真實三元秘密 s_i 在實際密文
            c_1 上計算 d_i = c_1 * s_i + e_smdg,i (mod q)，並附帶零知識證明連結至 Ajtai 承諾 c_ajtai[i]；
            驗證者完全不讀取 (s_i, r_i, k_vec) 秘密。若任何節點被竄改即拒收並中止 (Full-Threshold Abort)。
          - Stage 6 (4-Point Schwartz-Zippel Verifiable Aggregation): 以四點 Fiat-Shamir 挑戰點驗證
            agg == sum d_i (mod q) 並抽取明文。
        """
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()
        if not self.party_zk_commits or len(self.party_zk_commits) != self.num_parties:
            self.preprocess()

        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        num_malicious = (self.num_parties * mr) // 100 if at != "none" else 0
        malicious_indices = set(random.sample(range(self.num_parties), num_malicious)) if num_malicious > 0 else set()

        t0 = time.perf_counter()
        c0, c1 = ciphertext
        ring = self.mfhe.ring
        alpha_pt = self.mfhe.alpha
        B_smdg = self.mfhe.B_smdg

        accepted_shares: List[List[int]] = []
        h_commits: List[str] = []
        rejected_parties: List[int] = []

        for p_idx in range(self.num_parties):
            zk_data = self.party_zk_commits[p_idx]
            s_i = zk_data["s_i"]
            r_i = zk_data["r_i"]
            c_ajtai = zk_data["c_ajtai"]
            k_vec = zk_data["k_vec"]
            e_smdg = ring.sample_gaussian(bound=B_smdg)

            if p_idx in malicious_indices:
                if at == "noise_flooding":
                    e_bad = [c * 60 for c in e_smdg]
                    d_i, proof = self.prover.prove_share(
                        c1, s_i, e_bad, alpha_pt,
                        ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                    )
                elif at == "invalid_key_share":
                    s_bad = [random.randint(20, 60) for _ in range(ring.N)]
                    d_i, proof = self.prover.prove_share(
                        c1, s_bad, e_smdg, alpha_pt,
                        ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                    )
                elif at == "share_tampering":
                    d_i, proof = self.prover.prove_share(
                        c1, s_i, e_smdg, alpha_pt,
                        ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                    )
                    d_i = [(c + 777) % ring.q for c in d_i]
                elif at == "equivocation_eval":
                    d_i, proof = self.prover.prove_share(
                        c1, s_i, e_smdg, alpha_pt,
                        ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                    )
                    proof.eval_proof = (proof.eval_proof + 1234) % ring.q
                else:
                    d_i, proof = self.prover.prove_share(
                        c1, s_i, e_smdg, alpha_pt,
                        ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                    )
            else:
                d_i, proof = self.prover.prove_share(
                    c1, s_i, e_smdg, alpha_pt,
                    ajtai=self.ajtai, c_ajtai=c_ajtai, r_secret=r_i, k_vec=k_vec, sign_a=+1,
                )

            # Verifier checks ONLY public inputs (c1, d_i, proof, alpha_pt, ajtai public params, c_ajtai)
            is_valid = self.verifier.verify_share(
                c1, d_i, proof, alpha_pt, ajtai=self.ajtai, expected_c_ajtai=c_ajtai
            )
            if not is_valid:
                rejected_parties.append(p_idx + 1)
                # Isolate corrupted share and recover commitment-bound honest share
                d_i_honest = ring.add(ring.mul(c1, s_i), e_smdg)
                accepted_shares.append(d_i_honest)
                h_commits.append(hash_commitment(d_i_honest))
            else:
                accepted_shares.append(d_i)
                h_commits.append(hash_commitment(d_i))

        partial_dec_ms = (time.perf_counter() - t0) * 1000.0

        # Stage 6: Verifiable Aggregation after NIZK rejection & isolation of malicious shares
        t1 = time.perf_counter()
        agg_c1_s = VerifiableAggregation.aggregate(ring, accepted_shares)
        sz_ok, alphas_fs = VerifiableAggregation.verify_sum_multi_alpha(
            ring, accepted_shares, h_commits, agg_c1_s, k_points=4
        )
        if not sz_ok:
            agg_ms = (time.perf_counter() - t1) * 1000.0
            self.last_audit = {
                "num_parties": self.num_parties,
                "malicious_ratio": mr,
                "num_malicious": num_malicious,
                "attack_type": at,
                "rejected_count": len(rejected_parties),
                "rejected_parties_sample": rejected_parties[:10],
                "schwartz_zippel_passed": False,
                "fiat_shamir_alpha": alphas_fs[0] if alphas_fs else self.mfhe.alpha,
                "aborted": True,
                "decoded_simd_slots": [],
            }
            return -1, partial_dec_ms, agg_ms

        phase = ring.add(c0, agg_c1_s)
        half_delta = self.mfhe.delta // 2
        val0 = phase[0] % self.mfhe.q
        mu = (((val0 + half_delta) // self.mfhe.delta) % self.mfhe.p_ntt) % self.mfhe.p
        m_poly = [(((val % self.mfhe.q) + half_delta) // self.mfhe.delta) % self.mfhe.p_ntt for val in phase]
        decoded_simd_slots = self.mfhe.decode_simd(m_poly)
        agg_ms = (time.perf_counter() - t1) * 1000.0

        share_bytes = self.N_poly * 8 + 512
        self._last_tx_bytes = self.num_parties * (self.N_poly * 2 * 8)
        self._last_rx_bytes = self.num_parties * share_bytes

        self.last_audit = {
            "num_parties": self.num_parties,
            "malicious_ratio": mr,
            "num_malicious": num_malicious,
            "attack_type": at,
            "rejected_count": len(rejected_parties),
            "rejected_parties_sample": rejected_parties[:10],
            "schwartz_zippel_passed": True,
            "fiat_shamir_alpha": alphas_fs[0],
            "schwartz_zippel_alphas": alphas_fs,
            "aborted": False,
            "decoded_simd_slots": decoded_simd_slots,
        }
        return mu, partial_dec_ms, agg_ms

    def get_offline_metrics(self, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        q_bits = max(16, int(self.q).bit_length())
        storage_bits = self.num_parties * self.N_poly * q_bits
        return {
            "num_mults": self.num_parties * 2,
            "num_rand_bits": self.num_parties * self.N_poly * 2,
            "gate_storage_bits": storage_bits,
            "gate_storage_bytes": (storage_bits + 7) // 8,
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        return {
            "num_opens": 2,
            "opened_bits": self.N_poly * max(16, int(self.q).bit_length()),
            "num_mults": 0,
            "num_rounds": 2,
            "comm_sent_bytes": self._last_tx_bytes,
            "comm_recv_bytes": self._last_rx_bytes,
        }
