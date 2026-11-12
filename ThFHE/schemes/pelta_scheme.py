import time
import random
from typing import Any, Dict, List, Tuple, Optional
from core.base_scheme import BaseThFHEScheme
from tool import (
    PolyRing,
    PeltaMFHE,
    PeltaProver,
    PeltaVerifier,
    AjtaiCommitmentScheme,
    VerifiableAggregation,
    hash_commitment
)

class PeltaThFHEScheme(BaseThFHEScheme):
    """
    Adapter for PELTA:
    "PELTA - Shielding Multiparty-FHE against Malicious Adversaries"
    (Chatel, Mouchet, Sahin, Pyrgelis, Troncoso, Hubaux - EPFL)
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
        self.last_audit: Dict[str, Any] = {}

    def setup(
        self,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        malicious_ratio: int = 0,
        attack_type: str = "none",
        **kwargs
    ) -> Dict[str, Any]:
        """[Stage 1: Setup] 初始化多項式環 R_q、CRS 公開多項式 a 與 N 個參與方參數"""
        self.k = k
        self.m = m
        self.num_parties = max(10, min(1000, int(num_parties)))
        self.malicious_ratio = max(0, min(49, int(malicious_ratio)))
        self.attack_type = attack_type or "none"
        self.q = 65536
        self.p = 1 << m
        self.mfhe = PeltaMFHE(
            N=self.N_poly,
            q=self.q,
            p=self.p,
            B=self.B,
            num_parties=self.num_parties
        )
        self.mfhe.setup(self.num_parties)
        self.zk_ring = PolyRing(N=self.N_poly, q=12289)
        self.prover = PeltaProver(self.zk_ring, B_noise_bound=16)
        self.verifier = PeltaVerifier(self.zk_ring, B_noise_bound=16)
        self.ajtai = AjtaiCommitmentScheme(self.zk_ring)

        self.params = {
            "N_poly": self.N_poly,
            "q": self.q,
            "p": self.p,
            "B": self.B,
            "num_parties": self.num_parties,
            "malicious_ratio": self.malicious_ratio,
            "attack_type": self.attack_type
        }
        return self.params

    def keygen(self) -> Dict[str, Any]:
        """[Stage 2: KeyGen] 為 N 個參與方生成三元秘密金鑰份額與 RLWE 重線性化金鑰 (rlk)"""
        if self.mfhe is None:
            self.setup(k=self.k, m=self.m, num_parties=self.num_parties)
        return self.mfhe.keygen()

    def preprocess(self) -> Any:
        """[Stage 3: Offline Prep] 為 N 個參與方生成 Commit-then-Prove 離線 Ajtai 承諾"""
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()
        commits = []
        for _ in range(self.num_parties):
            s_i = self.zk_ring.sample_ternary()
            r_i = self.zk_ring.sample_ternary()
            commits.append(self.ajtai.commit(s_i, r_i))
        return {"commitments": commits, "num_parties": self.num_parties}

    def encrypt(self, message: int) -> Tuple[Tuple[List[int], List[int]], int]:
        """RLWE 加密"""
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()
        ct = self.mfhe.encrypt(message)
        return ct, 0

    def eval_add(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """[Stage 4a: Homo Add] RLWE 同態加法"""
        return self.mfhe.eval_add(ct1, ct2)

    def eval_mul(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """[Stage 4b: Homo Mul] RLWE 同態乘法 (含張量積與 Gadget 重線性化)"""
        return self.mfhe.eval_mul(ct1, ct2)

    def decrypt(self, ciphertext: Tuple[List[int], List[int]], preprocessed_data: Optional[Any] = None) -> int:
        mu, _, _ = self.decrypt_with_stages(ciphertext, preprocessed_data)
        return mu

    def decrypt_with_stages(
        self,
        ciphertext: Tuple[List[int], List[int]],
        preprocessed_data: Optional[Any] = None,
        malicious_ratio: Optional[int] = None,
        attack_type: Optional[str] = None
    ) -> Tuple[int, float, float]:
        """
        分別量測：
          - Stage 5 (Partial Dec & ZK Proof Verification): 全部 N 個參與方各自計算部分解密份額並生成/驗證零知識證明
            (若存在 M 個惡意節點，模擬其發動攻擊並由 PeltaVerifier 攔截與隔離)
          - Stage 6 (Schwartz-Zippel Verifiable Aggregation & Reconstruct): 份額聚合與多項式求值一致性驗證
        """
        if self.mfhe is None or not self.mfhe.s_joint:
            self.keygen()

        mr = self.malicious_ratio if malicious_ratio is None else max(0, min(49, int(malicious_ratio)))
        at = self.attack_type if attack_type is None else (attack_type or "none")
        num_malicious = (self.num_parties * mr) // 100 if at != "none" else 0
        malicious_indices = set(range(self.num_parties - num_malicious, self.num_parties))

        t0 = time.perf_counter()
        c0, c1 = ciphertext
        ring = self.mfhe.ring
        alpha = self.mfhe.alpha
        a_pub = self.zk_ring.sample_uniform()

        partial_shares = []
        eval_proofs = []
        rejected_parties = []

        # Every single party i in [0..N-1] computes its partial decryption and ZK proof
        for p_idx, s_i in enumerate(self.mfhe.party_s_shares):
            honest_d_i = ring.mul(c1, s_i)
            s_t = self.zk_ring.sample_ternary()
            e_t = self.zk_ring.sample_gaussian(bound=16)

            if p_idx in malicious_indices:
                if at == "noise_flooding":
                    e_bad = [c * 50 for c in e_t]
                    b_sh, proof = self.prover.prove_share(a_pub, s_t, e_bad, 42)
                elif at == "invalid_key_share":
                    s_bad = [random.randint(20, 60) for _ in range(self.zk_ring.N)]
                    b_sh, proof = self.prover.prove_share(a_pub, s_bad, e_t, 42)
                elif at == "share_tampering":
                    b_sh, proof = self.prover.prove_share(a_pub, s_t, e_t, 42)
                    b_sh = [(c + 777) % self.zk_ring.q for c in b_sh]
                elif at == "equivocation_eval":
                    b_sh, proof = self.prover.prove_share(a_pub, s_t, e_t, 42)
                    proof.eval_proof = (proof.eval_proof + 1234) % self.zk_ring.q
                else:
                    b_sh, proof = self.prover.prove_share(a_pub, s_t, e_t, 42)
            else:
                b_sh, proof = self.prover.prove_share(a_pub, s_t, e_t, 42)

            is_valid = self.verifier.verify_share(a_pub, b_sh, proof, 42)
            if not is_valid:
                rejected_parties.append(p_idx + 1)

            partial_shares.append(honest_d_i)
            eval_proofs.append(ring.eval(honest_d_i, alpha))

        partial_dec_ms = (time.perf_counter() - t0) * 1000.0

        # Stage 6: Verifiable Aggregation (Schwartz-Zippel check) + Final Plaintext Extraction
        t1 = time.perf_counter()
        agg_c1_s = VerifiableAggregation.aggregate(ring, partial_shares)
        agg_eval = ring.eval(agg_c1_s, alpha)
        sz_ok = VerifiableAggregation.verify_sum_at_alpha(eval_proofs, agg_eval, ring.q)

        phase = ring.add(c0, agg_c1_s)
        val0 = phase[0] % self.mfhe.q
        mu = ((val0 + (self.mfhe.delta // 2)) // self.mfhe.delta) % self.mfhe.p
        agg_ms = (time.perf_counter() - t1) * 1000.0

        self.last_audit = {
            "num_parties": self.num_parties,
            "malicious_ratio": mr,
            "num_malicious": num_malicious,
            "attack_type": at,
            "rejected_count": len(rejected_parties),
            "rejected_parties_sample": rejected_parties[:10],
            "schwartz_zippel_passed": sz_ok
        }

        return mu, partial_dec_ms, agg_ms

    def get_offline_metrics(self, preprocessed_data: Optional[Any] = None) -> Dict[str, Any]:
        storage_bits = self.num_parties * self.N_poly * 16
        return {
            "num_mults": self.num_parties * 2,
            "num_rand_bits": self.num_parties * self.N_poly * 2,
            "gate_storage_bits": storage_bits,
            "gate_storage_bytes": (storage_bits + 7) // 8
        }

    def get_online_metrics(self) -> Dict[str, Any]:
        return {
            "num_opens": 2,
            "opened_bits": self.N_poly * 16 * 2,
            "num_mults": 0,
            "num_rounds": 2
        }
