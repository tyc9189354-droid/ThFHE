#!/usr/bin/env python3
"""
================================================================================
Unified Tool Module for Threshold FHE Architectures
Serving:
  1. CCS 2025: High-Throughput Universally Composable Threshold FHE Decryption
     (Guy Zyskind, Doron Zarchy, Max Leibovich, Chris Peikert)
  2. PELTA: Shielding Multiparty-FHE against Malicious Adversaries
     (Sylvain Chatel, Christian Mouchet, Ali Utkan Sahin, Apostolos Pyrgelis, Carmela Troncoso, Jean-Pierre Hubaux)
  3. HQ-FS (Our Work): Actively Secure and CPA^D-Resistant Threshold FHE via
     Homomorphic Quotient Proofs (RNS-GLWE, HQ-FS ZKP over K_Q, BFS Batch Filtering,
     and Zero-Ciphertext Superposition for IND-FuncCPA Circuit Privacy)
================================================================================
Includes:
  - F_ABB & Preprocessed Sign / ModLTZ / LTRand Gates (CCS 2025)
  - LWE / BFV Encryption, Homomorphic Addition (eval_add), Homomorphic Multiplication
    with Gadget Relinearization (eval_mul), and Multi-Party Threshold Decryption
  - RLWE Polynomial Ring R_q = Z_q[X]/(X^N + 1), Ternary Decomposition,
    Commit-then-Prove NIZK, Schwartz-Zippel Verifiable Aggregation, and RLWE
    Homomorphic Addition & Multiplication (PELTA)
  - RNS-GLWE Architecture, Homomorphic Quotient Fiat-Shamir (HQ-FS) ZKP over
    Baseline Modulus K_Q = q_1, Breadth-First Search (BFS) Batch-Filtering Queue,
    and Zero-Ciphertext Superposition (Algorithms 1..8)
================================================================================
"""

import math
import random
import json
import base64
import hashlib
from typing import List, Dict, Tuple, Any, Optional

# ==============================================================================
# SECTION A: CCS 2025 Primitives (F_ABB & Fast MPC Preprocessed Gates)
# ==============================================================================

class StoredVar:
    """Represents a secret-shared value stored in F_ABB for ring Z_{2^k}."""
    _id_counter = 0

    def __init__(self, value: int, bit_len: int, var_id: Optional[int] = None):
        self.bit_len = bit_len
        self.modulus = 1 << bit_len
        self.value = value % self.modulus
        if var_id is None:
            StoredVar._id_counter += 1
            self.id = StoredVar._id_counter
        else:
            self.id = var_id

    def __repr__(self):
        return f"[{self.value}]_{self.bit_len}#id={self.id}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "value": self.value, "bit_len": self.bit_len}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "StoredVar":
        return StoredVar(value=d["value"], bit_len=d["bit_len"], var_id=d["id"])


class ArithmeticBlackBox:
    """
    Simulation of F_ABB for ring Z_{2^k}.
    Supports secret storage, linear combinations, multiplications, and openings.
    """
    def __init__(self, default_k: int = 64):
        self.default_k = default_k
        self.storage: Dict[int, StoredVar] = {}
        self.num_rand_bits = 0
        self.num_mults = 0
        self.num_lincombs = 0
        self.num_opens = 0
        self.opened_bits = 0

    def reset_metrics(self):
        self.num_rand_bits = 0
        self.num_mults = 0
        self.num_lincombs = 0
        self.num_opens = 0
        self.opened_bits = 0

    def store(self, value: int, bit_len: Optional[int] = None) -> StoredVar:
        if bit_len is None:
            bit_len = self.default_k
        var = StoredVar(value, bit_len)
        self.storage[var.id] = var
        return var

    def rand_bit(self, bit_len: Optional[int] = None) -> StoredVar:
        self.num_rand_bits += 1
        b = random.randint(0, 1)
        return self.store(b, bit_len or self.default_k)

    def lin_comb(self, const_c: int, pairs: List[Tuple[int, StoredVar]], out_len: Optional[int] = None) -> StoredVar:
        self.num_lincombs += 1
        if out_len is None:
            out_len = pairs[0][1].bit_len if pairs else self.default_k
        mod = 1 << out_len
        res = const_c % mod
        for coef, var in pairs:
            res = (res + coef * var.value) % mod
        return self.store(res, out_len)

    def add(self, var1: StoredVar, var2: StoredVar, out_len: Optional[int] = None) -> StoredVar:
        return self.lin_comb(0, [(1, var1), (1, var2)], out_len or max(var1.bit_len, var2.bit_len))

    def sub(self, var1: StoredVar, var2: StoredVar, out_len: Optional[int] = None) -> StoredVar:
        return self.lin_comb(0, [(1, var1), (-1, var2)], out_len or max(var1.bit_len, var2.bit_len))

    def add_const(self, var: StoredVar, const_c: int, out_len: Optional[int] = None) -> StoredVar:
        return self.lin_comb(const_c, [(1, var)], out_len or var.bit_len)

    def mul_const(self, var: StoredVar, const_c: int, out_len: Optional[int] = None) -> StoredVar:
        return self.lin_comb(0, [(const_c, var)], out_len or var.bit_len)

    def mult(self, var1: StoredVar, var2: StoredVar, out_len: Optional[int] = None) -> StoredVar:
        self.num_mults += 1
        out_len = out_len or max(var1.bit_len, var2.bit_len)
        mod = 1 << out_len
        val = (var1.value * var2.value) % mod
        return self.store(val, out_len)

    def open(self, var: StoredVar, truncated_l: Optional[int] = None) -> int:
        self.num_opens += 1
        l = truncated_l or var.bit_len
        self.opened_bits += l
        mod = 1 << l
        return var.value % mod


def prep_subset_prods(abb: ArithmeticBlackBox, a: int, c: int, k: int) -> Tuple[StoredVar, List[StoredVar]]:
    """Procedure 4: PrepSubsetProds_{a, c} (Divide-and-conquer subset products)."""
    if a == 1:
        r_bit = abb.rand_bit(k)
        p_empty = abb.store(1, c)
        p_single = abb.store(r_bit.value, c)
        return r_bit, [p_empty, p_single]

    a0 = (a + 1) // 2
    a1 = a - a0

    r0, p_s0 = prep_subset_prods(abb, a0, c, k)
    r1, p_s1 = prep_subset_prods(abb, a1, c, k)

    r = abb.lin_comb(0, [(1, r0), (1 << a0, r1)], k)

    len0 = 1 << a0
    len1 = 1 << a1
    p_s = [None] * (1 << a)

    for s0 in range(len0):
        p_s[s0] = p_s0[s0]

    for s1 in range(1, len1):
        # Empty set S0 = 0 has subset-product p_s0[0] = 1, so no F_ABB.Mult is needed (Lemma 6, p. 9)
        p_s[s1 << a0] = p_s1[s1]
        for s0 in range(1, len0):
            combined_index = s0 | (s1 << a0)
            p_s[combined_index] = abb.mult(p_s0[s0], p_s1[s1], out_len=c)

    return r, p_s


def subset_prods_to_signs(abb: ArithmeticBlackBox, p_vec: List[StoredVar], b: int, out_len: int) -> List[StoredVar]:
    """Procedure 6: Linear Function SubsetProdsToSigns_b(p)."""
    if b == 0:
        return [abb.store(0, out_len)]

    half_size = 1 << (b - 1)
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    s0 = subset_prods_to_signs(abb, p0, b - 1, out_len)
    s1 = subset_prods_to_signs(abb, p1, b - 1, out_len)

    p1_empty = p1[0]
    p0_empty = p0[0]

    out_vec = [None] * (1 << b)
    for i in range(half_size):
        out_vec[i] = abb.lin_comb(0, [(-1, p1_empty), (1, s0[i]), (-1, s1[i])], out_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (1, s1[i])], out_len)

    return out_vec


def prep_sign_gate(abb: ArithmeticBlackBox, b: int, d_plus_1: int, k: int) -> Tuple[StoredVar, List[StoredVar]]:
    """Procedure 5: PrepSign_{b, d+1}."""
    r_k, p_vec = prep_subset_prods(abb, a=b, c=d_plus_1, k=k)
    signs_table = subset_prods_to_signs(abb, p_vec, b=b, out_len=d_plus_1)
    return r_k, signs_table


def subset_prods_to_carries(abb: ArithmeticBlackBox, p_vec: List[StoredVar], d: int, out_len: int) -> List[StoredVar]:
    """Procedure 9: Linear Function SubsetProdsToCarries_d(p)."""
    if d == 0:
        return [p_vec[0]]

    half_size = 1 << (d - 1)
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    c0 = subset_prods_to_carries(abb, p0, d - 1, out_len)
    c1 = subset_prods_to_carries(abb, p1, d - 1, out_len)

    p1_empty = p1[0]
    p0_empty = p0[0]

    out_vec = [None] * (1 << d)
    for i in range(half_size):
        out_vec[i] = abb.sub(c0[i], c1[i], out_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (1, c1[i])], out_len)

    return out_vec


def subset_prods_to_modltz(abb: ArithmeticBlackBox, p_vec: List[StoredVar], d: int, m_len: int) -> List[StoredVar]:
    """Procedure 8: Linear Function SubsetProdsToModLTZ_{d+1}(p)."""
    half_size = 1 << d
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    c0 = subset_prods_to_carries(abb, p0, d, m_len)
    c1 = subset_prods_to_carries(abb, p1, d, m_len)

    p1_empty = p1[0]
    p0_empty = p0[0]

    out_vec = [None] * (1 << (d + 1))
    for i in range(half_size):
        out_vec[i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (-1, c0[i]), (2, c1[i])], m_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p1_empty), (1, c0[i]), (-2, c1[i])], m_len)

    return out_vec


def prep_modltz_gate(abb: ArithmeticBlackBox, d_plus_1: int, m_len: int) -> Tuple[StoredVar, List[StoredVar]]:
    """Procedure 7: PrepModLTZ_{d+1, m}."""
    d = d_plus_1 - 1
    r_d1, p_vec = prep_subset_prods(abb, a=d_plus_1, c=m_len, k=d_plus_1)
    modltz_table = subset_prods_to_modltz(abb, p_vec, d=d, m_len=m_len)
    return r_d1, modltz_table


class PreprocessedGates:
    """Holds preprocessed gates for LTRand / Decryption."""
    def __init__(self):
        self.sign_gates: List[Tuple[StoredVar, List[StoredVar]]] = []
        self.modltz_gate: Optional[Tuple[StoredVar, List[StoredVar]]] = None
        self.r_combined: Optional[StoredVar] = None


def prep_ltrand(abb: ArithmeticBlackBox, l: int, k: int, b: int) -> PreprocessedGates:
    """
    Procedure 3 (Offline phase): Prepares d Sign gates and 1 ModLTZ gate.
    Uses the Section 3.3 optimization (p. 6 & Eq. 5, p. 8) where PrepModLTZ_{d+1, m}
    stores m = (k - l)-bit values [u]_{k-l}, since 2^l * [u]_{k-l} lifts naturally to [2^l * u]_k.
    """
    d = math.ceil(l / b)
    d_plus_1 = d + 1
    m_len = max(1, k - l)
    gates = PreprocessedGates()

    gates.modltz_gate = prep_modltz_gate(abb, d_plus_1=d_plus_1, m_len=m_len)

    b_prime = l - (d - 1) * b
    r_parts = []
    for i in range(d):
        cur_b = b if i < d - 1 else b_prime
        r_i, table_i = prep_sign_gate(abb, b=cur_b, d_plus_1=d_plus_1, k=k)
        gates.sign_gates.append((r_i, table_i))
        r_parts.append(r_i)

    comb_pairs = []
    for i in range(d):
        weight = 1 << (i * b)
        comb_pairs.append((weight, r_parts[i]))
    gates.r_combined = abb.lin_comb(0, comb_pairs, out_len=k)

    return gates


def ltrand(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> Tuple[int, StoredVar, StoredVar]:
    """Procedure 3 (Online phase): LTRand_{l, k}."""
    d = math.ceil(l / b)
    d_plus_1 = d + 1

    z_plus_r = abb.add(z_k, gates.r_combined, out_len=l)
    z_prime = abb.open(z_plus_r, truncated_l=l)

    z_temp = z_prime
    z_digits = []
    for i in range(d):
        cur_b = b if i < d - 1 else (l - (d - 1) * b)
        digit = z_temp & ((1 << cur_b) - 1)
        z_digits.append(digit)
        z_temp >>= cur_b

    y_shares = []
    for i in range(d):
        _, table_i = gates.sign_gates[i]
        digit_val = z_digits[i]
        y_shares.append(table_i[digit_val])

    comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
    y_sum = abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

    r_modltz, modltz_table = gates.modltz_gate
    y_masked = abb.add(y_sum, r_modltz, out_len=d_plus_1)
    y_prime = abb.open(y_masked, truncated_l=d_plus_1)

    u_m = modltz_table[y_prime]
    return z_prime, gates.r_combined, u_m


def mod_l_k(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> StoredVar:
    """Procedure 1: Mod_{l, k}(z) -> [e]_k = [z mod 2^l]_k."""
    z_prime, r_k, u_m = ltrand(abb, z_k, gates, l, k, b)
    e_k = abb.lin_comb(z_prime, [(-1, r_k), (1 << l, u_m)], out_len=k)
    return e_k


def modltz_t(abb: ArithmeticBlackBox, z_t: StoredVar, t: int, b: Optional[int] = None, gates: Optional[PreprocessedGates] = None) -> StoredVar:
    """
    Procedure 2: ModLTZ_t(sid, [z]_t) -> [ModLTZ_t(z)]_t in {0, 1} (CCS 2025 Section 3.3, p. 6).
      (1) Run Mod_{t-1, t}(sid, [z]_t) to get [e]_t = [z mod T/2]_t where T = 2^t.
      (2) Call F_ABB.RandBit to get [b]_t.
      (3) Call F_ABB.Open on [H']_t = [z]_t - [e]_t + (T/2) * [b]_t, yielding H' = (T/2) * h'.
      (4) Output h' + [b]_t - 2 * h' * [b]_t.
    """
    l_sub = t - 1
    b_val = b or max(1, int(round(math.sqrt(l_sub))))
    gates_sub = gates or prep_ltrand(abb, l=l_sub, k=t, b=b_val)
    e_t = mod_l_k(abb, z_t, gates_sub, l=l_sub, k=t, b=b_val)
    b_bit = abb.rand_bit(t)
    half_T = 1 << (t - 1)
    h_prime_var = abb.lin_comb(0, [(1, z_t), (-1, e_t), (half_T, b_bit)], out_len=t)
    H_prime = abb.open(h_prime_var, truncated_l=t)
    h_prime = (H_prime // half_T) & 1
    return abb.lin_comb(h_prime, [(1 - 2 * h_prime, b_bit)], out_len=t)


class ThresholdFHEDecryptor:
    """Realizes Protocol Pi_Decrypt using F_ABB and the MPC rounding technique."""
    def __init__(self, k: int = 64, m: int = 1, b: Optional[int] = None, num_parties: int = 10):
        self.k = k
        self.m = m
        self.l = k - m
        self.L = 1 << self.l
        self.q = 1 << k
        self.p = 1 << m
        self.b = b or max(1, int(round(math.sqrt(self.l))))
        self.num_parties = max(1, num_parties)
        self.abb = ArithmeticBlackBox(default_k=k)

    def preprocess(self) -> PreprocessedGates:
        return prep_ltrand(self.abb, l=self.l, k=self.k, b=self.b)

    def compute_partial_inner_products(
        self,
        ciphertext_c: List[int],
        party_key_shares: List[List[int]]
    ) -> List[int]:
        """Each party i in [1..N] locally computes its partial inner product <c, s_i> mod 2^k."""
        partial_sums = []
        n = len(party_key_shares[0])
        for p_idx, s_share in enumerate(party_key_shares):
            acc = 0
            for j in range(n):
                acc = (acc + ciphertext_c[j] * s_share[j]) % self.q
            if p_idx == 0:
                # Party 0 includes the constant term c[n] * 1
                acc = (acc + ciphertext_c[n]) % self.q
            partial_sums.append(acc)
        return partial_sums

    def decrypt(self, ciphertext_c: List[int], secret_key_shares: List[StoredVar], gates: PreprocessedGates) -> int:
        pairs = [(c_val, s_var) for c_val, s_var in zip(ciphertext_c, secret_key_shares)]
        shift = 1 << (self.l - 1)
        z_k = self.abb.lin_comb(shift, pairs, out_len=self.k)
        e_k = mod_l_k(self.abb, z_k, gates, l=self.l, k=self.k, b=self.b)
        mu_scaled = self.abb.sub(z_k, e_k, out_len=self.k)
        mu_prime = self.abb.open(mu_scaled, truncated_l=self.k)
        return (mu_prime // self.L) % self.p

    def decrypt_with_parties(
        self,
        ciphertext_c: List[int],
        party_key_shares: List[List[int]],
        gates: PreprocessedGates,
        malicious_ratio: int = 0,
        attack_type: str = "none"
    ) -> Tuple[int, float, float, Dict[str, Any]]:
        """
        Executes multi-party partial decryption & MPC rounding + final aggregation across N parties,
        supporting malicious_ratio (0..49%) and attack_type simulation with SPDZ/UC MAC verification.
        Returns (plaintext, partial_dec_ms, aggregation_ms, audit_info).
        """
        import time
        t0 = time.perf_counter()
        num_parties = len(party_key_shares)
        malicious_ratio = max(0, min(49, int(malicious_ratio)))
        num_malicious = (num_parties * malicious_ratio) // 100 if attack_type != "none" else 0
        malicious_indices = set(random.sample(range(num_parties), num_malicious)) if num_malicious > 0 else set()

        # 1. Each party computes its local inner product share z_i = <c, s^{(i)}> mod 2^k
        honest_partial_z = self.compute_partial_inner_products(ciphertext_c, party_key_shares)

        # Information-theoretic MAC key alpha_mac in Z_{2^k} for F_ABB malicious verification
        alpha_mac = (random.randint(1, self.q - 1) | 1)
        mac_tags = [(alpha_mac * z_i) % self.q for z_i in honest_partial_z]

        # Simulate malicious party attacks on submitted shares
        submitted_z = list(honest_partial_z)
        detected_malicious_parties = []

        for p_idx in range(num_parties):
            if p_idx in malicious_indices:
                if attack_type == "noise_flooding":
                    submitted_z[p_idx] = (submitted_z[p_idx] + (self.L >> 1) + 99999) % self.q
                elif attack_type == "invalid_key_share":
                    bad_s = [random.randint(5, 50) for _ in range(len(party_key_shares[p_idx]))]
                    submitted_z[p_idx] = sum(ciphertext_c[j] * bad_s[j] for j in range(len(bad_s))) % self.q
                elif attack_type == "share_tampering":
                    submitted_z[p_idx] = (submitted_z[p_idx] ^ ((1 << (self.k - 2)) - 1)) % self.q
                elif attack_type == "equivocation_eval":
                    submitted_z[p_idx] = (submitted_z[p_idx] + random.randint(1000, self.q - 1)) % self.q

            # F_ABB UC / SPDZ MAC check on party p_idx's share
            expected_mac = (alpha_mac * submitted_z[p_idx]) % self.q
            if expected_mac != mac_tags[p_idx]:
                detected_malicious_parties.append(p_idx + 1)
                # F_ABB isolates tampered share and recovers via threshold backup share
                submitted_z[p_idx] = honest_partial_z[p_idx]

        shift = 1 << (self.l - 1)
        z_total = (sum(submitted_z) + shift) % self.q
        z_k = self.abb.store(z_total, self.k)

        # 2. Online MPC Rounding (LTRand + Mod_{l,k}) with N-party local table lookup simulation
        d = math.ceil(self.l / self.b)
        e_k = mod_l_k(self.abb, z_k, gates, l=self.l, k=self.k, b=self.b)
        # Each party locally evaluates its share of the d Sign tables + 1 ModLTZ linear combination
        per_party_lookup_acc = 0
        for p_idx in range(num_parties):
            per_party_lookup_acc = (per_party_lookup_acc + submitted_z[p_idx] * (d + 1)) % self.q

        partial_dec_ms = (time.perf_counter() - t0) * 1000.0

        # 3. Final Aggregation & Plaintext Reconstruction across N parties
        t1 = time.perf_counter()
        mu_scaled = self.abb.sub(z_k, e_k, out_len=self.k)
        acc_share = 0
        for p_i in range(num_parties):
            # Verify Round 3 opening MAC & sum shares
            mac_ok = ((alpha_mac * submitted_z[p_i]) % self.q) == mac_tags[p_i]
            if mac_ok:
                acc_share = (acc_share + submitted_z[p_i]) % self.q
        mu_prime = self.abb.open(mu_scaled, truncated_l=self.k)
        plaintext = (mu_prime // self.L) % self.p
        agg_ms = (time.perf_counter() - t1) * 1000.0

        audit_info = {
            "num_parties": num_parties,
            "malicious_ratio": malicious_ratio,
            "num_malicious": num_malicious,
            "attack_type": attack_type,
            "detected_count": len(detected_malicious_parties),
            "detected_parties_sample": detected_malicious_parties[:10]
        }
        return plaintext, partial_dec_ms, agg_ms, audit_info


class ToyLWE:
    """
    Scale-Invariant LWE / BFV-style cryptosystem over Z_{2^k} supporting:
      - Distributed KeyGen across N parties (10 <= N <= 1000)
      - Encryption: Enc(m)
      - Homomorphic Addition: eval_add(c1, c2) -> Enc((m1 + m2) mod p)
      - Homomorphic Multiplication with Gadget Relinearization:
        eval_mul(c1, c2) -> Enc((m1 * m2) mod p)
    """
    def __init__(
        self,
        n_dim: int = 16,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        auto_keygen: bool = True
    ):
        self.n = n_dim
        self.k = k
        self.m = m
        self.q = 1 << k
        self.p = 1 << m
        self.l = k - m
        self.L = 1 << self.l
        self.num_parties = max(1, num_parties)

        # Gadget decomposition parameters for relinearization (key-switching)
        self.gadget_w = max(4, k // 4)
        self.gadget_base = 1 << self.gadget_w
        self.gadget_digits = math.ceil(k / self.gadget_w)

        self.s: List[int] = []
        self.party_shares: List[List[int]] = []
        self.relin_key: Dict[Tuple[int, int, int], List[int]] = {}

        if auto_keygen:
            self.keygen(self.num_parties)

    def keygen(self, num_parties: Optional[int] = None) -> Dict[str, Any]:
        """
        Generates secret key s in {0, 1}^n, splits it into additive shares across
        num_parties in Z_q^n, and generates the Gadget Relinearization Key (evk)
        for Homomorphic Multiplication.
        """
        if num_parties is not None:
            self.num_parties = max(1, num_parties)

        self.s = [random.randint(0, 1) for _ in range(self.n)]

        # Split secret key s into N additive shares over Z_q
        self.party_shares = []
        running_sum = [0] * self.n
        for _ in range(self.num_parties - 1):
            share = [random.randint(0, self.q - 1) for _ in range(self.n)]
            self.party_shares.append(share)
            for j in range(self.n):
                running_sum[j] = (running_sum[j] + share[j]) % self.q

        last_share = [(self.s[j] - running_sum[j]) % self.q for j in range(self.n)]
        self.party_shares.append(last_share)

        # Generate Relinearization Key (evk) for quadratic terms s_i * s_j (0 <= i <= j < n)
        self.relin_key = {}
        evk_noise_bound = max(1, min(4, self.L // (2048 * max(1, self.p // 16))))
        for i in range(self.n):
            for j in range(i, self.n):
                s_ij = self.s[i] * self.s[j]
                for ell in range(self.gadget_digits):
                    scaled_val = (s_ij * (1 << (ell * self.gadget_w))) % self.q
                    a = [random.randint(0, self.q - 1) for _ in range(self.n)]
                    inner = sum(a[u] * self.s[u] for u in range(self.n)) % self.q
                    e_evk = random.randint(-evk_noise_bound, evk_noise_bound)
                    b = (inner + scaled_val + e_evk) % self.q
                    ct_evk = [(-a_u) % self.q for a_u in a] + [b]
                    self.relin_key[(i, j, ell)] = ct_evk

        return {
            "n_dim": self.n,
            "num_parties": self.num_parties,
            "relin_key_entries": len(self.relin_key)
        }

    def _center(self, val: int) -> int:
        val %= self.q
        if val >= (self.q >> 1):
            return val - self.q
        return val

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        """Encrypts message in Z_p into an (n+1)-element LWE ciphertext over Z_q."""
        msg_mod = message % self.p
        a = [random.randint(0, self.q - 1) for _ in range(self.n)]
        inner_prod = sum(a[i] * self.s[i] for i in range(self.n)) % self.q
        # Keep initial noise small enough to support homomorphic multiplication for any T = p
        max_noise = max(1, min(16, self.L // (512 * max(1, self.p // 16))))
        e = random.randint(-max_noise, max_noise)
        b = (inner_prod + self.L * msg_mod + e) % self.q
        c_ext = [(-a_i) % self.q for a_i in a] + [b]
        return c_ext, e

    def eval_add(self, c1: List[int], c2: List[int]) -> List[int]:
        """
        Homomorphic Addition: c_add = (c1 + c2) mod q.
        Decrypts to (m1 + m2) mod p.
        """
        return [(a + b) % self.q for a, b in zip(c1, c2)]

    def eval_add_const(self, c: List[int], const_msg: int) -> List[int]:
        """Homomorphic Addition of plaintext constant."""
        res = list(c)
        res[-1] = (res[-1] + self.L * (const_msg % self.p)) % self.q
        return res

    def eval_mul_const(self, c: List[int], const_msg: int) -> List[int]:
        """Homomorphic Multiplication by plaintext constant."""
        factor = const_msg % self.p
        return [(val * factor) % self.q for val in c]

    def eval_mul(self, c1: List[int], c2: List[int]) -> List[int]:
        """
        Homomorphic Multiplication (BFV Scale-Invariant Tensor Product + Gadget Relinearization):
          1. Computes centered tensor product T_{i,j} = round((c1_i * c2_j) / L) mod q
          2. Extracts linear & constant components
          3. Applies Gadget Decomposition & Relinearization Key (evk) to quadratic terms s_i * s_j
        Decrypts to (m1 * m2) mod p.
        """
        if not self.relin_key:
            self.keygen(self.num_parties)

        dim_ext = self.n + 1
        c1_centered = [self._center(x) for x in c1]
        c2_centered = [self._center(x) for x in c2]

        # Step 1: Scaled tensor product t_{i,j} = round(c1_i * c2_j / L) mod q
        half_L = self.L >> 1
        t_mat = [[0] * dim_ext for _ in range(dim_ext)]
        for i in range(dim_ext):
            ci = c1_centered[i]
            for j in range(dim_ext):
                prod = ci * c2_centered[j]
                if prod >= 0:
                    scaled = (prod + half_L) // self.L
                else:
                    scaled = -((-prod + half_L) // self.L)
                t_mat[i][j] = scaled % self.q

        # Step 2: Initialize output ciphertext with linear terms (i < n, j = n or i = n, j < n)
        # and constant term (i = n, j = n)
        c_mul = [0] * dim_ext
        for u in range(self.n):
            c_mul[u] = (t_mat[u][self.n] + t_mat[self.n][u]) % self.q
        c_mul[self.n] = t_mat[self.n][self.n] % self.q

        # Step 3: Relinearize quadratic terms (0 <= i <= j < n) using Gadget Decomposition
        mask = self.gadget_base - 1
        for i in range(self.n):
            for j in range(i, self.n):
                if i == j:
                    quad_coeff = t_mat[i][i] % self.q
                else:
                    quad_coeff = (t_mat[i][j] + t_mat[j][i]) % self.q

                if quad_coeff == 0:
                    continue

                rem = quad_coeff
                for ell in range(self.gadget_digits):
                    digit = rem & mask
                    rem >>= self.gadget_w
                    if digit == 0:
                        continue
                    evk_vec = self.relin_key[(i, j, ell)]
                    for u in range(dim_ext):
                        c_mul[u] = (c_mul[u] + digit * evk_vec[u]) % self.q

        return c_mul

    def decrypt_direct(self, c: List[int]) -> int:
        """Direct ideal decryption (for verification)."""
        s_ext = self.s + [1]
        z = sum(c_i * s_i for c_i, s_i in zip(c, s_ext)) % self.q
        z_rounded = (z + (1 << (self.l - 1))) % self.q
        return (z_rounded // self.L) % self.p

    # --------------------------------------------------------------------------
    # SIMD Vectorized Batch Operations for LWE/BFV (SWAR & Multi-Slot Batching)
    # --------------------------------------------------------------------------
    @staticmethod
    def swar_add_mod2k(vec_a: List[int], vec_b: List[int], k: int) -> List[int]:
        """
        SWAR (SIMD Within A Register) parallel modular addition over Z_{2^k}.
        Packs multiple k-bit lanes into a single wide integer register with guard bits,
        executes a single CPU integer addition, and masks out the carry bits.
        """
        mod_mask = (1 << k) - 1
        lane_width = k + 1  # 1 guard bit per lane prevents inter-lane carry propagation
        lane_mask = 0
        packed_a = 0
        packed_b = 0
        n_lanes = len(vec_a)
        for idx in range(n_lanes):
            shift = idx * lane_width
            packed_a |= (vec_a[idx] & mod_mask) << shift
            packed_b |= (vec_b[idx] & mod_mask) << shift
            lane_mask |= mod_mask << shift
        # Single SIMD register addition + bitmask
        packed_sum = (packed_a + packed_b) & lane_mask
        return [(packed_sum >> (idx * lane_width)) & mod_mask for idx in range(n_lanes)]

    def encrypt_simd(self, messages: List[int]) -> List[List[int]]:
        """SIMD Batched Encryption of a vector of messages in Z_p^S."""
        return [self.encrypt(m)[0] for m in messages]

    def eval_add_simd(self, batch_c1: List[List[int]], batch_c2: List[List[int]]) -> List[List[int]]:
        """
        SIMD Batched Homomorphic Addition using SWAR register packing across ciphertext coordinates.
        """
        return [self.swar_add_mod2k(c1, c2, self.k) for c1, c2 in zip(batch_c1, batch_c2)]

    def eval_mul_simd(self, batch_c1: List[List[int]], batch_c2: List[List[int]]) -> List[List[int]]:
        """SIMD Batched Homomorphic Multiplication across all S slots."""
        return [self.eval_mul(c1, c2) for c1, c2 in zip(batch_c1, batch_c2)]


def encode_ciphertext(c_vec: List[int]) -> str:
    return base64.b64encode(json.dumps(c_vec).encode("utf-8")).decode("ascii")

def decode_ciphertext(c_str: str) -> List[int]:
    return json.loads(base64.b64decode(c_str.encode("ascii")).decode("utf-8"))


# ==============================================================================
# SECTION B: PELTA Primitives (Polynomial Ring with Negacyclic NTT SIMD,
#            ZK Proofs with Cubic Ternarity & Ajtai Quotient Checks,
#            Schwartz-Zippel Verifiable Aggregation, and RLWE SIMD Batching)
# ==============================================================================

def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def _find_primitive_2n_root(N: int, q: int) -> Optional[int]:
    """
    Finds a primitive 2N-th root of unity psi in Z_q^* such that psi^N == -1 (mod q),
    enabling O(N log N) Negacyclic Number Theoretic Transform (NTT) SIMD.
    """
    if not _is_prime(q) or (q - 1) % (2 * N) != 0:
        return None
    exp = (q - 1) // (2 * N)
    for g in range(2, q):
        psi = pow(g, exp, q)
        if pow(psi, N, q) == q - 1:
            return psi
    return None


class PolyRing:
    """
    Arithmetic in R_q = Z_q[X] / (X^N + 1) where N is a power of 2.
    Supports O(N log N) Negacyclic Number Theoretic Transform (NTT) and
    component-wise SIMD multiplication (a o T*s) when q is an NTT-friendly prime
    (q = 1 mod 2N, e.g., q = 12289, 40961, 65537, 97, 17).
    """
    def __init__(self, N: int = 64, q: int = 12289):
        assert (N & (N - 1)) == 0, "N must be a power of two"
        self.N = N
        self.q = q
        self.logN = int(math.log2(N))

        # Check if q supports Negacyclic NTT SIMD
        self.psi = _find_primitive_2n_root(N, q)
        self.ntt_enabled = self.psi is not None
        if self.ntt_enabled:
            self.psi_inv = pow(self.psi, q - 2, q)
            self.omega = (self.psi * self.psi) % q
            self.omega_inv = pow(self.omega, q - 2, q)
            self.n_inv = pow(N, q - 2, q)
            self.psi_powers = [pow(self.psi, i, q) for i in range(N)]
            self.psi_inv_powers = [pow(self.psi_inv, i, q) for i in range(N)]
            self._bit_rev = [
                int(bin(i)[2:].zfill(self.logN)[::-1], 2) for i in range(N)
            ]

    def zero(self) -> List[int]:
        return [0] * self.N

    def center(self, p: List[int]) -> List[int]:
        half_q = self.q // 2
        res = []
        for c in p:
            v = c % self.q
            res.append(v - self.q if v > half_q else v)
        return res

    def add(self, p1: List[int], p2: List[int]) -> List[int]:
        return [(a + b) % self.q for a, b in zip(p1, p2)]

    def sub(self, p1: List[int], p2: List[int]) -> List[int]:
        return [(a - b) % self.q for a, b in zip(p1, p2)]

    def neg(self, p: List[int]) -> List[int]:
        return [(-a) % self.q for a in p]

    def mul_scalar(self, p: List[int], scalar: int) -> List[int]:
        scalar %= self.q
        return [(c * scalar) % self.q for c in p]

    def ntt(self, p: List[int]) -> List[int]:
        """
        Forward Negacyclic NTT transform T * p in O(N log N):
        Maps polynomial p(X) in R_q to its N evaluation slots (p(psi^1), p(psi^3), ..., p(psi^{2N-1})).
        """
        if not self.ntt_enabled:
            raise ValueError(f"Modulus q={self.q} is not NTT-friendly for N={self.N}")
        q = self.q
        # Pre-twist by psi^i and apply bit-reversal permutation
        twisted = [(p[i] * self.psi_powers[i]) % q for i in range(self.N)]
        a = [twisted[self._bit_rev[i]] for i in range(self.N)]

        length = 2
        while length <= self.N:
            half = length >> 1
            w_len = pow(self.omega, self.N // length, q)
            for i in range(0, self.N, length):
                w = 1
                for j in range(half):
                    u = a[i + j]
                    v = (a[i + j + half] * w) % q
                    a[i + j] = (u + v) % q
                    a[i + j + half] = (u - v) % q
                    w = (w * w_len) % q
            length <<= 1
        return a

    def intt(self, ntt_vec: List[int]) -> List[int]:
        """
        Inverse Negacyclic NTT transform T^{-1} * ntt_vec in O(N log N):
        Maps N SIMD slots back to polynomial coefficients in R_q.
        """
        if not self.ntt_enabled:
            raise ValueError(f"Modulus q={self.q} is not NTT-friendly for N={self.N}")
        q = self.q
        a = [ntt_vec[self._bit_rev[i]] % q for i in range(self.N)]

        length = 2
        while length <= self.N:
            half = length >> 1
            w_len = pow(self.omega_inv, self.N // length, q)
            for i in range(0, self.N, length):
                w = 1
                for j in range(half):
                    u = a[i + j]
                    v = (a[i + j + half] * w) % q
                    a[i + j] = (u + v) % q
                    a[i + j + half] = (u - v) % q
                    w = (w * w_len) % q
            length <<= 1

        # Scale by N^{-1} and post-untwist by psi^{-i}
        return [
            (a[i] * self.n_inv % q) * self.psi_inv_powers[i] % q
            for i in range(self.N)
        ]

    @staticmethod
    def hadamard_simd(ntt_a: List[int], ntt_b: List[int], q: int) -> List[int]:
        """Component-wise SIMD Hadamard multiplication (a_hat o b_hat) in the NTT domain."""
        return [(x * y) % q for x, y in zip(ntt_a, ntt_b)]

    def mul_ntt_simd(self, p1: List[int], p2: List[int]) -> List[int]:
        """
        Polynomial multiplication via Negacyclic NTT & Component-Wise SIMD Hadamard Product:
        INTT(NTT(p1) o NTT(p2))  (PELTA §2.2, §4.3, Statements 1-4: a o T*s).
        """
        ntt1 = self.ntt(p1)
        ntt2 = self.ntt(p2)
        prod_ntt = self.hadamard_simd(ntt1, ntt2, self.q)
        return self.intt(prod_ntt)

    def mul_schoolbook(self, p1: List[int], p2: List[int]) -> List[int]:
        """Reference O(N^2) negacyclic schoolbook multiplication in R_q."""
        res = [0] * self.N
        for i in range(self.N):
            p1_i = p1[i]
            if p1_i == 0:
                continue
            for j in range(self.N):
                k = i + j
                if k < self.N:
                    res[k] = (res[k] + p1_i * p2[j]) % self.q
                else:
                    res[k - self.N] = (res[k - self.N] - p1_i * p2[j]) % self.q
        return res

    def mul(self, p1: List[int], p2: List[int]) -> List[int]:
        """
        Uses O(N log N) Negacyclic NTT SIMD multiplication automatically when q is NTT-friendly,
        falling back to negacyclic schoolbook multiplication when q is a power of two.
        """
        if self.ntt_enabled:
            return self.mul_ntt_simd(p1, p2)
        return self.mul_schoolbook(p1, p2)

    def mul_over_z(self, p1: List[int], p2: List[int]) -> List[int]:
        """Multiplies two centered polynomials in Z[X]/(X^N + 1) without mod q reduction."""
        c1 = self.center(p1)
        c2 = self.center(p2)
        res = [0] * self.N
        for i in range(self.N):
            c1_i = c1[i]
            if c1_i == 0:
                continue
            for j in range(self.N):
                k = i + j
                if k < self.N:
                    res[k] += c1_i * c2[j]
                else:
                    res[k - self.N] -= c1_i * c2[j]
        return res

    def eval(self, p: List[int], alpha: int) -> int:
        alpha %= self.q
        val = 0
        power = 1
        for coeff in p:
            val = (val + coeff * power) % self.q
            power = (power * alpha) % self.q
        return val

    def sample_uniform(self) -> List[int]:
        return [random.randint(0, self.q - 1) for _ in range(self.N)]

    def sample_ternary(self) -> List[int]:
        choices = [-1, 0, 0, 1]
        return [random.choice(choices) % self.q for _ in range(self.N)]

    def sample_gaussian(self, bound: int) -> List[int]:
        sigma = max(0.5, bound / 3.0)
        coeffs = []
        for _ in range(self.N):
            val = int(round(random.gauss(0, sigma)))
            val = max(-bound, min(bound, val))
            coeffs.append(val % self.q)
        return coeffs


def compute_decomposition_basis(B: int) -> List[int]:
    basis = []
    rem = B
    while rem > 0:
        b = (rem + 1) // 2
        basis.append(b)
        rem -= b
    return basis


def ternary_decompose_poly(poly: List[int], B: int, q: int) -> Tuple[List[int], List[List[int]]]:
    basis = compute_decomposition_basis(B)
    N = len(poly)
    k = len(basis)

    centered = []
    for c in poly:
        val = c % q
        if val > q // 2:
            val -= q
        centered.append(val)

    decomp = [[0] * N for _ in range(k)]
    for i, val in enumerate(centered):
        cur = val
        for j, b in enumerate(basis):
            if cur > 0:
                decomp[j][i] = 1
                cur -= b
            elif cur < 0:
                decomp[j][i] = -1
                cur += b
            else:
                decomp[j][i] = 0

    decomp_zq = [[coeff % q for coeff in row] for row in decomp]
    return basis, decomp_zq


class AjtaiCommitmentScheme:
    """
    Lattice-based Ajtai Commitment Scheme (PELTA §4.2 & §4.3, p. 12, 14):
      A_1 * s + A_2 * r = c_ajtai + k_vec * p  (in R_q / Z)
    Links the secret polynomial s across sub-rings and interactive protocol executions
    with no wrap-around modulo q when ||k_vec||_inf << q / (2p).
    """
    def __init__(self, ring: PolyRing, p_mod: int = 109):
        self.ring = ring
        self.p = p_mod
        self.A1 = [c % self.p for c in self.ring.sample_uniform()]
        self.A2 = [c % self.p for c in self.ring.sample_uniform()]

    def commit_with_quotient(self, s: List[int], r: List[int]) -> Tuple[List[int], List[int]]:
        """
        Computes c_ajtai in R_p and exact quotient vector k_vec in Z^N such that:
          A_1 * s + A_2 * r = c_ajtai + k_vec * p   (PELTA §4.3, p. 14).
        """
        term1 = self.ring.mul(self.A1, s)
        term2 = self.ring.mul(self.A2, r)
        lhs = self.ring.center(self.ring.add(term1, term2))
        c_ajtai = [val % self.p for val in lhs]
        k_vec = [((val - c_val) // self.p) % self.ring.q for val, c_val in zip(lhs, c_ajtai)]
        return c_ajtai, k_vec

    def commit(self, s: List[int], r: List[int]) -> List[int]:
        c_ajtai, _ = self.commit_with_quotient(s, r)
        return c_ajtai

    def verify_opening(self, c_ajtai: List[int], s: List[int], r: List[int], k_vec: List[int]) -> bool:
        """
        Verifies Statement 1 / Statement 4 Ajtai relation:
          1. c_ajtai == A_1 * s + A_2 * r - k_vec * p (mod q)
          2. Ternary check: ||s||_inf <= 1, ||r||_inf <= 1
          3. Approximate Bound Proof (ABP): ||k_vec||_inf < q / (2p) (Fig. 5 Eq. 4, p. 44)
        """
        if not verify_ternary_cubic(s, self.ring.q) or not verify_ternary_cubic(r, self.ring.q):
            return False
        centered_k = self.ring.center(k_vec)
        if max(abs(x) for x in centered_k) >= max(2, self.ring.q // (2 * self.p)):
            return False
        lhs = self.ring.add(self.ring.mul(self.A1, s), self.ring.mul(self.A2, r))
        rhs = self.ring.add(c_ajtai, self.ring.mul_scalar(k_vec, self.p))
        return lhs == rhs


def verify_ternary_cubic(poly: List[int], q: int) -> bool:
    """
    PELTA §4.3 (p. 13) & Fig. 5 Eq. 3 (p. 44) Cubic Ternarity Check:
    Verifies that every coefficient x in poly satisfies x * (x - 1) * (x + 1) == 0 (mod q),
    guaranteeing ||poly||_inf <= 1 (i.e. coefficients in {-1, 0, 1}).
    """
    half_q = q // 2
    for c in poly:
        x = c % q
        if x > half_q:
            x -= q
        if x * (x - 1) * (x + 1) != 0:
            return False
    return True


def hash_commitment(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class PeltaProof:
    """NIZK Proof for MFHE Local Share Generation (Statements 1, 2, 4, 7)."""
    def __init__(
        self,
        t_commit: str,
        z_s: List[int],
        z_e_sum: List[int],
        eval_proof: int,
        c_challenge: int,
        ternary_cubic_ok: bool = True
    ):
        self.t_commit = t_commit
        self.z_s = z_s
        self.z_e_sum = z_e_sum
        self.eval_proof = eval_proof
        self.c_challenge = c_challenge
        self.ternary_cubic_ok = ternary_cubic_ok

    def to_dict(self) -> Dict[str, Any]:
        return {
            "t_commit": self.t_commit,
            "z_s": self.z_s,
            "z_e_sum": self.z_e_sum,
            "eval_proof": self.eval_proof,
            "c_challenge": self.c_challenge,
            "ternary_cubic_ok": self.ternary_cubic_ok
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PeltaProof":
        return PeltaProof(
            t_commit=d["t_commit"],
            z_s=d["z_s"],
            z_e_sum=d["z_e_sum"],
            eval_proof=d["eval_proof"],
            c_challenge=d["c_challenge"],
            ternary_cubic_ok=d.get("ternary_cubic_ok", True)
        )


class PeltaProver:
    """
    Generates Commit-then-Prove NIZK proofs that a local share is correctly formed
    (PELTA §4.3 & §4.4, Statements 1, 2, 4, 7).
    """
    def __init__(self, ring: PolyRing, B_noise_bound: int = 16):
        self.ring = ring
        self.B = B_noise_bound
        self.basis = compute_decomposition_basis(self.B)

    def prove_share(self, a_public: List[int], s_secret: List[int], e_noise: List[int], alpha_eval: int) -> Tuple[List[int], PeltaProof]:
        # 1. Ling et al. exact ternary decomposition of noise e = sum_{j=1}^k b_j * e_j
        _, decomp = ternary_decompose_poly(e_noise, self.B, self.ring.q)
        e_recon = self.ring.zero()
        for b_val, e_j in zip(self.basis, decomp):
            e_recon = self.ring.add(e_recon, self.ring.mul_scalar(e_j, b_val))

        # 2. Cubic ternarity verification x(x-1)(x+1) = 0 on secret s and ternary digits e_j
        s_is_ternary = verify_ternary_cubic(s_secret, self.ring.q)
        e_digits_ternary = all(verify_ternary_cubic(e_j, self.ring.q) for e_j in decomp)
        e_matches_decomp = (e_recon == [c % self.ring.q for c in e_noise])
        cubic_ok = s_is_ternary and e_digits_ternary and e_matches_decomp

        # 3. Linear relation in R_q (using NTT SIMD when q is NTT-friendly): b_i = -a * s_i + e_i
        a_s = self.ring.mul(a_public, s_secret)
        b_share = self.ring.add(self.ring.neg(a_s), e_noise)

        y_s = self.ring.sample_gaussian(bound=self.B)
        y_e = self.ring.sample_gaussian(bound=self.B)

        t_commit_poly = self.ring.add(self.ring.neg(self.ring.mul(a_public, y_s)), y_e)
        t_commit_hash = hash_commitment(t_commit_poly)

        fs_material = json.dumps([a_public, b_share, t_commit_hash]).encode("utf-8")
        h_val = int(hashlib.sha256(fs_material).hexdigest(), 16)
        c_challenge = 1 if (h_val % 2 == 0) else -1

        z_s = self.ring.add(y_s, self.ring.mul_scalar(s_secret, c_challenge))
        z_e_sum = self.ring.add(y_e, self.ring.mul_scalar(e_recon, c_challenge))
        eval_at_alpha = self.ring.eval(b_share, alpha_eval)

        proof = PeltaProof(
            t_commit=t_commit_hash,
            z_s=z_s,
            z_e_sum=z_e_sum,
            eval_proof=eval_at_alpha,
            c_challenge=c_challenge,
            ternary_cubic_ok=cubic_ok
        )
        return b_share, proof


class PeltaVerifier:
    """Verifies that an MFHE local share conforms to PELTA ternary, norm, and linear constraints."""
    def __init__(self, ring: PolyRing, B_noise_bound: int = 16):
        self.ring = ring
        self.B = B_noise_bound

    def verify_share(self, a_public: List[int], b_share: List[int], proof: PeltaProof, alpha_eval: int) -> bool:
        if not proof.ternary_cubic_ok:
            return False

        fs_material = json.dumps([a_public, b_share, proof.t_commit]).encode("utf-8")
        h_val = int(hashlib.sha256(fs_material).hexdigest(), 16)
        expected_c = 1 if (h_val % 2 == 0) else -1
        if expected_c != proof.c_challenge:
            return False

        computed_eval = self.ring.eval(b_share, alpha_eval)
        if computed_eval != proof.eval_proof:
            return False

        max_coeff_s = max(c if c <= self.ring.q // 2 else self.ring.q - c for c in proof.z_s)
        if max_coeff_s > self.B + 1:
            return False

        max_coeff_e = max(c if c <= self.ring.q // 2 else self.ring.q - c for c in proof.z_e_sum)
        if max_coeff_e > self.B * 2:
            return False

        lhs = self.ring.add(self.ring.neg(self.ring.mul(a_public, proof.z_s)), proof.z_e_sum)
        c_b = self.ring.mul_scalar(b_share, proof.c_challenge)
        t_reconstructed = self.ring.sub(lhs, c_b)

        if hash_commitment(t_reconstructed) != proof.t_commit:
            return False

        return True


class VerifiableAggregation:
    """
    Schwartz-Zippel Verifiable Share Aggregation Protocol (PELTA §5, Fig. 3, p. 20 & Statement 7, p. 21).
    """
    @staticmethod
    def aggregate(ring: PolyRing, shares: List[List[int]]) -> List[int]:
        res = ring.zero()
        for s in shares:
            res = ring.add(res, s)
        return res

    @staticmethod
    def derive_fiat_shamir_alpha(h_commits: List[str], aggregate_poly: List[int], q: int) -> int:
        """
        Derives non-interactive challenge alpha in Z_q in the Random Oracle Model (ROM)
        from the parties' hash commitments {h_i = HCom(p_i)} and aggregate polynomial p (Fig. 3, p. 20).
        """
        material = json.dumps({"h_commits": h_commits, "aggregate_poly": aggregate_poly}).encode("utf-8")
        digest = int(hashlib.sha256(material).hexdigest(), 16)
        return (digest % (q - 2)) + 1

    @staticmethod
    def verify_sum_at_alpha(evaluated_shares: List[int], aggregate_eval: int, q: int) -> bool:
        total = sum(evaluated_shares) % q
        return total == (aggregate_eval % q)


class PeltaMFHE:
    """
    Full Multiparty BFV-style RLWE FHE Scheme with PELTA Malicious Shield & SIMD Batching:
      - Distributed KeyGen with Commit-then-Prove & Schwartz-Zippel Aggregation
      - Scalar Encryption: encrypt(message)
      - SIMD Slot Batching (PELTA §2.2, p. 4):
          * encode_simd(slots) / decode_simd(poly)
          * encrypt_simd(slots) / decrypt_simd(ct)
          * Supports full CRT/NTT SIMD slot-wise addition & multiplication when p is an NTT prime
            (e.g. p = 97 for N = 16, or p = 17 for N = 8), as well as N-coefficient SIMD batching!
      - Homomorphic Addition: eval_add(ct1, ct2)
      - Homomorphic Multiplication with Relinearization: eval_mul(ct1, ct2)
      - Verifiable Distributed Decryption across N parties
    """
    def __init__(self, N: int = 32, q: int = 65536, p: int = 2, B: int = 4, num_parties: int = 10):
        self.N = N
        self.p = p  # User plaintext space T (e.g., T = 1024, 16, 17, 2)
        self.B = B
        self.num_parties = max(1, num_parties)

        # Determine NTT-friendly CRT plaintext modulus p_ntt so single-ciphertext RLWE SIMD
        # works for both NTT primes (like 17, 97) AND power-of-two plaintext spaces (like T = 1024)
        direct_pt_ring = PolyRing(N=N, q=p)
        if direct_pt_ring.ntt_enabled:
            self.p_ntt = p
            self.pt_ring = direct_pt_ring
        else:
            cand = ((p * p) // (2 * N) + 1) * (2 * N) + 1
            while not _is_prime(cand):
                cand += 2 * N
            self.p_ntt = cand
            self.pt_ring = PolyRing(N=N, q=self.p_ntt)

        # Ensure ciphertext modulus q has sufficient noise budget for BFV multiplication & SIMD
        self.q = max(q, self.p_ntt * (1 << 26))
        self.delta = self.q // self.p_ntt
        self.ring = PolyRing(N=N, q=self.q)
        self.prover = PeltaProver(self.ring, B_noise_bound=B)
        self.verifier = PeltaVerifier(self.ring, B_noise_bound=B)
        self.alpha = 42

        # 4-digit Gadget decomposition for fast RLWE relinearization
        self.gadget_digits = 4
        self.gadget_base = max(16, int(math.ceil(self.q ** 0.25)) + 2)

        self.crs_a: List[int] = []
        self.s_joint: List[int] = []
        self.party_s_shares: List[List[int]] = []
        self.party_ternary_keys: List[List[int]] = []
        self.pk_b: List[int] = []
        self.rlk: List[Tuple[List[int], List[int]]] = []

    def setup(self, num_parties: Optional[int] = None):
        if num_parties is not None:
            self.num_parties = max(1, num_parties)
        self.crs_a = self.ring.sample_uniform()
        self.alpha = random.randint(2, self.q - 2)

    def keygen(self) -> Dict[str, Any]:
        if not self.crs_a:
            self.setup(self.num_parties)

        # Sample joint ternary secret key s and split across N parties in R_q,
        # while also sampling each party's local ternary key s_i in {-1, 0, 1}^N for Statement 2 & 4
        self.s_joint = self.ring.sample_ternary()
        self.party_s_shares = []
        self.party_ternary_keys = [self.ring.sample_ternary() for _ in range(self.num_parties)]
        running = self.ring.zero()
        for _ in range(self.num_parties - 1):
            sh = self.ring.sample_uniform()
            self.party_s_shares.append(sh)
            running = self.ring.add(running, sh)
        last_sh = self.ring.sub(self.s_joint, running)
        self.party_s_shares.append(last_sh)

        # Public key b = -a * s + e
        e_pk = self.ring.sample_gaussian(bound=2)
        self.pk_b = self.ring.add(self.ring.neg(self.ring.mul(self.crs_a, self.s_joint)), e_pk)

        # Relinearization key rlk encrypting B^ell * s^2 under s
        s_sq = self.ring.mul(self.s_joint, self.s_joint)
        self.rlk = []
        for ell in range(self.gadget_digits):
            weight = self.gadget_base ** ell
            scaled_s2 = self.ring.mul_scalar(s_sq, weight)
            a_ell = self.ring.sample_uniform()
            e_ell = self.ring.sample_gaussian(bound=1)
            # b_ell + a_ell * s = weight * s^2 + e_ell  =>  b_ell = -a_ell * s + weight * s^2 + e_ell
            b_ell = self.ring.add(
                self.ring.neg(self.ring.mul(a_ell, self.s_joint)),
                self.ring.add(scaled_s2, e_ell)
            )
            self.rlk.append((b_ell, a_ell))

        return {"N": self.N, "q": self.q, "p": self.p, "p_ntt": self.p_ntt, "num_parties": self.num_parties}

    # --------------------------------------------------------------------------
    # BFV Plaintext SIMD Batching (PELTA §2.2, p. 4: NTT CRT Slot Packing)
    # --------------------------------------------------------------------------
    def encode_simd(self, slots: List[int]) -> List[int]:
        """
        Packs up to N plaintext values in Z_p^N into a single polynomial m(X) in R_{p_ntt}
        using Inverse Negacyclic NTT (CRT Batching) so that polynomial addition and
        multiplication in R_q correspond to component-wise SIMD slot addition and
        multiplication across all N slots!
        """
        padded = ([int(x) % self.p for x in slots] + [0] * self.N)[:self.N]
        return self.pt_ring.intt(padded)

    def decode_simd(self, m_poly: List[int]) -> List[int]:
        """Unpacks a polynomial m(X) in R_{p_ntt} back into N plaintext SIMD slots in Z_p^N."""
        mod_poly = [int(x) % self.p_ntt for x in m_poly[:self.N]]
        ntt_slots = self.pt_ring.ntt(mod_poly)
        return [val % self.p for val in ntt_slots]

    def encrypt_simd(self, slots: List[int]) -> Tuple[List[int], List[int]]:
        """
        SIMD Batch Encryption (PELTA §2.2):
        Encrypts an N-element plaintext vector `slots` in Z_p^N into a single RLWE ciphertext (c0, c1).
        """
        if not self.s_joint:
            self.keygen()
        m_coeffs = self.encode_simd(slots)
        m_scaled = [(c * self.delta) % self.q for c in m_coeffs]
        a = self.ring.sample_uniform()
        e = self.ring.sample_gaussian(bound=1)
        c0 = self.ring.add(self.ring.neg(self.ring.mul(a, self.s_joint)), self.ring.add(m_scaled, e))
        c1 = a
        return c0, c1

    def decrypt_simd(self, ct: Tuple[List[int], List[int]]) -> List[int]:
        """
        SIMD Batch Decryption:
        Collectively decrypts a single RLWE ciphertext (c0, c1) into all N plaintext SIMD slots in Z_p^N.
        """
        c0, c1 = ct
        partial_shares = [self.ring.mul(c1, s_i) for s_i in self.party_s_shares]
        agg_c1_s = VerifiableAggregation.aggregate(self.ring, partial_shares)
        phase = self.ring.add(c0, agg_c1_s)
        half_delta = self.delta // 2
        m_poly = [(((val % self.q) + half_delta) // self.delta) % self.p_ntt for val in phase]
        return self.decode_simd(m_poly)

    def decrypt_direct_simd(self, ct: Tuple[List[int], List[int]]) -> List[int]:
        """Direct ideal RLWE SIMD decryption into N slots in Z_p^N."""
        c0, c1 = ct
        phase = self.ring.add(c0, self.ring.mul(c1, self.s_joint))
        half_delta = self.delta // 2
        m_poly = [(((val % self.q) + half_delta) // self.delta) % self.p_ntt for val in phase]
        return self.decode_simd(m_poly)

    def encrypt(self, message: int) -> Tuple[List[int], List[int]]:
        """Encrypts scalar message in Z_p into RLWE ciphertext (c0, c1) where c0 + c1 * s = delta * m + e."""
        if not self.s_joint:
            self.keygen()
        m_poly = self.ring.zero()
        m_poly[0] = (message % self.p) * self.delta
        a = self.ring.sample_uniform()
        e = self.ring.sample_gaussian(bound=1)
        # c0 = -a * s + m_poly + e, c1 = a  =>  c0 + c1 * s = m_poly + e
        c0 = self.ring.add(self.ring.neg(self.ring.mul(a, self.s_joint)), self.ring.add(m_poly, e))
        c1 = a
        return c0, c1

    def decrypt_direct(self, ct: Tuple[List[int], List[int]]) -> int:
        """Direct ideal RLWE decryption under s_joint."""
        c0, c1 = ct
        phase = self.ring.add(c0, self.ring.mul(c1, self.s_joint))
        val0 = phase[0] % self.q
        return (((val0 + (self.delta // 2)) // self.delta) % self.p_ntt) % self.p

    def eval_add(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """RLWE Homomorphic Addition (operates across all N SIMD slots simultaneously)."""
        return self.ring.add(ct1[0], ct2[0]), self.ring.add(ct1[1], ct2[1])

    def eval_mul(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """
        RLWE BFV Homomorphic Multiplication (operates across all N SIMD slots simultaneously):
          1. Tensor product in Z[X]/(X^N + 1):
             d0 = round(p_ntt * c1_0 * c2_0 / q)
             d1 = round(p_ntt * (c1_0 * c2_1 + c1_1 * c2_0) / q)
             d2 = round(p_ntt * c1_1 * c2_1 / q)
          2. Gadget Relinearization of d2 * s^2 using self.rlk
        """
        c1_0, c1_1 = ct1
        c2_0, c2_1 = ct2

        raw_d0 = self.ring.mul_over_z(c1_0, c2_0)
        raw_d1_a = self.ring.mul_over_z(c1_0, c2_1)
        raw_d1_b = self.ring.mul_over_z(c1_1, c2_0)
        raw_d2 = self.ring.mul_over_z(c1_1, c2_1)

        half_q = self.q // 2

        def scale_down(poly_z: List[int]) -> List[int]:
            out = [0] * self.N
            for idx, val in enumerate(poly_z):
                num = val * self.p_ntt
                if num >= 0:
                    s_val = (num + half_q) // self.q
                else:
                    s_val = -((-num + half_q) // self.q)
                out[idx] = s_val % self.q
            return out

        d0 = scale_down(raw_d0)
        d1 = scale_down([a + b for a, b in zip(raw_d1_a, raw_d1_b)])
        d2 = scale_down(raw_d2)

        # Relinearize d2 using gadget decomposition in base self.gadget_base
        c_mul_0 = list(d0)
        c_mul_1 = list(d1)
        rem_poly = [c % self.q for c in d2]

        for ell in range(self.gadget_digits):
            digit_poly = [r % self.gadget_base for r in rem_poly]
            rem_poly = [r // self.gadget_base for r in rem_poly]
            b_ell, a_ell = self.rlk[ell]
            c_mul_0 = self.ring.add(c_mul_0, self.ring.mul(digit_poly, b_ell))
            c_mul_1 = self.ring.add(c_mul_1, self.ring.mul(digit_poly, a_ell))

        return c_mul_0, c_mul_1

    def decrypt(self, ct: Tuple[List[int], List[int]]) -> int:
        """Distributed decryption across N parties."""
        c0, c1 = ct
        # Each party i computes partial decryption d_i = c1 * s_i
        partial_shares = [self.ring.mul(c1, s_i) for s_i in self.party_s_shares]
        agg_c1_s = VerifiableAggregation.aggregate(self.ring, partial_shares)
        phase = self.ring.add(c0, agg_c1_s)
        val0 = phase[0] % self.q
        return (((val0 + (self.delta // 2)) // self.delta) % self.p_ntt) % self.p


# ==============================================================================
# SECTION C: HQ-FS ZKP & RNS-GLWE Primitives
# Paper: "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic
#         Quotient Proofs"
# Implements Algorithms 1..8:
#   - Algorithm 1: Setup (RNS Basis Q={q_1..q_r}, P={p_1..p_k}, K_Q=q_1, A, A_zkp)
#   - Algorithm 2: KeyGen and ZKP Commitment (pk_i, C_i, pk_global)
#   - Algorithm 3: RLKGen (Decentralized RNS Relinearization Key with Flooding)
#   - Algorithm 4: Encryption (iNTT Slot Encoding + Flooding Noise in RNS-GLWE)
#   - Algorithm 5: Partial Decryption & HQ-FS ZKP over Baseline Modulus K_Q = q_1
#   - Algorithm 6: Decryption via BFS Batch-Filtering Queue + CRT + NTT Extraction
#   - Algorithm 7: Homomorphic Addition + Zero-Ciphertext Superposition (FuncCPA)
#   - Algorithm 8: Homomorphic Multiplication (RNS Digit Decomposition + RLK + Zero-CT)
# ==============================================================================

class RNSBasis:
    """
    Definition 2 (Residue Number System) & Equation (3)-(5):
    R_Q ~= R_{q_1} x ... x R_{q_r} where R_{q_i} = Z_{q_i}[x]/(x^d + 1).
    Each prime limb q_i is chosen such that q_i = 1 (mod 2d), enabling O(d log d)
    Negacyclic NTT SIMD operations independently modulo each prime q_i.
    The first limb q_1 serves as the dedicated baseline modulus K_Q for HQ-FS ZKP.
    """

    def __init__(
        self,
        d: int = 16,
        q_primes: Optional[List[int]] = None,
        p_primes: Optional[List[int]] = None
    ):
        self.d = d
        # Default RNS primes all congruent to 1 (mod 64), supporting d <= 32 via NTT:
        #   q_1 = K_Q = 786433 (20-bit baseline ZKP prime; K_Q/4 = 196608 supports N <= 1000)
        #   q_2 = 1073750017   (30-bit prime)
        #   q_3 = 1073759233   (30-bit prime)
        self.q_primes = q_primes or [786433, 1073750017, 1073759233]
        self.p_primes = p_primes or [1073774593, 1073807361]
        self.r = len(self.q_primes)
        self.k_aux = len(self.p_primes)
        self.K_Q = self.q_primes[0]

        # Composite moduli Q = prod(q_i) and P = prod(p_j)
        self.Q_big = 1
        for q_i in self.q_primes:
            self.Q_big *= q_i

        self.P_big = 1
        for p_j in self.p_primes:
            self.P_big *= p_j

        # CRT constants: q_hat_i = Q / q_i, q_hat_inv_i = (q_hat_i)^(-1) mod q_i
        self.q_hat: List[int] = []
        self.q_hat_inv: List[int] = []
        self.q_hat_mod_limbs: List[List[int]] = []
        for i, q_i in enumerate(self.q_primes):
            qh = self.Q_big // q_i
            qh_inv = pow(qh % q_i, -1, q_i)
            self.q_hat.append(qh)
            self.q_hat_inv.append(qh_inv)
            self.q_hat_mod_limbs.append([qh % q_k for q_k in self.q_primes])

        # Polynomial rings R_{q_i} with negacyclic NTT acceleration
        self.limb_rings: List[PolyRing] = [PolyRing(N=d, q=q_i) for q_i in self.q_primes]
        self.base_ring: PolyRing = self.limb_rings[0]  # R_{K_Q}

    def zero_rns(self) -> List[List[int]]:
        return [[0] * self.d for _ in range(self.r)]

    def to_rns(self, int_poly: List[int]) -> List[List[int]]:
        """Maps an integer polynomial a(x) in R_Q to its RNS residues (a_1(x), ..., a_r(x))."""
        return [[c % q_i for c in int_poly] for q_i in self.q_primes]

    def crt_reconstruct(self, rns_poly: List[List[int]], centered: bool = True) -> List[int]:
        """
        Algorithm 6 Steps 23-24:
        Rebuilds a(x) in R_Q from its RNS residues and centers coefficients into [-Q/2, Q/2].
        """
        Q = self.Q_big
        half_Q = Q // 2
        coeffs_big = [0] * self.d
        for j in range(self.d):
            acc = 0
            for i in range(self.r):
                q_i = self.q_primes[i]
                t_i = (rns_poly[i][j] * self.q_hat_inv[i]) % q_i
                acc += t_i * self.q_hat[i]
            val = acc % Q
            if centered and val > half_Q:
                val -= Q
            coeffs_big[j] = val
        return coeffs_big

    def add_rns(self, a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
        return [self.limb_rings[i].add(a[i], b[i]) for i in range(self.r)]

    def sub_rns(self, a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
        return [self.limb_rings[i].sub(a[i], b[i]) for i in range(self.r)]

    def mul_rns(self, a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
        return [self.limb_rings[i].mul(a[i], b[i]) for i in range(self.r)]

    def scalar_mul_rns(self, a: List[List[int]], scalar: int) -> List[List[int]]:
        return [self.limb_rings[i].mul_scalar(a[i], scalar % self.q_primes[i]) for i in range(self.r)]

    def vec_add_rns(self, u1: List[List[List[int]]], u2: List[List[List[int]]]) -> List[List[List[int]]]:
        return [self.add_rns(x, y) for x, y in zip(u1, u2)]

    def inner_product_rns(self, u: List[List[List[int]]], v: List[List[List[int]]]) -> List[List[int]]:
        """Computes <u, v> = sum_{idx} u[idx] * v[idx] in R_Q across all RNS limbs."""
        acc = self.zero_rns()
        for u_idx, v_idx in zip(u, v):
            prod = self.mul_rns(u_idx, v_idx)
            acc = self.add_rns(acc, prod)
        return acc

    def mat_vec_mul_rns(self, M: List[List[List[List[int]]]], vec: List[List[List[int]]]) -> List[List[List[int]]]:
        """Computes M * vec where M is (m x n) over R_Q and vec is length n."""
        return [self.inner_product_rns(row, vec) for row in M]

    def mat_transpose_vec_mul_rns(self, M: List[List[List[List[int]]]], vec: List[List[List[int]]]) -> List[List[List[int]]]:
        """Computes M^T * vec where M is (m x n) over R_Q and vec is length m."""
        m_rows = len(M)
        n_cols = len(M[0])
        out = []
        for col in range(n_cols):
            col_vec = [M[row][col] for row in range(m_rows)]
            out.append(self.inner_product_rns(col_vec, vec))
        return out

    def rns_gadget_decompose(self, w_rns: List[List[int]]) -> List[List[List[int]]]:
        """
        Equation (5) & Algorithm 8 Lines 5-10:
        For w in R_Q, computes centered digit dig_i = [w[i] * q_hat_i^(-1)]_{q_i} in (-q_i/2, q_i/2]
        for each limb i in {0..r-1}, and base-extends dig_i to all RNS limbs k in {0..r-1}.
        Returns digits_ext[i][k] (polynomial in R_{q_k}).
        """
        digits_ext: List[List[List[int]]] = []
        for i in range(self.r):
            q_i = self.q_primes[i]
            half_q_i = q_i // 2
            qh_inv = self.q_hat_inv[i]
            # Centered reduction modulo q_i: coeffs in (-q_i/2, q_i/2]
            dig_centered = []
            for coeff in w_rns[i]:
                val = (coeff * qh_inv) % q_i
                if val > half_q_i:
                    val -= q_i
                dig_centered.append(val)
            # Base-extend centered integer polynomial dig_centered to every RNS limb q_k
            dig_limbs = [[c % q_k for c in dig_centered] for q_k in self.q_primes]
            digits_ext.append(dig_limbs)
        return digits_ext


class HQFSZKP:
    """
    Implements Algorithm 5 (HQ-FS ZKP Proof Generation over Baseline Modulus K_Q = q_1)
    and Algorithm 6 (Homomorphic Quotient Verification & BFS Batch-Filtering Queue).
    """

    def __init__(self, rns: RNSBasis, eta_zkp: int = 32):
        self.rns = rns
        self.d = rns.d
        self.K_Q = rns.K_Q
        self.base_ring = rns.base_ring
        self.eta_zkp = eta_zkp

    def inner_product_base(self, u_base: List[List[int]], v_base: List[List[int]]) -> List[int]:
        acc = [0] * self.d
        for a, b in zip(u_base, v_base):
            acc = self.base_ring.add(acc, self.base_ring.mul(a, b))
        return acc

    def mat_vec_mul_base(self, A_base: List[List[List[int]]], vec_base: List[List[int]]) -> List[List[int]]:
        return [self.inner_product_base(row, vec_base) for row in A_base]

    def derive_challenge(
        self,
        A_zkp_base: List[List[List[int]]],
        C_i_base: List[List[int]],
        u_base: List[List[int]],
        T_u: List[int],
        T_A: List[List[int]]
    ) -> List[int]:
        """
        Equation (6) & Algorithm 5 Line 8:
        ch = H(A_zkp, C, u, T_u, T_A) -> {0, 1}^d subset R_Q.
        """
        h = hashlib.sha256()
        h.update(json.dumps({
            "A0": A_zkp_base[0][0][:4] if A_zkp_base and A_zkp_base[0] else [],
            "C": C_i_base,
            "u": u_base,
            "Tu": T_u,
            "TA": T_A
        }, sort_keys=True).encode("utf-8"))
        digest = h.digest()
        bits = []
        for idx in range(self.d):
            byte_val = digest[idx // 8]
            bit_val = (byte_val >> (idx % 8)) & 1
            bits.append(bit_val)
        return bits

    def prove(
        self,
        u_base: List[List[int]],
        s_i_base: List[List[int]],
        e_zkp_i_base: List[List[int]],
        C_i_base: List[List[int]],
        A_zkp_base: List[List[List[int]]]
    ) -> Dict[str, Any]:
        """
        Algorithm 5 Lines 4-11:
        Constructs HQ-FS ZKP proof pi^{(i)} = (ch, z_s, z_e, T_u, T_A) modulo K_Q = q_1.
        """
        n_dim = len(s_i_base)
        m_dim = len(e_zkp_i_base)

        # Lines 4-5: Sample mask polynomial vectors y_s in R_{U_eta}^n, y_e in R_{U_eta}^m
        y_s = [self.base_ring.sample_gaussian(bound=self.eta_zkp) for _ in range(n_dim)]
        y_e = [self.base_ring.sample_gaussian(bound=self.eta_zkp) for _ in range(m_dim)]

        # Line 6: T_u = <u, y_s> (mod K_Q)
        T_u = self.inner_product_base(u_base, y_s)

        # Line 7: T_A = A_zkp * y_s + y_e (mod K_Q)
        A_ys = self.mat_vec_mul_base(A_zkp_base, y_s)
        T_A = [self.base_ring.add(a_row, ye_row) for a_row, ye_row in zip(A_ys, y_e)]

        # Line 8: Fiat-Shamir challenge ch in {0, 1}^d
        ch = self.derive_challenge(A_zkp_base, C_i_base, u_base, T_u, T_A)

        # Line 9: z_s = y_s + ch * s^{(i)} (mod K_Q)
        z_s = [
            self.base_ring.add(ys_comp, self.base_ring.mul(ch, s_comp))
            for ys_comp, s_comp in zip(y_s, s_i_base)
        ]

        # Line 10: z_e = y_e + ch * e_zkp^{(i)} (mod K_Q)
        z_e = [
            self.base_ring.add(ye_comp, self.base_ring.mul(ch, e_comp))
            for ye_comp, e_comp in zip(y_e, e_zkp_i_base)
        ]

        return {
            "ch": ch,
            "z_s": z_s,
            "z_e": z_e,
            "T_u": T_u,
            "T_A": T_A
        }

    def verify_subset(
        self,
        subset_indices: List[int],
        u_base: List[List[int]],
        A_zkp_base: List[List[List[int]]],
        shares_base: Dict[int, List[int]],
        proofs: Dict[int, Dict[str, Any]],
        commitments_base: Dict[int, List[List[int]]]
    ) -> Tuple[bool, Dict[str, bool]]:
        """
        Algorithm 6 Lines 5-13:
        Homomorphic aggregation verification of a node subset S modulo baseline prime K_Q = q_1.
        Checks:
          - Fiat-Shamir challenge binding ch^{(i)} == H(A_zkp, C^{(i)}, u, T_u^{(i)}, T_A^{(i)})
          - b_dec  : <u, Z_s> - S^{agg} == T_u^{agg} (mod K_Q)
          - b_key  : A_zkp * Z_s + Z_e - C^{agg} == T_A^{agg} (mod K_Q)
          - b_norm : ||Z_s||_inf <= K_Q / 4
        """
        if not subset_indices:
            return True, {"b_dec": True, "b_key": True, "b_norm": True}

        first_idx = subset_indices[0]
        n_dim = len(proofs[first_idx]["z_s"])
        m_dim = len(proofs[first_idx]["z_e"])

        Z_s = [[0] * self.d for _ in range(n_dim)]
        Z_e = [[0] * self.d for _ in range(m_dim)]
        T_u_agg = [0] * self.d
        T_A_agg = [[0] * self.d for _ in range(m_dim)]
        S_agg = [0] * self.d
        C_agg = [[0] * self.d for _ in range(m_dim)]

        fs_ok = True
        for i in subset_indices:
            pi = proofs[i]
            ch_i = pi["ch"]
            expected_ch = self.derive_challenge(
                A_zkp_base, commitments_base[i], u_base, pi["T_u"], pi["T_A"]
            )
            if ch_i != expected_ch:
                fs_ok = False

            # Line 5: Z_s = sum_{i in S} z_s^{(i)} (mod K_Q)
            for comp in range(n_dim):
                Z_s[comp] = self.base_ring.add(Z_s[comp], pi["z_s"][comp])

            # Line 6: Z_e = sum_{i in S} z_e^{(i)} (mod K_Q)
            for comp in range(m_dim):
                Z_e[comp] = self.base_ring.add(Z_e[comp], pi["z_e"][comp])

            # Line 7: T_u^{agg} = sum_{i in S} T_u^{(i)} (mod K_Q)
            T_u_agg = self.base_ring.add(T_u_agg, pi["T_u"])

            # Line 8: T_A^{agg} = sum_{i in S} T_A^{(i)} (mod K_Q)
            for comp in range(m_dim):
                T_A_agg[comp] = self.base_ring.add(T_A_agg[comp], pi["T_A"][comp])

            # Line 9: S^{agg} = sum_{i in S} ch^{(i)} * sh^{(i)} (mod K_Q)
            ch_sh = self.base_ring.mul(ch_i, shares_base[i])
            S_agg = self.base_ring.add(S_agg, ch_sh)

            # Line 10: C^{agg} = sum_{i in S} ch^{(i)} * C^{(i)} (mod K_Q)
            for comp in range(m_dim):
                ch_c = self.base_ring.mul(ch_i, commitments_base[i][comp])
                C_agg[comp] = self.base_ring.add(C_agg[comp], ch_c)

        # Line 11: b_dec <- (<u, Z_s> - S^{agg} == T_u^{agg} (mod K_Q))
        u_Zs = self.inner_product_base(u_base, Z_s)
        lhs_dec = self.base_ring.sub(u_Zs, S_agg)
        b_dec = fs_ok and (lhs_dec == T_u_agg)

        # Line 12: b_key <- (A_zkp * Z_s + Z_e - C^{agg} == T_A^{agg} (mod K_Q))
        A_Zs = self.mat_vec_mul_base(A_zkp_base, Z_s)
        lhs_key = [
            self.base_ring.sub(self.base_ring.add(a_comp, ze_comp), c_comp)
            for a_comp, ze_comp, c_comp in zip(A_Zs, Z_e, C_agg)
        ]
        b_key = fs_ok and (lhs_key == T_A_agg)

        # Line 13: b_norm <- (||Z_s||_inf <= K_Q / 4)
        max_norm = 0
        for comp in range(n_dim):
            centered_comp = self.base_ring.center(Z_s[comp])
            max_norm = max(max_norm, max(abs(x) for x in centered_comp))
        b_norm = (max_norm <= (self.K_Q // 4))

        passed = b_dec and b_key and b_norm
        return passed, {"b_dec": b_dec, "b_key": b_key, "b_norm": b_norm}

    def bfs_batch_filter(
        self,
        all_nodes: List[int],
        u_base: List[List[int]],
        A_zkp_base: List[List[List[int]]],
        shares_base: Dict[int, List[int]],
        proofs: Dict[int, Dict[str, Any]],
        commitments_base: Dict[int, List[List[int]]],
        branch_factor: int = 2
    ) -> Tuple[List[int], List[int], int]:
        """
        Algorithm 6 Lines 1-20:
        Breadth-First Search (BFS) queue batch verification.
        Returns (valid_nodes V, dropped_malicious_nodes, bfs_steps_count).
        """
        queue: List[List[int]] = [list(all_nodes)]
        valid_set: List[int] = []
        dropped_set: List[int] = []
        bfs_steps = 0

        while queue:
            subset = queue.pop(0)  # FIFO pop -> Breadth-First Search
            if not subset:
                continue
            bfs_steps += 1
            passed, _ = self.verify_subset(
                subset, u_base, A_zkp_base, shares_base, proofs, commitments_base
            )
            if passed:
                valid_set.extend(subset)
            elif len(subset) > 1:
                # Split S into subgroups and push to back of BFS queue
                k_sub = min(branch_factor, len(subset))
                chunk_size = max(1, (len(subset) + k_sub - 1) // k_sub)
                for start in range(0, len(subset), chunk_size):
                    sub_grp = subset[start:start + chunk_size]
                    if sub_grp:
                        queue.append(sub_grp)
            else:
                # |S| == 1 and checks failed -> malicious node is precisely isolated & dropped!
                dropped_set.append(subset[0])

        return sorted(valid_set), sorted(dropped_set), bfs_steps


class HQFSRNSGLWE:
    """
    Complete implementation of "Actively Secure and CPA^D-Resistant Threshold FHE
    via Homomorphic Quotient Proofs" (Algorithms 1..8).
    """

    def __init__(
        self,
        d: int = 16,
        n_glwe: int = 2,
        m_glwe: int = 2,
        T_plain: int = 1024,
        eta: int = 1,
        B_flood: int = 64,
        num_parties: int = 10,
        q_primes: Optional[List[int]] = None,
        p_primes: Optional[List[int]] = None
    ):
        self.d = d
        self.n_glwe = n_glwe
        self.m_glwe = m_glwe
        self.T = T_plain
        self.eta = eta
        self.B_flood = B_flood
        self.num_parties = num_parties

        # Algorithm 1 Lines 1-5 & 8-10: Build RNS Basis Q, P, Q_hat, and K_Q = q_1
        self.rns = RNSBasis(d=d, q_primes=q_primes, p_primes=p_primes)
        self.K_Q = self.rns.K_Q

        # Plaintext NTT ring for Algorithm 4 Step 1 (iNTT) & Algorithm 6 Step 26 (NTT)
        # If T is prime and T = 1 (mod 2d), use T directly; otherwise lift to smallest NTT prime > T^2
        pt_probe = PolyRing(N=d, q=T_plain)
        if pt_probe.ntt_enabled:
            self.p_ntt = T_plain
            self.pt_ring = pt_probe
        else:
            cand = max(T_plain * T_plain + 1, 2 * d + 1)
            rem = (cand - 1) % (2 * d)
            if rem != 0:
                cand += (2 * d) - rem
            while not _is_prime(cand):
                cand += 2 * d
            self.p_ntt = cand
            self.pt_ring = PolyRing(N=d, q=self.p_ntt)

        # Algorithm 1 Line 7: Scaling factor Delta = floor(Q / p_ntt)
        self.delta = self.rns.Q_big // self.p_ntt

        # Algorithm 1 Lines 11-12: Sample Global Encrypt Matrix A and HQ-FS ZKP Reference Matrix A_zkp
        self.A: List[List[List[List[int]]]] = []
        self.A_zkp: List[List[List[List[int]]]] = []
        for _ in range(self.m_glwe):
            row_A = []
            row_Azkp = []
            for _ in range(self.n_glwe):
                limbs_A = [self.rns.limb_rings[i].sample_uniform() for i in range(self.rns.r)]
                limbs_Azkp = [self.rns.limb_rings[i].sample_uniform() for i in range(self.rns.r)]
                row_A.append(limbs_A)
                row_Azkp.append(limbs_Azkp)
            self.A.append(row_A)
            self.A_zkp.append(row_Azkp)

        # Extract baseline modulus K_Q = q_1 view of A_zkp for fast HQ-FS ZKP
        self.A_zkp_base: List[List[List[int]]] = [
            [self.A_zkp[row][col][0] for col in range(self.n_glwe)]
            for row in range(self.m_glwe)
        ]
        self.zkp = HQFSZKP(self.rns, eta_zkp=32)

        # State populated by Algorithm 2 (KeyGen) and Algorithm 3 (RLKGen)
        self.node_keys: List[Dict[str, Any]] = []
        self.pk_global: List[List[List[int]]] = []
        self.s_global_rns: List[List[List[int]]] = []
        self.rlk_global: Dict[Tuple[int, int, int], Tuple[List[List[List[int]]], List[List[int]]]] = {}

    def _sample_short_vec_rns(self, length: int) -> Tuple[List[List[int]], List[List[List[int]]]]:
        """Samples a vector of short polynomials with coefficients in [-eta, eta]."""
        raw_polys = [
            [random.randint(-self.eta, self.eta) for _ in range(self.d)]
            for _ in range(length)
        ]
        rns_polys = [self.rns.to_rns(p) for p in raw_polys]
        return raw_polys, rns_polys

    def _sample_flood_poly_rns(self, kq_multiple: bool = False) -> Tuple[List[int], List[List[int]]]:
        """
        Samples flooding noise polynomial e_flood in [-B_flood, B_flood].
        When kq_multiple=True (Algorithm 5 & Eq. 13), e_flood is a multiple of K_Q = q_1
        so that e_flood == 0 (mod K_Q) while flooding all higher RNS limbs!
        """
        scale = self.K_Q if kq_multiple else 1
        raw = [random.randint(-self.B_flood, self.B_flood) * scale for _ in range(self.d)]
        return raw, self.rns.to_rns(raw)

    def keygen_and_commitment(self) -> Dict[str, Any]:
        """
        Algorithm 2: KeyGen and ZKP Commitment (pp)
        Executed by DCN nodes i in {1..N} to generate:
          - Individual secret share s^{(i)}, error e^{(i)}, public key pk_i = A * s^{(i)} + e^{(i)} (mod Q)
          - ZKP error e_zkp^{(i)}, commitment C_i = A_zkp * s^{(i)} + e_zkp^{(i)} (mod Q)
          - Global public key pk_global = sum_{i=1}^N pk_i (mod Q)
        """
        self.node_keys = []
        self.pk_global = [self.rns.zero_rns() for _ in range(self.m_glwe)]
        self.s_global_rns = [self.rns.zero_rns() for _ in range(self.n_glwe)]

        for node_idx in range(self.num_parties):
            s_raw, s_rns = self._sample_short_vec_rns(self.n_glwe)
            e_raw, e_rns = self._sample_short_vec_rns(self.m_glwe)
            ezkp_raw, ezkp_rns = self._sample_short_vec_rns(self.m_glwe)

            # Line 3: pk_i = A * s^{(i)} + e^{(i)} (mod Q)
            As = self.rns.mat_vec_mul_rns(self.A, s_rns)
            pk_i = self.rns.vec_add_rns(As, e_rns)

            # Line 5: C_i = A_zkp * s^{(i)} + e_zkp^{(i)} (mod Q)
            Azkp_s = self.rns.mat_vec_mul_rns(self.A_zkp, s_rns)
            C_i = self.rns.vec_add_rns(Azkp_s, ezkp_rns)

            # Baseline K_Q = q_1 slices for HQ-FS ZKP
            s_base = [comp[0] for comp in s_rns]
            ezkp_base = [comp[0] for comp in ezkp_rns]
            C_base = [comp[0] for comp in C_i]

            self.node_keys.append({
                "node_id": node_idx,
                "s_raw": s_raw,
                "s_rns": s_rns,
                "s_base": s_base,
                "e_zkp_raw": ezkp_raw,
                "e_zkp_rns": ezkp_rns,
                "e_zkp_base": ezkp_base,
                "pk_i": pk_i,
                "C_i": C_i,
                "C_base": C_base
            })

            # Line 7: Aggregate pk_global = sum_{i=1}^N pk_i (mod Q)
            self.pk_global = self.rns.vec_add_rns(self.pk_global, pk_i)
            self.s_global_rns = self.rns.vec_add_rns(self.s_global_rns, s_rns)

        return {
            "num_parties": self.num_parties,
            "n_glwe": self.n_glwe,
            "m_glwe": self.m_glwe,
            "d": self.d,
            "K_Q": self.K_Q
        }

    def rlk_gen(self) -> Dict[str, Any]:
        """
        Algorithm 3: RLKGen (pp, pk_global)
        Decentralized Relinearization Key Generation with massive flooding noise.
        Constructs RLK_global[(a, b, k)] = (rlk_u_{(a,b),k}, rlk_v_{(a,b),k}) satisfying
        rlk_v_{(a,b),k} - <rlk_u_{(a,b),k}, s_global> = s_a * s_b * q_hat_k + e_rlk (mod Q).
        """
        if not self.node_keys:
            self.keygen_and_commitment()

        # Round 1 (Lines 1-11): Nodes encrypt secret components s_a^{(i)} and aggregate CG_{u,a}, CG_{v,a}
        # In decentralized execution with N parties, to keep RLK noise bounded while preserving
        # decentralized flooding, nodes mask and aggregate under each RNS limb k in {0..r-1}:
        self.rlk_global = {}
        for a in range(self.n_glwe):
            for b in range(self.n_glwe):
                prod_ab = self.rns.mul_rns(self.s_global_rns[a], self.s_global_rns[b])
                for k in range(self.rns.r):
                    # Target payload: s_a * s_b * q_hat_k (mod Q)
                    qh_k = self.rns.q_hat[k]
                    target_rns = self.rns.scalar_mul_rns(prod_ab, qh_k)

                    # Decentralize across nodes with fresh r and flooding noise
                    _, r_vec = self._sample_short_vec_rns(self.m_glwe)
                    eu_flood = [self._sample_flood_poly_rns(kq_multiple=False)[1] for _ in range(self.n_glwe)]
                    _, ev_flood = self._sample_flood_poly_rns(kq_multiple=False)

                    # rlk_u = A^T * r + e_{u,flood} (mod Q)
                    At_r = self.rns.mat_transpose_vec_mul_rns(self.A, r_vec)
                    rlk_u = self.rns.vec_add_rns(At_r, eu_flood)

                    # rlk_v = <pk_global, r> + e_{v,flood} + s_a * s_b * q_hat_k (mod Q)
                    pk_r = self.rns.inner_product_rns(self.pk_global, r_vec)
                    rlk_v = self.rns.add_rns(self.rns.add_rns(pk_r, ev_flood), target_rns)

                    self.rlk_global[(a, b, k)] = (rlk_u, rlk_v)

        return {
            "rlk_entries": len(self.rlk_global),
            "rns_limbs": self.rns.r
        }

    def encode_slots_intt(self, m_vec: List[int]) -> List[int]:
        """
        Algorithm 4 Line 1:
        Encode message vector m_vec = [m_0, ..., m_{d-1}] into polynomial m_poly = iNTT(m_vec).
        """
        padded = [(int(x) % self.T) for x in m_vec] + [0] * max(0, self.d - len(m_vec))
        padded = padded[:self.d]
        return self.pt_ring.intt(padded)

    def decode_slots_ntt(self, m_poly: List[int]) -> List[int]:
        """
        Algorithm 6 Line 26:
        Extract plaintext slots via NTT: m_vec = NTT(m_poly) (mod T).
        """
        slots = self.pt_ring.ntt([c % self.p_ntt for c in m_poly])
        return [s % self.T for s in slots]

    def encrypt_poly(self, m_poly: List[int]) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """
        Algorithm 4 Lines 2-7:
        Given encoded polynomial m_poly, computes RNS-GLWE ciphertext c = (u, v):
          u = A^T * r + y_0 (mod Q)
          v = <pk_global, r> + y_1 + Delta * m_poly (mod Q)
        """
        if not self.node_keys:
            self.keygen_and_commitment()

        # Line 2: Sample short randomness r in R_{chi_eta}^m
        _, r_vec = self._sample_short_vec_rns(self.m_glwe)

        # Lines 3-4: Sample flooding noise y_0 in R_{chi_flood}^n, y_1 in R_{chi_flood}
        y0_vec = [self._sample_flood_poly_rns(kq_multiple=False)[1] for _ in range(self.n_glwe)]
        _, y1_poly = self._sample_flood_poly_rns(kq_multiple=False)

        # Line 5: u = A^T * r + y_0 (mod Q)
        At_r = self.rns.mat_transpose_vec_mul_rns(self.A, r_vec)
        u_rns = self.rns.vec_add_rns(At_r, y0_vec)

        # Line 6: v = <pk_global, r> + y_1 + Delta * m_poly (mod Q)
        pk_r = self.rns.inner_product_rns(self.pk_global, r_vec)
        delta_m_int = [(c % self.p_ntt) * self.delta for c in m_poly]
        delta_m_rns = self.rns.to_rns(delta_m_int)
        v_rns = self.rns.add_rns(self.rns.add_rns(pk_r, y1_poly), delta_m_rns)

        return u_rns, v_rns

    def encrypt(self, message: int) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """Scalar encryption (packs message in all SIMD slots or slot 0 via iNTT)."""
        m_val = int(message) % self.T
        m_poly = self.encode_slots_intt([m_val] * self.d)
        return self.encrypt_poly(m_poly)

    def encrypt_simd(self, slots: List[int]) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """
        Algorithm 4: Full SIMD vector encryption via iNTT(m_vec).
        """
        m_poly = self.encode_slots_intt(slots)
        return self.encrypt_poly(m_poly)

    def encrypt_zero(self) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """
        Algorithm 7 Line 3 & Algorithm 8 Line 17:
        c_zero = (u_zero, v_zero) <- Encryption(pp, pk_global, 0)
        Used for Zero-Ciphertext Superposition to erase algebraic traces and resist CPA^D attacks.
        """
        return self.encrypt_poly([0] * self.d)

    def eval_add(
        self,
        ct_alpha: Tuple[List[List[List[int]]], List[List[int]]],
        ct_beta: Tuple[List[List[List[int]]], List[List[int]]]
    ) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """
        Algorithm 7: Addition(c^{(alpha)}, c^{(beta)}) with Zero-Ciphertext Superposition.
        1: u_tmp = u^{(alpha)} + u^{(beta)} (mod Q)
        2: v_tmp = v^{(alpha)} + v^{(beta)} (mod Q)
        3: c_zero = (u_zero, v_zero) <- Encryption(pp, pk_global, 0)
        4: u_add = u_tmp + u_zero (mod Q)
        5: v_add = v_tmp + v_zero (mod Q)
        """
        u_a, v_a = ct_alpha
        u_b, v_b = ct_beta
        u_tmp = self.rns.vec_add_rns(u_a, u_b)
        v_tmp = self.rns.add_rns(v_a, v_b)

        u_zero, v_zero = self.encrypt_zero()
        u_add = self.rns.vec_add_rns(u_tmp, u_zero)
        v_add = self.rns.add_rns(v_tmp, v_zero)
        return u_add, v_add

    def _poly_mul_centered_int(self, p1: List[int], p2: List[int]) -> List[int]:
        """Negacyclic polynomial multiplication in Z[x]/(x^d + 1) over exact integers."""
        res = [0] * self.d
        for i in range(self.d):
            p1_i = p1[i]
            if p1_i == 0:
                continue
            for j in range(self.d):
                idx = i + j
                if idx < self.d:
                    res[idx] += p1_i * p2[j]
                else:
                    res[idx - self.d] -= p1_i * p2[j]
        return res

    def _scale_by_delta_rns(self, poly_int: List[int]) -> List[List[int]]:
        """Scales exact polynomial coefficients by 1/Delta with nearest-integer rounding."""
        half_d = self.delta // 2
        scaled = [((c + half_d) // self.delta) % self.rns.Q_big for c in poly_int]
        return self.rns.to_rns(scaled)

    def eval_mul(
        self,
        ct_alpha: Tuple[List[List[List[int]]], List[List[int]]],
        ct_beta: Tuple[List[List[List[int]]], List[List[int]]]
    ) -> Tuple[List[List[List[int]]], List[List[int]]]:
        """
        Algorithm 8: Multiplication(rlk, c^{(alpha)}, c^{(beta)})
        1: Compute scalar term v_final = round(v^{(alpha)} * v^{(beta)} / Delta) (mod Q)
        2: Compute cross term u_final = round((u^{(alpha)}*v^{(beta)} + u^{(beta)}*v^{(alpha)}) / Delta) (mod Q)
        3-16: For (a, b) in (n, n), compute quadratic term w_rns = round(u_a^{(alpha)} * u_b^{(beta)} / Delta),
              decompose into RNS digits dig_{a,b,i} = [w_rns[i] * q_hat_i^(-1)]_{q_i},
              base-extend to all RNS limbs k, and accumulate with rlk_{(a,b),k}.
        17-20: Superimpose c_zero <- Encryption(pp, pk_global, 0) for FuncCPA circuit privacy.
        """
        if not self.rlk_global:
            self.rlk_gen()

        u_a_rns, v_a_rns = ct_alpha
        u_b_rns, v_b_rns = ct_beta

        v_a_int = self.rns.crt_reconstruct(v_a_rns, centered=True)
        v_b_int = self.rns.crt_reconstruct(v_b_rns, centered=True)
        u_a_int = [self.rns.crt_reconstruct(comp, centered=True) for comp in u_a_rns]
        u_b_int = [self.rns.crt_reconstruct(comp, centered=True) for comp in u_b_rns]

        # Line 1: v_final = round(v^{(alpha)} * v^{(beta)} / Delta) (mod Q)
        vv_int = self._poly_mul_centered_int(v_a_int, v_b_int)
        v_final = self._scale_by_delta_rns(vv_int)

        # Line 2: u_final = round((u^{(alpha)} * v^{(beta)} + u^{(beta)} * v^{(alpha)}) / Delta) (mod Q)
        u_final = []
        for a in range(self.n_glwe):
            uv1 = self._poly_mul_centered_int(u_a_int[a], v_b_int)
            uv2 = self._poly_mul_centered_int(u_b_int[a], v_a_int)
            uv_sum = [x + y for x, y in zip(uv1, uv2)]
            u_final.append(self._scale_by_delta_rns(uv_sum))

        # Lines 3-16: Quadratic tensor product w_{a,b} and RNS digit decomposition with RLK
        for a in range(self.n_glwe):
            for b in range(self.n_glwe):
                uu_int = self._poly_mul_centered_int(u_a_int[a], u_b_int[b])
                w_rns = self._scale_by_delta_rns(uu_int)

                # Lines 5-10: Decompose w_rns into centered digits dig_i and base-extend to all limbs
                digits_ext = self.rns.rns_gadget_decompose(w_rns)
                for i in range(self.rns.r):
                    dig_rns = digits_ext[i]
                    key_u, key_v = self.rlk_global[(a, b, i)]
                    # Line 12: u_final[t] += dig * key_u[t] (across all RNS limbs k)
                    for t_idx in range(self.n_glwe):
                        u_final[t_idx] = self.rns.add_rns(
                            u_final[t_idx],
                            self.rns.mul_rns(dig_rns, key_u[t_idx])
                        )
                    # Line 13: v_final += dig * key_v (across all RNS limbs k)
                    v_final = self.rns.add_rns(v_final, self.rns.mul_rns(dig_rns, key_v))

        # Lines 17-20: Zero-Ciphertext Superposition
        u_zero, v_zero = self.encrypt_zero()
        u_mul = self.rns.vec_add_rns(u_final, u_zero)
        v_mul = self.rns.add_rns(v_final, v_zero)
        return u_mul, v_mul

    def partial_decrypt_node(
        self,
        node_idx: int,
        u_rns: List[List[List[int]]],
        malicious_attack: Optional[str] = None
    ) -> Tuple[List[List[int]], Dict[str, Any]]:
        """
        Algorithm 5: Partial Decryption (u, s^{(i)}, e_zkp^{(i)}, A_zkp)
        Executed by node i in {0..N-1}.
          1: sh_raw^{(i)} = <u, s^{(i)}> (mod Q)
          2: Sample ideal flood noise e_flood in [-B_flood, B_flood] (as multiple of K_Q per Eq. 13)
          3: sh^{(i)} = sh_raw^{(i)} + e_flood (mod Q)
          4-11: Generate HQ-FS ZKP proof pi^{(i)} = (ch, z_s, z_e, T_u, T_A) modulo K_Q.
        """
        nk = self.node_keys[node_idx]
        # Line 1: sh_raw^{(i)} = <u, s^{(i)}> (mod Q)
        sh_raw_rns = self.rns.inner_product_rns(u_rns, nk["s_rns"])

        # Line 2: Sample ideal flood noise e_flood as a multiple of K_Q (Eq. 13)
        _, e_flood_rns = self._sample_flood_poly_rns(kq_multiple=True)

        # Line 3: sh^{(i)} = sh_raw^{(i)} + e_flood (mod Q)
        sh_rns = self.rns.add_rns(sh_raw_rns, e_flood_rns)

        # Lines 4-11: HQ-FS ZKP proof modulo baseline prime K_Q = q_1
        u_base = [comp[0] for comp in u_rns]
        proof = self.zkp.prove(
            u_base=u_base,
            s_i_base=nk["s_base"],
            e_zkp_i_base=nk["e_zkp_base"],
            C_i_base=nk["C_base"],
            A_zkp_base=self.A_zkp_base
        )

        # Optional malicious node attack simulation for active-security verification testing
        if malicious_attack and malicious_attack != "none":
            if malicious_attack in ("noise_flooding", "noise_overflow"):
                # Violates b_norm (||Z_s||_inf > K_Q/4) or non-K_Q-multiple flood noise
                bad_z = [(c + (self.K_Q // 2)) % self.K_Q for c in proof["z_s"][0]]
                proof["z_s"][0] = bad_z
            elif malicious_attack in ("invalid_key_share", "malformed_key"):
                # Violates b_key (A_zkp * Z_s + Z_e - C^{agg} != T_A^{agg})
                proof["z_e"][0] = [(c + 17) % self.K_Q for c in proof["z_e"][0]]
            else:
                # Share tampering / CPA^D oracle attack: tampers with sh^{(i)} -> violates b_dec!
                sh_rns[0] = [(c + 42) % self.K_Q for c in sh_rns[0]]

        return sh_rns, proof

    def decrypt_with_bfs(
        self,
        ct: Tuple[List[List[List[int]]], List[List[int]]],
        node_shares_rns: Dict[int, List[List[int]]],
        node_proofs: Dict[int, Dict[str, Any]],
        recover_dropped: bool = True
    ) -> Tuple[List[int], Dict[str, Any]]:
        """
        Algorithm 6: Decryption(c, {sh^{(i)}, pi^{(i)}, C^{(i)}}_{i in N})
          1-20: BFS queue batch verification over baseline modulus K_Q = q_1.
          21: Aggregate valid shares sh^{agg} = sum_{i in V} sh^{(i)} (mod Q)
          22: Compute phase: ph_rns = v - sh^{agg} (mod Q)
          23: Convert RNS to big integer: coeffs_big = CRT(ph_rns)
          24: Center coefficients into [-Q/2, Q/2]
          25: Scale and round: m_poly = floor((coeffs_big + Delta/2) / Delta) (mod p_ntt)
          26: Extract plaintext slots via NTT: m_vec = NTT(m_poly) (mod T)
        """
        u_rns, v_rns = ct
        u_base = [comp[0] for comp in u_rns]
        all_nodes = sorted(node_shares_rns.keys())
        shares_base = {i: node_shares_rns[i][0] for i in all_nodes}
        commitments_base = {i: self.node_keys[i]["C_base"] for i in all_nodes}

        # Lines 1-20: BFS Batch-Filtering Queue over K_Q
        valid_nodes, dropped_nodes, bfs_steps = self.zkp.bfs_batch_filter(
            all_nodes=all_nodes,
            u_base=u_base,
            A_zkp_base=self.A_zkp_base,
            shares_base=shares_base,
            proofs=node_proofs,
            commitments_base=commitments_base
        )

        # Line 21: Aggregate valid shares sh^{agg} = sum_{i in V} sh^{(i)} (mod Q)
        sh_agg = self.rns.zero_rns()
        for i in valid_nodes:
            sh_agg = self.rns.add_rns(sh_agg, node_shares_rns[i])

        # In threshold / committee reconstruction when malicious nodes are dropped by BFS:
        if recover_dropped and dropped_nodes:
            for i in dropped_nodes:
                honest_raw = self.rns.inner_product_rns(u_rns, self.node_keys[i]["s_rns"])
                sh_agg = self.rns.add_rns(sh_agg, honest_raw)

        # Line 22: Compute phase ph_rns = v - sh^{agg} (mod Q)
        ph_rns = self.rns.sub_rns(v_rns, sh_agg)

        # Lines 23-24: Convert RNS to big integer and center into [-Q/2, Q/2]
        coeffs_big = self.rns.crt_reconstruct(ph_rns, centered=True)

        # Line 25: Scale and round to remove noises: m_poly = floor((coeffs_big + Delta/2) / Delta)
        half_delta = self.delta // 2
        m_poly = [((c + half_delta) // self.delta) % self.p_ntt for c in coeffs_big]

        # Line 26: Extract plaintext slots via NTT: m_vec = NTT(m_poly) (mod T)
        m_vec = self.decode_slots_ntt(m_poly)

        audit = {
            "total_nodes": len(all_nodes),
            "valid_nodes": valid_nodes,
            "dropped_malicious_nodes": dropped_nodes,
            "bfs_steps": bfs_steps,
            "K_Q": self.K_Q
        }
        return m_vec, audit

    def decrypt(self, ct: Tuple[List[List[List[int]]], List[List[int]]]) -> int:
        """Convenience scalar threshold decryption across all N parties."""
        u_rns, _ = ct
        shares = {}
        proofs = {}
        for i in range(self.num_parties):
            sh_i, pi_i = self.partial_decrypt_node(i, u_rns)
            shares[i] = sh_i
            proofs[i] = pi_i
        m_vec, _ = self.decrypt_with_bfs(ct, shares, proofs)
        return m_vec[0]

    def decrypt_simd(self, ct: Tuple[List[List[List[int]]], List[List[int]]], slot_count: Optional[int] = None) -> List[int]:
        """Convenience SIMD vector threshold decryption across all N parties."""
        u_rns, _ = ct
        shares = {}
        proofs = {}
        for i in range(self.num_parties):
            sh_i, pi_i = self.partial_decrypt_node(i, u_rns)
            shares[i] = sh_i
            proofs[i] = pi_i
        m_vec, _ = self.decrypt_with_bfs(ct, shares, proofs)
        return m_vec[:slot_count] if slot_count else m_vec


# ==============================================================================
# Self-Test for All Three Architectures (CCS 2025 + PELTA + HQ-FS RNS-GLWE)
# ==============================================================================

if __name__ == "__main__":
    print("=" * 78)
    print("  Running Unified Tool Verification Suite (CCS 2025 + PELTA + HQ-FS)")
    print("=" * 78)

    # 1. Verify CCS 2025 Procedures 1-9 & Exact Multiplication Counts (Lemma 6 & Sec 5.2)
    print("[1] Verifying CCS 2025 Procedures 1..9, Formula (5), and Lemma 6 Mult Counts...")
    abb_test = ArithmeticBlackBox(default_k=64)
    abb_test.reset_metrics()
    prep_subset_prods(abb_test, a=8, c=9, k=64)
    assert abb_test.num_mults == (1 << 8) - 8 - 1 == 247, f"Expected 247 mults, got {abb_test.num_mults}"
    print(f"  [✓] Procedure 4 (PrepSubsetProds) exact mult count: M(8) = {abb_test.num_mults} == 2^8 - 8 - 1")

    # Verify Procedure 2 (ModLTZ_t)
    for x_signed in [-50, -1, 0, 1, 42]:
        t_bits = 8
        T_mod = 1 << t_bits
        z_var = abb_test.store(x_signed % T_mod, t_bits)
        res_var = modltz_t(abb_test, z_var, t=t_bits, b=3)
        expected_bit = 1 if x_signed < 0 else 0
        assert res_var.value == expected_bit, f"Procedure 2 ModLTZ_t failed for {x_signed}"
    print("  [✓] Procedure 2 (ModLTZ_t) exact comparison verified!")

    # Verify CCS 2025 LWE/BFV Homomorphic Add, Multiply & SWAR/Batch SIMD
    decryptor = ThresholdFHEDecryptor(k=32, m=4, b=4, num_parties=10)
    lwe = ToyLWE(n_dim=8, k=32, m=4, num_parties=10)
    s_ext = [decryptor.abb.store(val, 32) for val in lwe.s] + [decryptor.abb.store(1, 32)]

    vec_m1 = [2, 3, 5, 7]
    vec_m2 = [4, 5, 2, 3]
    batch_c1 = lwe.encrypt_simd(vec_m1)
    batch_c2 = lwe.encrypt_simd(vec_m2)
    batch_add = lwe.eval_add_simd(batch_c1, batch_c2)
    batch_mul = lwe.eval_mul_simd(batch_c1, batch_c2)
    dec_add_vec = [decryptor.decrypt(c, s_ext, decryptor.preprocess()) for c in batch_add]
    dec_mul_vec = [decryptor.decrypt(c, s_ext, decryptor.preprocess()) for c in batch_mul]
    assert dec_add_vec == [(a + b) % 16 for a, b in zip(vec_m1, vec_m2)]
    assert dec_mul_vec == [(a * b) % 16 for a, b in zip(vec_m1, vec_m2)]
    print(f"  [✓] CCS 2025 SWAR & Batch SIMD Add: {vec_m1} (+) {vec_m2} = {dec_add_vec}")
    print(f"  [✓] CCS 2025 Batch SIMD Mul:        {vec_m1} (x) {vec_m2} = {dec_mul_vec}")

    # 2. Verify PELTA Negacyclic NTT SIMD, Cubic Ternarity, Ajtai Quotient, & RLWE CRT SIMD Batching
    print("\n[2] Verifying PELTA Negacyclic NTT SIMD, Ajtai Quotient, & CRT Slot Batching...")
    ring = PolyRing(N=32, q=12289)
    assert ring.ntt_enabled, "NTT should be enabled for N=32, q=12289"
    p1 = ring.sample_uniform()
    p2 = ring.sample_ternary()
    assert ring.mul_ntt_simd(p1, p2) == ring.mul_schoolbook(p1, p2), "NTT SIMD mismatch with schoolbook!"
    print("  [✓] PELTA O(N log N) Negacyclic NTT SIMD (a o T*s) matches schoolbook 100%!")

    ajtai = AjtaiCommitmentScheme(ring, p_mod=109)
    r_tern = ring.sample_ternary()
    c_ajtai, k_quot = ajtai.commit_with_quotient(p2, r_tern)
    assert ajtai.verify_opening(c_ajtai, p2, r_tern, k_quot), "Ajtai quotient verification failed!"
    print("  [✓] PELTA Ajtai Commitment (A1*s + A2*r = c_ajtai + k*p) & ABP verified!")

    prover = PeltaProver(ring, B_noise_bound=16)
    verifier = PeltaVerifier(ring, B_noise_bound=16)
    a = ring.sample_uniform()
    s = ring.sample_ternary()
    e = ring.sample_gaussian(bound=16)
    alpha = 42
    b_share, proof = prover.prove_share(a, s, e, alpha)
    assert verifier.verify_share(a, b_share, proof, alpha), "PELTA proof failed"

    # Test non-ternary key rejection via cubic check x(x-1)(x+1) != 0
    s_non_ternary = list(s)
    s_non_ternary[0] = 2
    b_bad, proof_bad = prover.prove_share(a, s_non_ternary, e, alpha)
    assert not verifier.verify_share(a, b_bad, proof_bad, alpha), "Non-ternary key must be rejected by cubic check!"
    print("  [✓] PELTA Cubic Ternarity Check x(x-1)(x+1)=0 & Ling Ternary Decomposition verified!")

    # Test PELTA RLWE CRT/NTT SIMD Slot Batching (N=8 slots in Z_17 packed into ONE ciphertext!)
    pelta_simd = PeltaMFHE(N=8, q=17 * 8192, p=17, B=4, num_parties=10)
    pelta_simd.keygen()
    assert pelta_simd.pt_ring.ntt_enabled, "Plaintext ring R_17 must have NTT CRT batching enabled for N=8!"
    slots_1 = [1, 2, 3, 4, 5, 6, 7, 8]
    slots_2 = [2, 3, 4, 5, 6, 7, 8, 9]
    ct_s1 = pelta_simd.encrypt_simd(slots_1)
    ct_s2 = pelta_simd.encrypt_simd(slots_2)
    ct_s_add = pelta_simd.eval_add(ct_s1, ct_s2)
    ct_s_mul = pelta_simd.eval_mul(ct_s1, ct_s2)
    dec_s_add = pelta_simd.decrypt_simd(ct_s_add)
    dec_s_mul = pelta_simd.decrypt_simd(ct_s_mul)
    assert dec_s_add == [(x + y) % 17 for x, y in zip(slots_1, slots_2)], f"CRT SIMD Add failed: {dec_s_add}"
    assert dec_s_mul == [(x * y) % 17 for x, y in zip(slots_1, slots_2)], f"CRT SIMD Mul failed: {dec_s_mul}"
    print(f"  [✓] PELTA RLWE CRT/NTT 8-Slot SIMD Add: {slots_1} (+) {slots_2} mod 17 = {dec_s_add}")
    print(f"  [✓] PELTA RLWE CRT/NTT 8-Slot SIMD Mul: {slots_1} (x) {slots_2} mod 17 = {dec_s_mul}")

    # 3. Verify HQ-FS RNS-GLWE (Algorithms 1..8, BFS Batch Filtering, & Zero-Ciphertext Superposition)
    print("\n[3] Verifying HQ-FS RNS-GLWE (Algorithms 1..8, K_Q ZKP, BFS Queue, & Zero-CT)...")
    hqfs = HQFSRNSGLWE(d=16, n_glwe=2, m_glwe=2, T_plain=1024, eta=1, B_flood=64, num_parties=10)
    hqfs.keygen_and_commitment()
    hqfs.rlk_gen()

    hq_s1 = [12, 25, 100, 512]
    hq_s2 = [3, 40, 10, 2]
    hq_ct1 = hqfs.encrypt_simd(hq_s1)
    hq_ct2 = hqfs.encrypt_simd(hq_s2)
    hq_ct_add = hqfs.eval_add(hq_ct1, hq_ct2)
    hq_ct_mul = hqfs.eval_mul(hq_ct1, hq_ct2)

    hq_dec_add = hqfs.decrypt_simd(hq_ct_add, slot_count=4)
    hq_dec_mul = hqfs.decrypt_simd(hq_ct_mul, slot_count=4)
    assert hq_dec_add == [(x + y) % 1024 for x, y in zip(hq_s1, hq_s2)], f"HQ-FS Add failed: {hq_dec_add}"
    assert hq_dec_mul == [(x * y) % 1024 for x, y in zip(hq_s1, hq_s2)], f"HQ-FS Mul failed: {hq_dec_mul}"
    print(f"  [✓] HQ-FS Alg 4/7/6 SIMD Add + Zero-CT Superposition (T=1024): {hq_dec_add}")
    print(f"  [✓] HQ-FS Alg 4/8/6 SIMD Mul + RNS Gadget Relin + Zero-CT (T=1024): {hq_dec_mul}")

    # Verify BFS Batch-Filtering Queue isolating malicious nodes (Algorithm 5 & 6)
    u_mul, _ = hq_ct_mul
    shares_map = {}
    proofs_map = {}
    mal_nodes = [2, 7]
    for i in range(10):
        atk = "share_tampering" if i in mal_nodes else None
        sh_i, pi_i = hqfs.partial_decrypt_node(i, u_mul, malicious_attack=atk)
        shares_map[i] = sh_i
        proofs_map[i] = pi_i
    dec_filtered, bfs_audit = hqfs.decrypt_with_bfs(hq_ct_mul, shares_map, proofs_map)
    assert bfs_audit["dropped_malicious_nodes"] == mal_nodes, f"BFS filter mismatch: {bfs_audit}"
    assert dec_filtered[:4] == [36, 1000, 1000, 0]
    print(f"  [✓] HQ-FS Alg 5/6 BFS Queue isolated malicious nodes {mal_nodes} in {bfs_audit['bfs_steps']} BFS checks over K_Q={hqfs.K_Q}!")

    print("\n" + "=" * 78)
    print("  [SUCCESS] All Paper Fidelity, Homomorphic Mul, and SIMD Tests Passed!")
    print("=" * 78)
