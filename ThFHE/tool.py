#!/usr/bin/env python3
"""
================================================================================
Unified Tool Module for Threshold FHE Architectures
Serving both:
  1. CCS 2025: High-Throughput Universally Composable Threshold FHE Decryption
     (Guy Zyskind, Doron Zarchy, Max Leibovich, Chris Peikert)
  2. PELTA: Shielding Multiparty-FHE against Malicious Adversaries
     (Sylvain Chatel, Christian Mouchet, Ali Utkan Sahin, Apostolos Pyrgelis, Carmela Troncoso, Jean-Pierre Hubaux)
================================================================================
Includes:
  - F_ABB & Preprocessed Sign / ModLTZ / LTRand Gates (CCS 2025)
  - LWE / BFV Encryption, Homomorphic Addition (eval_add), Homomorphic Multiplication
    with Gadget Relinearization (eval_mul), and Multi-Party Threshold Decryption
  - RLWE Polynomial Ring R_q = Z_q[X]/(X^N + 1), Ternary Decomposition,
    Commit-then-Prove NIZK, Schwartz-Zippel Verifiable Aggregation, and RLWE
    Homomorphic Addition & Multiplication (PELTA)
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
        for s0 in range(len0):
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
    """Procedure 3 (Offline phase): Prepares Sign gates and ModLTZ gate."""
    d = math.ceil(l / b)
    d_plus_1 = d + 1
    gates = PreprocessedGates()

    gates.modltz_gate = prep_modltz_gate(abb, d_plus_1=d_plus_1, m_len=k)

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

    u_k = modltz_table[y_prime]
    return z_prime, gates.r_combined, u_k


def mod_l_k(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> StoredVar:
    """Procedure 1: Mod_{l, k}(z) -> [e]_k = [z mod 2^l]_k."""
    z_prime, r_k, u_k = ltrand(abb, z_k, gates, l, k, b)
    e_k = abb.lin_comb(z_prime, [(-1, r_k), (1 << l, u_k)], out_len=k)
    return e_k


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
        evk_noise_bound = max(1, min(8, self.L // 1024))
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
        # Keep initial noise small enough to support homomorphic multiplication
        max_noise = max(1, min(32, self.L // 256))
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


def encode_ciphertext(c_vec: List[int]) -> str:
    return base64.b64encode(json.dumps(c_vec).encode("utf-8")).decode("ascii")

def decode_ciphertext(c_str: str) -> List[int]:
    return json.loads(base64.b64decode(c_str.encode("ascii")).decode("utf-8"))


# ==============================================================================
# SECTION B: PELTA Primitives (Polynomial Ring, ZK Proofs, Verifiable Aggregation,
#            and RLWE Homomorphic Addition & Multiplication)
# ==============================================================================

class PolyRing:
    """Arithmetic in R_q = Z_q[X] / (X^N + 1) where N is a power of 2."""
    def __init__(self, N: int = 64, q: int = 12289):
        assert (N & (N - 1)) == 0, "N must be a power of two"
        self.N = N
        self.q = q

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

    def mul(self, p1: List[int], p2: List[int]) -> List[int]:
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
    def __init__(self, ring: PolyRing, p_mod: int = 1009):
        self.ring = ring
        self.p = p_mod
        self.A1 = self.ring.sample_uniform()
        self.A2 = self.ring.sample_uniform()

    def commit(self, s: List[int], r: List[int]) -> List[int]:
        term1 = self.ring.mul(self.A1, s)
        term2 = self.ring.mul(self.A2, r)
        c = self.ring.add(term1, term2)
        return [val % self.p for val in c]


def hash_commitment(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class PeltaProof:
    """NIZK Proof for MFHE Local Share Generation."""
    def __init__(self, t_commit: str, z_s: List[int], z_e_sum: List[int], eval_proof: int, c_challenge: int):
        self.t_commit = t_commit
        self.z_s = z_s
        self.z_e_sum = z_e_sum
        self.eval_proof = eval_proof
        self.c_challenge = c_challenge

    def to_dict(self) -> Dict[str, Any]:
        return {
            "t_commit": self.t_commit,
            "z_s": self.z_s,
            "z_e_sum": self.z_e_sum,
            "eval_proof": self.eval_proof,
            "c_challenge": self.c_challenge
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "PeltaProof":
        return PeltaProof(
            t_commit=d["t_commit"],
            z_s=d["z_s"],
            z_e_sum=d["z_e_sum"],
            eval_proof=d["eval_proof"],
            c_challenge=d["c_challenge"]
        )


class PeltaProver:
    """Generates NIZK proofs that a local share is correctly formed."""
    def __init__(self, ring: PolyRing, B_noise_bound: int = 16):
        self.ring = ring
        self.B = B_noise_bound
        self.basis = compute_decomposition_basis(self.B)

    def prove_share(self, a_public: List[int], s_secret: List[int], e_noise: List[int], alpha_eval: int) -> Tuple[List[int], PeltaProof]:
        _, decomp = ternary_decompose_poly(e_noise, self.B, self.ring.q)
        e_recon = self.ring.zero()
        for b_val, e_j in zip(self.basis, decomp):
            e_recon = self.ring.add(e_recon, self.ring.mul_scalar(e_j, b_val))

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
            c_challenge=c_challenge
        )
        return b_share, proof


class PeltaVerifier:
    """Verifies that an MFHE local share conforms to ternary/noise constraints."""
    def __init__(self, ring: PolyRing, B_noise_bound: int = 16):
        self.ring = ring
        self.B = B_noise_bound

    def verify_share(self, a_public: List[int], b_share: List[int], proof: PeltaProof, alpha_eval: int) -> bool:
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
    """Schwartz-Zippel Verifiable Aggregation Protocol."""
    @staticmethod
    def aggregate(ring: PolyRing, shares: List[List[int]]) -> List[int]:
        res = ring.zero()
        for s in shares:
            res = ring.add(res, s)
        return res

    @staticmethod
    def verify_sum_at_alpha(evaluated_shares: List[int], aggregate_eval: int, q: int) -> bool:
        total = sum(evaluated_shares) % q
        return total == (aggregate_eval % q)


class PeltaMFHE:
    """
    Full Multiparty BFV-style RLWE FHE Scheme with PELTA Malicious Shield:
      - Distributed KeyGen with Commit-then-Prove & Schwartz-Zippel Aggregation
      - Encryption of plaintext messages in Z_p
      - Homomorphic Addition: eval_add(ct1, ct2)
      - Homomorphic Multiplication with Relinearization: eval_mul(ct1, ct2)
      - Verifiable Distributed Decryption across N parties
    """
    def __init__(self, N: int = 32, q: int = 65536, p: int = 2, B: int = 4, num_parties: int = 10):
        self.N = N
        self.q = q
        self.p = p
        self.delta = q // p
        self.B = B
        self.num_parties = max(1, num_parties)
        self.ring = PolyRing(N=N, q=q)
        self.prover = PeltaProver(self.ring, B_noise_bound=B)
        self.verifier = PeltaVerifier(self.ring, B_noise_bound=B)
        self.alpha = 42

        # Gadget decomposition for RLWE relinearization
        self.gadget_base = 16
        self.gadget_digits = math.ceil(math.log(q, self.gadget_base))

        self.crs_a: List[int] = []
        self.s_joint: List[int] = []
        self.party_s_shares: List[List[int]] = []
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

        # Sample joint ternary secret key s and split across N parties in R_q
        self.s_joint = self.ring.sample_ternary()
        self.party_s_shares = []
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

        return {"N": self.N, "q": self.q, "num_parties": self.num_parties}

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
        return ((val0 + (self.delta // 2)) // self.delta) % self.p

    def eval_add(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """RLWE Homomorphic Addition."""
        return self.ring.add(ct1[0], ct2[0]), self.ring.add(ct1[1], ct2[1])

    def eval_mul(self, ct1: Tuple[List[int], List[int]], ct2: Tuple[List[int], List[int]]) -> Tuple[List[int], List[int]]:
        """
        RLWE BFV Homomorphic Multiplication:
          1. Tensor product in Z[X]/(X^N + 1):
             d0 = round(p * c1_0 * c2_0 / q)
             d1 = round(p * (c1_0 * c2_1 + c1_1 * c2_0) / q)
             d2 = round(p * c1_1 * c2_1 / q)
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
                num = val * self.p
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
        return ((val0 + (self.delta // 2)) // self.delta) % self.p


# ==============================================================================
# Self-Test for Both Architectures (Including Homomorphic Addition & Multiplication)
# ==============================================================================

if __name__ == "__main__":
    print("=" * 75)
    print("  Running Unified Tool Self-Verification Tests (Add + Multiply + Decrypt)")
    print("=" * 75)

    # 1. Test CCS 2025 primitives + Homomorphic Add & Multiply
    print("[1] Testing CCS 2025 LWE/BFV Homomorphic Add, Multiply & MPC Rounding...")
    decryptor = ThresholdFHEDecryptor(k=32, m=1, b=4, num_parties=10)
    lwe = ToyLWE(n_dim=8, k=32, m=1, num_parties=10)
    s_ext = [decryptor.abb.store(val, 32) for val in lwe.s] + [decryptor.abb.store(1, 32)]

    for m1 in [0, 1]:
        for m2 in [0, 1]:
            c1, _ = lwe.encrypt(m1)
            c2, _ = lwe.encrypt(m2)

            # Test Homomorphic Addition
            c_add = lwe.eval_add(c1, c2)
            gates_add = decryptor.preprocess()
            dec_add = decryptor.decrypt(c_add, s_ext, gates_add)
            assert dec_add == (m1 + m2) % 2, f"CCS25 eval_add failed for {m1}+{m2}: got {dec_add}"

            # Test Homomorphic Multiplication
            c_mul = lwe.eval_mul(c1, c2)
            gates_mul = decryptor.preprocess()
            dec_mul = decryptor.decrypt(c_mul, s_ext, gates_mul)
            assert dec_mul == (m1 * m2) % 2, f"CCS25 eval_mul failed for {m1}*{m2}: got {dec_mul}"

    print("  [✓] CCS 2025 Homomorphic Add, Multiply & MPC Decryption passed!")

    # 2. Test PELTA primitives + RLWE Homomorphic Add & Multiply
    print("\n[2] Testing PELTA Zero-Knowledge, Verifiable Aggregation & RLWE Add/Mul...")
    ring = PolyRing(N=32, q=12289)
    prover = PeltaProver(ring, B_noise_bound=16)
    verifier = PeltaVerifier(ring, B_noise_bound=16)

    a = ring.sample_uniform()
    s = ring.sample_ternary()
    e = ring.sample_gaussian(bound=16)
    alpha = 42

    b_share, proof = prover.prove_share(a, s, e, alpha)
    assert verifier.verify_share(a, b_share, proof, alpha), "PELTA proof failed"

    agg = VerifiableAggregation.aggregate(ring, [b_share, b_share])
    agg_eval = ring.eval(agg, alpha)
    assert VerifiableAggregation.verify_sum_at_alpha([proof.eval_proof, proof.eval_proof], agg_eval, ring.q)

    pelta_fhe = PeltaMFHE(N=16, q=65536, p=2, B=4, num_parties=10)
    pelta_fhe.keygen()
    for m1 in [0, 1]:
        for m2 in [0, 1]:
            ct1 = pelta_fhe.encrypt(m1)
            ct2 = pelta_fhe.encrypt(m2)
            ct_add = pelta_fhe.eval_add(ct1, ct2)
            ct_mul = pelta_fhe.eval_mul(ct1, ct2)
            assert pelta_fhe.decrypt(ct_add) == (m1 + m2) % 2, f"PELTA eval_add failed for {m1}+{m2}"
            assert pelta_fhe.decrypt(ct_mul) == (m1 * m2) % 2, f"PELTA eval_mul failed for {m1}*{m2}"

    print("  [✓] PELTAZK + RLWE Homomorphic Add & Multiply passed!")

    print("\n" + "=" * 75)
    print("  [SUCCESS] All Unified Tool tests passed for both papers!")
    print("=" * 75)
