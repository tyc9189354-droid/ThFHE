#!/usr/bin/env python3
"""
================================================================================
Tool Module: Reusable Functions and Classes for Threshold FHE Decryption
Based on CCS 2025: "High-Throughput Universally Composable Threshold FHE Decryption"
================================================================================

This module provides reusable primitives for:
  1. Arithmetic Black Box (F_ABB) simulation for ring Z_{2^k}
  2. Preprocessed Gates generation (Sign & ModLTZ gates via Fast Linear Transforms)
  3. Online MPC Rounding primitives (LTRand and Mod_{l, k})
  4. LWE cryptosystem and Threshold Decryptor abstractions
  5. Serialization utilities for network transfer
"""

import math
import random
import json
import base64
from typing import List, Dict, Tuple, Any, Optional

# ==============================================================================
# 1. Arithmetic Black Box (F_ABB) Abstraction
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
    Tracks operation metrics for benchmarking.
    """
    def __init__(self, default_k: int = 64):
        self.default_k = default_k
        self.storage: Dict[int, StoredVar] = {}
        # Metrics
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
        """Command: RandBit"""
        self.num_rand_bits += 1
        b = random.randint(0, 1)
        return self.store(b, bit_len or self.default_k)

    def lin_comb(self, const_c: int, pairs: List[Tuple[int, StoredVar]], out_len: Optional[int] = None) -> StoredVar:
        """Command: LinComb -> y = c + sum(c_j * x_j)"""
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
        """Command: Mult -> z = x * y"""
        self.num_mults += 1
        out_len = out_len or max(var1.bit_len, var2.bit_len)
        mod = 1 << out_len
        val = (var1.value * var2.value) % mod
        return self.store(val, out_len)

    def open(self, var: StoredVar, truncated_l: Optional[int] = None) -> int:
        """Command: Open (Truncated opening of low l bits)"""
        self.num_opens += 1
        l = truncated_l or var.bit_len
        self.opened_bits += l
        mod = 1 << l
        return var.value % mod


# ==============================================================================
# 2. Section 4: Preprocessing Procedures (Fast Transforms)
# ==============================================================================

def prep_subset_prods(abb: ArithmeticBlackBox, a: int, c: int, k: int) -> Tuple[StoredVar, List[StoredVar]]:
    """
    Procedure 4: PrepSubsetProds_{a, c}
    Prepares [r]_k for uniform random r in [2^a], along with vector [p_S]_c for all S subset of [a],
    where p_S = prod_{i in S} r_i.
    Uses recursive divide-and-conquer with 2^a - a - 1 multiplications.
    """
    if a == 1:
        r_bit = abb.rand_bit(k)
        p_empty = abb.store(1, c)
        p_single = abb.store(r_bit.value, c)
        return r_bit, [p_empty, p_single]

    a0 = (a + 1) // 2
    a1 = a - a0

    r0, p_s0 = prep_subset_prods(abb, a0, c, k)
    r1, p_s1 = prep_subset_prods(abb, a1, c, k)

    # [r]_k = [r0]_k + 2^{a0} * [r1]_k
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
    """
    Procedure 6: Linear Function SubsetProdsToSigns_b(p)
    Transforms subset-products into [Sign(x - r)]_{out_len} for all x in [2^b].
    """
    if b == 0:
        return [abb.store(0, out_len)]

    half_size = 1 << (b - 1)
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    s0 = subset_prods_to_signs(abb, p0, b - 1, out_len)
    s1 = subset_prods_to_signs(abb, p1, b - 1, out_len)

    p1_empty = p1[0]  # r_{b-1}
    p0_empty = p0[0]

    out_vec = [None] * (1 << b)
    for i in range(half_size):
        out_vec[i] = abb.lin_comb(0, [(-1, p1_empty), (1, s0[i]), (-1, s1[i])], out_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (1, s1[i])], out_len)

    return out_vec


def prep_sign_gate(abb: ArithmeticBlackBox, b: int, d_plus_1: int, k: int) -> Tuple[StoredVar, List[StoredVar]]:
    """Procedure 5: PrepSign_{b, d+1}"""
    r_k, p_vec = prep_subset_prods(abb, a=b, c=d_plus_1, k=k)
    signs_table = subset_prods_to_signs(abb, p_vec, b=b, out_len=d_plus_1)
    return r_k, signs_table


def subset_prods_to_carries(abb: ArithmeticBlackBox, p_vec: List[StoredVar], d: int, out_len: int) -> List[StoredVar]:
    """Procedure 9: Linear Function SubsetProdsToCarries_d(p)"""
    if d == 0:
        return [p_vec[0]]

    half_size = 1 << (d - 1)
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    c0 = subset_prods_to_carries(abb, p0, d - 1, out_len)
    c1 = subset_prods_to_carries(abb, p1, d - 1, out_len)

    p1_empty = p1[0]  # r_{d-1}
    p0_empty = p0[0]

    out_vec = [None] * (1 << d)
    for i in range(half_size):
        out_vec[i] = abb.sub(c0[i], c1[i], out_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (1, c1[i])], out_len)

    return out_vec


def subset_prods_to_modltz(abb: ArithmeticBlackBox, p_vec: List[StoredVar], d: int, m_len: int) -> List[StoredVar]:
    """Procedure 8: Linear Function SubsetProdsToModLTZ_{d+1}(p)"""
    half_size = 1 << d
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    c0 = subset_prods_to_carries(abb, p0, d, m_len)
    c1 = subset_prods_to_carries(abb, p1, d, m_len)

    p1_empty = p1[0]  # r_d
    p0_empty = p0[0]  # 1

    out_vec = [None] * (1 << (d + 1))
    for i in range(half_size):
        out_vec[i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (-1, c0[i]), (2, c1[i])], m_len)
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p1_empty), (1, c0[i]), (-2, c1[i])], m_len)

    return out_vec


def prep_modltz_gate(abb: ArithmeticBlackBox, d_plus_1: int, m_len: int) -> Tuple[StoredVar, List[StoredVar]]:
    """Procedure 7: PrepModLTZ_{d+1, m}"""
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

    # (1) ModLTZ gate for (d+1)-bit input, output mod 2^k
    gates.modltz_gate = prep_modltz_gate(abb, d_plus_1=d_plus_1, m_len=k)

    # (2) d Sign gates
    b_prime = l - (d - 1) * b
    r_parts = []
    for i in range(d):
        cur_b = b if i < d - 1 else b_prime
        r_i, table_i = prep_sign_gate(abb, b=cur_b, d_plus_1=d_plus_1, k=k)
        gates.sign_gates.append((r_i, table_i))
        r_parts.append(r_i)

    # (3) Compute [r]_k = sum_{i in [d]} [r_i]_k * B^i
    comb_pairs = []
    for i in range(d):
        weight = 1 << (i * b)
        comb_pairs.append((weight, r_parts[i]))
    gates.r_combined = abb.lin_comb(0, comb_pairs, out_len=k)

    return gates


# ==============================================================================
# 3. Section 3.3: Online Primitives (LTRand and Mod)
# ==============================================================================

def ltrand(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> Tuple[int, StoredVar, StoredVar]:
    """Procedure 3 (Online phase): LTRand_{l, k}"""
    d = math.ceil(l / b)
    d_plus_1 = d + 1

    # (1) Open [z]_l + [r]_l
    z_plus_r = abb.add(z_k, gates.r_combined, out_len=l)
    z_prime = abb.open(z_plus_r, truncated_l=l)

    # (2) Express z_prime in base B
    z_temp = z_prime
    z_digits = []
    for i in range(d):
        cur_b = b if i < d - 1 else (l - (d - 1) * b)
        digit = z_temp & ((1 << cur_b) - 1)
        z_digits.append(digit)
        z_temp >>= cur_b

    # (3) Look up [y_i]_{d+1} = [Sign(z'_i - r_i)] from preprocessed Sign gates
    y_shares = []
    for i in range(d):
        _, table_i = gates.sign_gates[i]
        digit_val = z_digits[i]
        y_shares.append(table_i[digit_val])

    # (4) Compute [y]_{d+1} = sum_{i in [d]} [y_i]_{d+1} * 2^i
    comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
    y_sum = abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

    # (5) Apply ModLTZ gate: Open [y]_{d+1} + [r_modltz]_{d+1}
    r_modltz, modltz_table = gates.modltz_gate
    y_masked = abb.add(y_sum, r_modltz, out_len=d_plus_1)
    y_prime = abb.open(y_masked, truncated_l=d_plus_1)

    u_k = modltz_table[y_prime]
    return z_prime, gates.r_combined, u_k


def mod_l_k(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> StoredVar:
    """Procedure 1: Mod_{l, k}(z) -> [e]_k = [z mod 2^l]_k"""
    z_prime, r_k, u_k = ltrand(abb, z_k, gates, l, k, b)
    e_k = abb.lin_comb(z_prime, [(-1, r_k), (1 << l, u_k)], out_len=k)
    return e_k


# ==============================================================================
# 4. High-Level Decryptor and Toy LWE Scheme
# ==============================================================================

class ThresholdFHEDecryptor:
    """Realizes Protocol Pi_Decrypt using F_ABB and the MPC rounding technique."""
    def __init__(self, k: int = 64, m: int = 1, b: Optional[int] = None):
        self.k = k
        self.m = m
        self.l = k - m
        self.L = 1 << self.l
        self.q = 1 << k
        self.p = 1 << m
        self.b = b or max(1, int(round(math.sqrt(self.l))))
        self.abb = ArithmeticBlackBox(default_k=k)

    def preprocess(self) -> PreprocessedGates:
        return prep_ltrand(self.abb, l=self.l, k=self.k, b=self.b)

    def decrypt(self, ciphertext_c: List[int], secret_key_shares: List[StoredVar], gates: PreprocessedGates) -> int:
        # Step 1: [z]_k = <c, s> + 2^{l-1}
        pairs = [(c_val, s_var) for c_val, s_var in zip(ciphertext_c, secret_key_shares)]
        shift = 1 << (self.l - 1)
        z_k = self.abb.lin_comb(shift, pairs, out_len=self.k)

        # Step 2: Noise extraction [e]_k = [z mod L]_k
        e_k = mod_l_k(self.abb, z_k, gates, l=self.l, k=self.k, b=self.b)

        # Step 3: [z]_k - [e]_k = [L * mu]_k, then Open
        mu_scaled = self.abb.sub(z_k, e_k, out_len=self.k)
        mu_prime = self.abb.open(mu_scaled, truncated_l=self.k)

        # Step 4: mu = mu' / L in Z_p
        return (mu_prime // self.L) % self.p


class ToyLWE:
    """Basic LWE cryptosystem over Z_{2^k} for testing and demonstration."""
    def __init__(self, n_dim: int = 16, k: int = 64, m: int = 1):
        self.n = n_dim
        self.k = k
        self.m = m
        self.q = 1 << k
        self.p = 1 << m
        self.l = k - m
        self.L = 1 << self.l
        self.s = [random.randint(0, 1) for _ in range(self.n)]

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        a = [random.randint(0, self.q - 1) for _ in range(self.n)]
        inner_prod = sum(a[i] * self.s[i] for i in range(self.n)) % self.q
        max_noise = self.L // 8
        e = random.randint(-max_noise, max_noise)

        b = (inner_prod + self.L * message + e) % self.q
        c_ext = [(-a_i) % self.q for a_i in a] + [b]
        return c_ext, e


# ==============================================================================
# 5. Serialization Utilities
# ==============================================================================

def encode_ciphertext(c_vec: List[int]) -> str:
    """Encodes list of integers into base64 JSON string."""
    return base64.b64encode(json.dumps(c_vec).encode("utf-8")).decode("ascii")

def decode_ciphertext(c_str: str) -> List[int]:
    """Decodes base64 JSON string into list of integers."""
    return json.loads(base64.b64decode(c_str.encode("ascii")).decode("utf-8"))


if __name__ == "__main__":
    print("[*] Running Tool self-verification tests...")
    # Fast test
    decryptor = ThresholdFHEDecryptor(k=16, m=1, b=4)
    lwe = ToyLWE(n_dim=8, k=16, m=1)
    s_ext = [decryptor.abb.store(val, 16) for val in lwe.s] + [decryptor.abb.store(1, 16)]
    gates = decryptor.preprocess()

    for test_msg in [0, 1]:
        c_ext, _ = lwe.encrypt(test_msg)
        recovered = decryptor.decrypt(c_ext, s_ext, gates)
        print(f"  Test message: {test_msg} -> Decrypted: {recovered} | Correct: {recovered == test_msg}")
        assert recovered == test_msg, f"Mismatch for {test_msg}"
        gates = decryptor.preprocess()

    print("[✓] All Tool primitive functions and classes verified successfully!")
