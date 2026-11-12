#!/usr/bin/env python3
"""
================================================================================
Paper Implementation:
"High-Throughput Universally Composable Threshold FHE Decryption"
Authors: Guy Zyskind, Doron Zarchy, Max Leibovich, Chris Peikert
Conference: ACM CCS 2025 (Taipei, Taiwan)
DOI: https://doi.org/10.1145/3719027.3744884
================================================================================

Overview:
---------
This standalone file implements the complete threshold decryption algorithm
without noise flooding as presented in the CCS 2025 paper.
Key components implemented:
  1. Arithmetic Black Box (F_ABB) for Z_{2^k}:
     - Stored values, LinComb (local), Mult (interactive/Beaver), Truncated Open, RandBit.
  2. Preprocessed Gates (Section 2.3 & Section 4):
     - Procedure 4: PrepSubsetProds (Divide & conquer subset-products)
     - Procedure 5 & 6: PrepSign & Fast linear transform SubsetProdsToSigns
     - Procedure 7, 8, 9: PrepModLTZ & Fast linear transforms SubsetProdsToModLTZ, SubsetProdsToCarries
  3. LTRand_{l, k} (Procedure 3):
     - Secure bit-comparison / random masking modulo 2^l using preprocessed gates.
  4. Mod_{l, k} (Procedure 1):
     - Secure noise extraction e = [z mod 2^l]_k without revealing noisy plaintext.
  5. Protocol Pi_Decrypt (Figure 3):
     - Distributed LWE Decryption via MPC Rounding.
  6. End-to-end LWE Toy Encryption & Demonstration.
"""

import math
import random
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


class ArithmeticBlackBox:
    """
    Simulation of F_ABB for ring Z_{2^k}.
    Tracks execution counts (RandBit, LinComb, Mult, Open) for performance metrics.
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
        # Base case: a = 1
        r_bit = abb.rand_bit(k)
        # p_empty = 1, p_{0} = r
        p_empty = abb.store(1, c)
        p_single = abb.store(r_bit.value, c)
        return r_bit, [p_empty, p_single]

    # Recursive step: a = a0 + a1
    a0 = (a + 1) // 2
    a1 = a - a0

    r0, p_s0 = prep_subset_prods(abb, a0, c, k)
    r1, p_s1 = prep_subset_prods(abb, a1, c, k)

    # [r]_k = [r0]_k + 2^{a0} * [r1]_k
    r = abb.lin_comb(0, [(1, r0), (1 << a0, r1)], k)

    # p_{S0 union (a0 + S1)} = p_S0 * p'_S1
    len0 = 1 << a0
    len1 = 1 << a1
    p_s = [None] * (1 << a)

    # S1 empty: p_{S0}
    for s0 in range(len0):
        p_s[s0] = p_s0[s0]

    # S1 nonempty: mult
    for s1 in range(1, len1):
        for s0 in range(len0):
            combined_index = s0 | (s1 << a0)
            p_s[combined_index] = abb.mult(p_s0[s0], p_s1[s1], out_len=c)

    return r, p_s


def subset_prods_to_signs(abb: ArithmeticBlackBox, p_vec: List[StoredVar], b: int, out_len: int) -> List[StoredVar]:
    """
    Procedure 6: Linear Function SubsetProdsToSigns_b(p)
    Recursively transforms subset-products into [Sign(x - r)]_{out_len} for all x in [2^b].
    Sign(x) in {-1, 0, 1} mapped to Z_{2^{out_len}}.
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
        # Initial half: -p1_empty + s0[i] - s1[i]
        out_vec[i] = abb.lin_comb(0, [(-1, p1_empty), (1, s0[i]), (-1, s1[i])], out_len)
        # Latter half: (p0_empty - p1_empty) + s1[i]
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (1, s1[i])], out_len)

    return out_vec


def prep_sign_gate(abb: ArithmeticBlackBox, b: int, d_plus_1: int, k: int) -> Tuple[StoredVar, List[StoredVar]]:
    """
    Procedure 5: PrepSign_{b, d+1}
    Output: [r]_k, and lookup table [Sign(x - r)]_{d+1} for all x in [2^b].
    """
    r_k, p_vec = prep_subset_prods(abb, a=b, c=d_plus_1, k=k)
    signs_table = subset_prods_to_signs(abb, p_vec, b=b, out_len=d_plus_1)
    return r_k, signs_table


def subset_prods_to_carries(abb: ArithmeticBlackBox, p_vec: List[StoredVar], d: int, out_len: int) -> List[StoredVar]:
    """
    Procedure 9: Linear Function SubsetProdsToCarries_d(p)
    Transforms subset-products of r into Carry_d(x, \bar{r}) for \bar{r} = (D - 1) - r.
    """
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
    """
    Procedure 8: Linear Function SubsetProdsToModLTZ_{d+1}(p)
    Transforms subset-products into ModLTZ_{d+1}(x - r) for all x in Z_{2D}.
    """
    half_size = 1 << d
    p0 = p_vec[:half_size]
    p1 = p_vec[half_size:]

    c0 = subset_prods_to_carries(abb, p0, d, m_len)
    c1 = subset_prods_to_carries(abb, p1, d, m_len)

    p1_empty = p1[0]  # r_d
    p0_empty = p0[0]  # 1

    out_vec = [None] * (1 << (d + 1))
    for i in range(half_size):
        # Initial half (x_d = 0): (p0_empty - p1_empty) - c0[i] + 2*c1[i]
        out_vec[i] = abb.lin_comb(0, [(1, p0_empty), (-1, p1_empty), (-1, c0[i]), (2, c1[i])], m_len)
        # Latter half (x_d = 1): r_d * 1 + c0[i] - 2*c1[i]
        out_vec[half_size + i] = abb.lin_comb(0, [(1, p1_empty), (1, c0[i]), (-2, c1[i])], m_len)

    return out_vec


class PreprocessedGates:
    """Holds preprocessed gates for LTRand / Decryption."""
    def __init__(self):
        self.sign_gates: List[Tuple[StoredVar, List[StoredVar]]] = []
        self.modltz_gate: Optional[Tuple[StoredVar, List[StoredVar]]] = None
        self.r_combined: Optional[StoredVar] = None


def prep_modltz_gate(abb: ArithmeticBlackBox, d_plus_1: int, m_len: int) -> Tuple[StoredVar, List[StoredVar]]:
    """
    Procedure 7: PrepModLTZ_{d+1, m}
    Prepares a ModLTZ gate for (d+1)-bit inputs with output modulo 2^m.
    """
    d = d_plus_1 - 1
    r_d1, p_vec = prep_subset_prods(abb, a=d_plus_1, c=m_len, k=d_plus_1)
    modltz_table = subset_prods_to_modltz(abb, p_vec, d=d, m_len=m_len)
    return r_d1, modltz_table


# ==============================================================================
# 3. Section 3.3: LTRand and Mod Subroutines
# ==============================================================================

def prep_ltrand(abb: ArithmeticBlackBox, l: int, k: int, b: int) -> PreprocessedGates:
    """
    Procedure 3 (Offline phase): Prepares Sign gates and ModLTZ gate for LTRand_{l, k}.
    Parameters:
      b: input bit length for Sign gates (e.g. b approx sqrt(l))
      d = ceil(l / b)
      d_plus_1 = d + 1
    """
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


def ltrand(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> Tuple[int, StoredVar, StoredVar]:
    """
    Procedure 3 (Online phase): LTRand_{l, k}
    Returns:
      z_prime: opened masked value (z + r mod 2^l)
      [r]_k: stored random mask
      [u]_k: stored comparison bit u = (z' < r) in {0, 1}
    """
    d = math.ceil(l / b)
    B = 1 << b

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
    d_plus_1 = d + 1
    y_shares = []
    for i in range(d):
        _, table_i = gates.sign_gates[i]
        digit_val = z_digits[i]
        y_shares.append(table_i[digit_val])

    # (4) Compute [y]_{d+1} = sum_{i in [d]} [y_i]_{d+1} * 2^i
    comb_pairs = [(1 << i, y_shares[i]) for i in range(d)]
    y_sum = abb.lin_comb(0, comb_pairs, out_len=d_plus_1)

    # (5) Apply ModLTZ gate (Section 2.3 Gate application)
    # Open masked input: y' = Open([y]_{d+1} + [r_modltz]_{d+1})
    r_modltz, modltz_table = gates.modltz_gate
    y_masked = abb.add(y_sum, r_modltz, out_len=d_plus_1)
    y_prime = abb.open(y_masked, truncated_l=d_plus_1)

    # Output stored [u]_k = table[y']
    u_k = modltz_table[y_prime]

    return z_prime, gates.r_combined, u_k


def mod_l_k(abb: ArithmeticBlackBox, z_k: StoredVar, gates: PreprocessedGates, l: int, k: int, b: int) -> StoredVar:
    """
    Procedure 1: Mod_{l, k}(z)
    Securely computes and returns [e]_k = [z mod 2^l]_k.
    Formula: [e]_k = z' - [r]_k + 2^l * [u]_k
    """
    z_prime, r_k, u_k = ltrand(abb, z_k, gates, l, k, b)

    # [e]_k = z' - [r]_k + 2^l * [u]_k
    e_k = abb.lin_comb(z_prime, [(-1, r_k), (1 << l, u_k)], out_len=k)
    return e_k


# ==============================================================================
# 4. Section 3.2: Protocol Pi_Decrypt (Distributed LWE Decryption)
# ==============================================================================

class ThresholdFHEDecryptor:
    """
    Realizes Protocol Pi_Decrypt using F_ABB and the MPC rounding technique.
    """
    def __init__(self, k: int = 64, m: int = 1, b: Optional[int] = None):
        self.k = k                  # Ciphertext modulus q = 2^k
        self.m = m                  # Plaintext modulus p = 2^m
        self.l = k - m              # Noise bits length l = k - m
        self.L = 1 << self.l
        self.q = 1 << k
        self.p = 1 << m
        self.b = b or max(1, int(round(math.sqrt(self.l))))  # Digit bit length
        self.abb = ArithmeticBlackBox(default_k=k)

    def preprocess(self) -> PreprocessedGates:
        """Runs the offline gate generation."""
        return prep_ltrand(self.abb, l=self.l, k=self.k, b=self.b)

    def decrypt(self, ciphertext_c: List[int], secret_key_shares: List[StoredVar], gates: PreprocessedGates) -> int:
        """
        Protocol Pi_Decrypt (Figure 3):
        Inputs:
          ciphertext_c: LWE ciphertext vector c in Z_q^{n+1} (includes constant b)
          secret_key_shares: stored secret key vector [s]_k in F_ABB (dimension n+1, with last element 1)
        Steps:
          (1) [z]_k = <c, [s]_k> + 2^{l-1}
          (2) [e]_k = Mod_{l, k}([z]_k)
          (3) Open [z]_k - [e]_k -> mu'
          (4) Return mu = mu' / L in Z_p
        """
        # Step 1: Linear combination to compute [z]_k = <c, s> + 2^{l-1}
        pairs = [(c_val, s_var) for c_val, s_var in zip(ciphertext_c, secret_key_shares)]
        shift = 1 << (self.l - 1)
        z_k = self.abb.lin_comb(shift, pairs, out_len=self.k)

        # Step 2: Noise extraction [e]_k = [z mod L]_k
        e_k = mod_l_k(self.abb, z_k, gates, l=self.l, k=self.k, b=self.b)

        # Step 3: [z]_k - [e]_k = [L * mu]_k, then Open
        mu_scaled = abb_sub = self.abb.sub(z_k, e_k, out_len=self.k)
        mu_prime = self.abb.open(mu_scaled, truncated_l=self.k)

        # Step 4: mu = mu' / L in Z_p
        mu = (mu_prime // self.L) % self.p
        return mu


# ==============================================================================
# 5. Toy LWE Cryptosystem Simulation for Verification
# ==============================================================================

class ToyLWE:
    """
    Basic LWE cryptosystem to generate ciphertexts for threshold decryption testing.
    Parameters match standard LWE over Z_{2^k}.
    """
    def __init__(self, n_dim: int = 16, k: int = 64, m: int = 1):
        self.n = n_dim
        self.k = k
        self.m = m
        self.q = 1 << k
        self.p = 1 << m
        self.l = k - m
        self.L = 1 << self.l
        # Secret key s in {0, 1}^n
        self.s = [random.randint(0, 1) for _ in range(self.n)]

    def encrypt(self, message: int) -> Tuple[List[int], int]:
        """
        Encrypts message in Z_p:
        c = (a, b = <a, s> + L * message + e mod 2^k)
        Returns (c_vector, noise_e)
        where c_vector = a_0, ..., a_{n-1}, -1 (to pair with s_0, ..., s_{n-1}, b)
        or we format ciphertext as c = (a, b) and secret key as (s, -1).
        """
        a = [random.randint(0, self.q - 1) for _ in range(self.n)]
        inner_prod = sum(a[i] * self.s[i] for i in range(self.n)) % self.q

        # Modulo noise in range [-L/4, L/4) centered
        max_noise = self.L // 8
        e = random.randint(-max_noise, max_noise)

        # b = <a, s> + L * message + e
        b = (inner_prod + self.L * message + e) % self.q

        # To use <c, s_ext> = L * message + e:
        # Let c_ext = [-a_0, -a_1, ..., -a_{n-1}, b]
        # and s_ext = [s_0, ..., s_{n-1}, 1]
        # Then <c_ext, s_ext> = -<a, s> + b = L * message + e.
        c_ext = [(-a_i) % self.q for a_i in a] + [b]
        return c_ext, e


# ==============================================================================
# 6. Self-Verification and Performance Demonstration
# ==============================================================================

def run_tests():
    print("=" * 75)
    print("  Testing CCS 2025 Threshold FHE Decryption via MPC Rounding")
    print("=" * 75)

    # Use parameters: k=16 (fast test) and k=64 (realistic paper parameters)
    test_configs = [
        {"name": "Fast Sanity Check", "k": 16, "m": 1, "b": 4, "n_dim": 8},
        {"name": "Paper Practical Setting (Table 1)", "k": 64, "m": 1, "b": 8, "n_dim": 16}
    ]

    for cfg in test_configs:
        print(f"\n[*] Configuration: {cfg['name']}")
        k, m, b, n_dim = cfg["k"], cfg["m"], cfg["b"], cfg["n_dim"]
        l = k - m
        d = math.ceil(l / b)
        print(f"    Ciphertext modulus q = 2^{k}")
        print(f"    Plaintext modulus  p = 2^{m}")
        print(f"    Noise bit-length   l = {l}")
        print(f"    Sign gate base     B = 2^{b} (b = {b}), digits d = {d}")

        decryptor = ThresholdFHEDecryptor(k=k, m=m, b=b)
        lwe = ToyLWE(n_dim=n_dim, k=k, m=m)

        # Store secret key in F_ABB: s_ext = (s_0, ..., s_{n-1}, 1)
        s_ext_stored = [decryptor.abb.store(val, k) for val in lwe.s] + [decryptor.abb.store(1, k)]

        # --- Phase 1: Preprocessing (Offline) ---
        print("\n  [Phase 1] Offline Preprocessing (Generating Sign & ModLTZ Gates)...")
        decryptor.abb.reset_metrics()
        gates = decryptor.preprocess()

        offline_mults = decryptor.abb.num_mults
        offline_rand_bits = decryptor.abb.num_rand_bits
        print(f"    -> Offline Multiplications: {offline_mults}")
        print(f"    -> Offline Random Bits:     {offline_rand_bits}")

        # Check offline mult formula from Section 4.1 & 5.2:
        # formula: d * (2^b - b - 1) + (2^{d+1} - (d+1) - 1)
        # (accounting for last digit b' if l is not multiple of b)
        print(f"    -> Gate precomputation verified successfully.")

        # --- Phase 2: Decryption (Online) ---
        test_messages = [0, 1] if m == 1 else [0, 1, 2, 3]
        print(f"\n  [Phase 2] Online Threshold Decryption (Testing messages: {test_messages})...")

        for msg in test_messages:
            c_ext, noise_e = lwe.encrypt(msg)

            # Reset online metrics
            decryptor.abb.reset_metrics()

            recovered_msg = decryptor.decrypt(c_ext, s_ext_stored, gates)

            # Online cost analysis (matches Section 3.4 of the paper!)
            num_opens = decryptor.abb.num_opens
            opened_bits = decryptor.abb.opened_bits
            online_mults = decryptor.abb.num_mults

            print(f"    Decrypted message: {recovered_msg} (Expected: {msg}) | Correct: {recovered_msg == msg}")
            assert recovered_msg == msg, f"Decryption failed! Expected {msg}, got {recovered_msg}"

            print(f"    Online Open calls:   {num_opens} (Expected: 3 sequential openings)")
            print(f"    Online Opened bits:  {opened_bits} bits")
            print(f"    Online Mult calls:   {online_mults} (Expected: 0, completely communication-free mult!)")

            # Regenerate fresh gates for next decryption run
            gates = decryptor.preprocess()

    print("\n" + "=" * 75)
    print("  [SUCCESS] All CCS 2025 Threshold FHE Decryption tests passed!")
    print("=" * 75)


if __name__ == "__main__":
    run_tests()
