#!/usr/bin/env python3
"""
================================================================================
HQ-FS: Tool Module (Unified Bridge to Root `tool.py`)
Paper: "Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic
        Quotient Proofs"
================================================================================
Provides all RNS-GLWE, HQ-FS ZKP (modulo baseline prime K_Q = q_1), Breadth-First
Search (BFS) batch-filtering queue, and Zero-Ciphertext Superposition primitives
integrated in the root `tool.py`.
================================================================================
"""

import os
import sys
import importlib.util

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
ROOT_TOOL_PATH = os.path.join(PARENT_DIR, "tool.py")

if "root_thfhe_tool" not in sys.modules:
    _spec = importlib.util.spec_from_file_location("root_thfhe_tool", ROOT_TOOL_PATH)
    _root_tool = importlib.util.module_from_spec(_spec)
    sys.modules["root_thfhe_tool"] = _root_tool
    _spec.loader.exec_module(_root_tool)
else:
    _root_tool = sys.modules["root_thfhe_tool"]

PolyRing = _root_tool.PolyRing
RNSBasis = _root_tool.RNSBasis
HQFSZKP = _root_tool.HQFSZKP
HQFSRNSGLWE = _root_tool.HQFSRNSGLWE
hash_commitment = _root_tool.hash_commitment

__all__ = [
    "PolyRing",
    "RNSBasis",
    "HQFSZKP",
    "HQFSRNSGLWE",
    "hash_commitment"
]

if __name__ == "__main__":
    print("=" * 78)
    print("  HQ-FS Tool Self-Test (Algorithms 1..8, RNS-GLWE, BFS Queue, Zero-CT)")
    print("=" * 78)
    hqfs = HQFSRNSGLWE(d=16, n_glwe=2, m_glwe=2, T_plain=1024, eta=1, B_flood=64, num_parties=10)
    hqfs.keygen_and_commitment()
    hqfs.rlk_gen()

    s1 = [12, 25, 100, 512]
    s2 = [3, 40, 10, 2]
    ct1 = hqfs.encrypt_simd(s1)
    ct2 = hqfs.encrypt_simd(s2)
    ct_add = hqfs.eval_add(ct1, ct2)
    ct_mul = hqfs.eval_mul(ct1, ct2)

    dec_add = hqfs.decrypt_simd(ct_add, slot_count=4)
    dec_mul = hqfs.decrypt_simd(ct_mul, slot_count=4)
    assert dec_add == [15, 65, 110, 514], f"Add mismatch: {dec_add}"
    assert dec_mul == [36, 1000, 1000, 0], f"Mul mismatch: {dec_mul}"
    print(f"  [✓] Algorithm 4/7/6 SIMD Add + Zero-Ciphertext Superposition: {dec_add}")
    print(f"  [✓] Algorithm 4/8/6 SIMD Mul + RNS Gadget Relin + Zero-CT:    {dec_mul}")
    print("=" * 78)
