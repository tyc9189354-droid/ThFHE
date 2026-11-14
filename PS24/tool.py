#!/usr/bin/env python3
"""
PS24 Tool Module: Re-exports PS24ThFHE from root tool.py
Paper: "Low Communication Threshold Fully Homomorphic Encryption"
       (Alain Passelegue & Damien Stehle, ePrint 2024/1984)
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from tool import PS24ThFHE

__all__ = ["PS24ThFHE"]
