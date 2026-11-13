#!/usr/bin/env python3
"""
Ajax Tool Module: Re-exports AjaxThFHE from root tool.py
Paper: "Ajax: Fast Threshold Fully Homomorphic Encryption without Noise Flooding"
       (Hu et al., USENIX Security 2025)
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from tool import AjaxThFHE

__all__ = ["AjaxThFHE"]
