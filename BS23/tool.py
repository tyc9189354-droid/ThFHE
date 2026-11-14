#!/usr/bin/env python3
"""
BS23 Tool Module: Re-exports BS23ThFHE from root tool.py
Paper: "Simple Threshold (Fully Homomorphic) Encryption From LWE With Polynomial Modulus"
       (Katharina Boudgoust & Peter Scholl, ASIACRYPT 2023)
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from tool import BS23ThFHE

__all__ = ["BS23ThFHE"]
