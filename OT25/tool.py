#!/usr/bin/env python3
"""
OT25 Tool Module: Re-exports OT25ThFHE from root tool.py
Paper: "Low Communication Threshold FHE from Standard (Module-)LWE" (Asiacrypt 2025)
"""

import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from tool import OT25ThFHE

__all__ = ["OT25ThFHE"]
