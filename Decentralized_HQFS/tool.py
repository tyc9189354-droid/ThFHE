import os
import sys
import importlib.util

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_root_tool_path = os.path.join(_parent_dir, "tool.py")

_spec = importlib.util.spec_from_file_location("root_tool", _root_tool_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

for _k, _v in _mod.__dict__.items():
    if not _k.startswith("__"):
        globals()[_k] = _v
