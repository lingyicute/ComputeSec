# -*- coding: utf-8 -*-
"""pytest 全局配置。

把仓库根目录加入 sys.path，使 tests/test_run.py 可以直接 ``import run``——
无论以 ``pytest`` 还是 ``python -m pytest``、从哪个工作目录调用都成立
（此前依赖 ``python -m pytest`` 会把 CWD 加入 sys.path 的行为）。
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
