# -*- coding: utf-8 -*-
"""pytest 全局配置。

把仓库根目录加入 sys.path，使 tests/test_run.py 可以直接 ``import run``——
无论以 ``pytest`` 还是 ``python -m pytest``、从哪个工作目录调用都成立
（此前依赖 ``python -m pytest`` 会把 CWD 加入 sys.path 的行为）。
"""
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


@pytest.fixture(autouse=True)
def _isolated_data_home(tmp_path_factory, monkeypatch):
    """每个测试都用独立的 XDG_DATA_HOME。

    hostdata / kernelver 默认读写 ~/.local/share/computesec：不隔离的话，测试会读到
    开发者自己的真实缓存（结果随机器而变），还会把测试数据写回去。需要特定目录的
    测试可以照常再 monkeypatch.setenv 覆盖。
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")))
