# -*- coding: utf-8 -*-
"""run.py 的 desktop entry 编码测试。"""

import pytest

import run as launcher


@pytest.mark.parametrize("arg,want", [
    ("/usr/bin/python3", "/usr/bin/python3"),
    ("/home/u/a b/run.py", '"/home/u/a b/run.py"'),
    ("/home/u/a&b/run.py", '"/home/u/a&b/run.py"'),
    ("/home/u/a$b/run.py", r'"/home/u/a\\$b/run.py"'),
    ("/home/u/a`b/run.py", r'"/home/u/a\\`b/run.py"'),
    ("/home/u/a\"b/run.py", r'"/home/u/a\\"b/run.py"'),
    ("/home/u/a\\b/run.py", r'"/home/u/a\\\\b/run.py"'),
    ("/home/u/%u/run.py", "/home/u/%%u/run.py"),
])
def test_quote_desktop_arg(arg, want):
    assert launcher._quote_desktop_arg(arg) == want


def test_quote_desktop_arg_escapes_newline():
    encoded = launcher._quote_desktop_arg("/home/u/a\nExec=evil")
    assert "\n" not in encoded
    assert r"\n" in encoded
