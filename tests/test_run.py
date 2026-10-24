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


def test_data_home_respects_absolute_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert launcher._data_home() == str(tmp_path / "xdg")


def test_data_home_ignores_relative_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert launcher._data_home() == str(tmp_path / ".local" / "share")


# ---------------------------------------------------------------------------
# install_desktop：装/卸 .desktop 与图标
# ---------------------------------------------------------------------------
def _prepare(tmp_path, monkeypatch):
    """把 XDG_DATA_HOME 指到临时目录，并屏蔽掉系统里的 update-desktop-database。"""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(launcher.shutil, "which", lambda name: None)   # 不真的去刷新缓存
    return tmp_path / "xdg"


def test_install_desktop_then_uninstall(tmp_path, monkeypatch):
    data_home = _prepare(tmp_path, monkeypatch)
    launcher.install_desktop()

    desktop = data_home / "applications" / (launcher.APP_ID + ".desktop")
    icon = data_home / "icons" / "hicolor" / "scalable" / "apps" / (launcher.APP_ID + ".svg")
    assert desktop.exists() and icon.exists()

    content = desktop.read_text(encoding="utf-8")
    assert content.startswith("[Desktop Entry]")
    assert "Exec=computesec" not in content          # 已被替换成真实路径
    assert launcher.PKG_ROOT in content
    assert "run.py" in content

    launcher.install_desktop(uninstall=True)
    assert not desktop.exists() and not icon.exists()


def test_install_desktop_uninstall_is_idempotent(tmp_path, monkeypatch):
    _prepare(tmp_path, monkeypatch)
    launcher.install_desktop(uninstall=True)          # 什么都没装也不该抛异常


def test_install_desktop_creates_missing_dirs(tmp_path, monkeypatch):
    data_home = _prepare(tmp_path, monkeypatch)
    assert not (data_home / "applications").exists()
    launcher.install_desktop()
    assert (data_home / "applications").is_dir()
    assert (data_home / "icons" / "hicolor" / "scalable" / "apps").is_dir()
