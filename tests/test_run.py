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
# 命令行参数
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv", [["--version"], ["-V"]])
def test_version_does_not_launch_gui(argv, capsys):
    """--version 必须在 import gi 之前就返回，否则无图形环境下会报依赖错误。"""
    from computesec import data
    assert launcher.main(argv) == 0
    out = capsys.readouterr().out.strip()
    assert out == f"{launcher.APP_ID} {data.VERSION}"


@pytest.mark.parametrize("argv", [["--help"], ["-h"]])
def test_help_lists_options(argv, capsys):
    assert launcher.main(argv) == 0
    out = capsys.readouterr().out
    for opt in ("--install", "--uninstall", "--version", "--help"):
        assert opt in out


def test_unknown_option_is_rejected(capsys):
    """不能把打错的参数当成"启动 GUI"偷偷吞掉。"""
    assert launcher.main(["--instal"]) == 2
    assert "--instal" in capsys.readouterr().err


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


# ---------------------------------------------------------------------------
# XDG 规则：三处共用一个实现（computesec.xdg）
# ---------------------------------------------------------------------------
def test_data_dir_rules_are_shared(monkeypatch, tmp_path):
    """hostdata 与 kernelver 的数据目录必须落在同一个地方。"""
    from computesec import hostdata, kernelver, xdg

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert hostdata._data_dir() == str(tmp_path / "xdg" / "computesec")
    assert kernelver._data_dir() == hostdata._data_dir()
    assert launcher._data_home() == xdg.data_home()


def test_data_dir_is_private(monkeypatch, tmp_path):
    """目录里可能有完整的 sysctl 快照，不能给同机其它用户读到。"""
    import os
    import stat

    from computesec import xdg

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    d = xdg.data_dir()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700

    os.chmod(d, 0o755)                       # 模拟旧版本留下的目录
    xdg.data_dir()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
