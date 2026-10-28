# -*- coding: utf-8 -*-
"""run.py / computesec.cli：命令行参数、desktop entry 编码与安装。"""

import pytest

import run as launcher
from computesec import cli


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
    assert cli._quote_desktop_arg(arg) == want


def test_quote_desktop_arg_escapes_newline():
    encoded = cli._quote_desktop_arg("/home/u/a\nExec=evil")
    assert "\n" not in encoded
    assert r"\n" in encoded


def test_data_home_respects_absolute_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert cli._data_home() == str(tmp_path / "xdg")


def test_data_home_ignores_relative_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cli._data_home() == str(tmp_path / ".local" / "share")


# ---------------------------------------------------------------------------
# 命令行参数
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("argv", [["--version"], ["-V"]])
def test_version_does_not_launch_gui(argv, capsys):
    """--version 必须在 import gi 之前就返回，否则无图形环境下会报依赖错误。"""
    from computesec import data
    assert launcher.main(argv) == 0
    out = capsys.readouterr().out.strip()
    assert out == f"{cli.APP_ID} {data.VERSION}"


@pytest.mark.parametrize("argv", [["--help"], ["-h"]])
def test_help_lists_options(argv, capsys):
    assert launcher.main(argv) == 0
    out = capsys.readouterr().out
    for opt in ("--install", "--uninstall", "--version", "--help"):
        assert opt in out


@pytest.mark.parametrize("argv", [["--instal"], ["install"], ["foo.txt"]])
def test_unknown_argument_is_rejected(argv, capsys):
    """不能把打错的参数当成"启动 GUI"偷偷吞掉——不带横线的也一样，否则 GApplication
    会把它当成要打开的文件，只报一句 "This application can not open files"。"""
    assert launcher.main(argv) == 2
    assert argv[0] in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--version", "--install"], ["--install", "--help"]])
def test_conflicting_actions_are_rejected(argv, capsys):
    """同时给出两个动作时直接报错：任何"先命中哪个做哪个"的规则都是猜。"""
    assert launcher.main(argv) == 2
    assert "不能同时使用" in capsys.readouterr().err


def test_unknown_argument_is_not_carried_by_a_valid_one(capsys):
    """打错的参数不能被旁边的正确参数"带过"（--install --instal）。"""
    assert launcher.main(["--install", "--instal"]) == 2
    assert "--instal" in capsys.readouterr().err


def test_same_action_twice_is_harmless(capsys):
    """重复给同一个参数不算冲突（用户手滑按了两下），也不该报错。"""
    from computesec import data
    assert launcher.main(["--version", "-V"]) == 0
    assert capsys.readouterr().out.strip() == f"{data.APP_ID} {data.VERSION}"


def test_pip_entry_point_shares_the_same_cli(capsys):
    """pip 装出的 computesec 命令与 run.py 走同一套参数处理。"""
    from computesec import data
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"{data.APP_ID} {data.VERSION}"


def test_missing_deps_message_mentions_venv(monkeypatch):
    monkeypatch.setattr(cli.sys, "base_prefix", "/usr")
    monkeypatch.setattr(cli.sys, "prefix", "/tmp/venv")
    assert "--system-site-packages" in cli._missing_deps_message("No module named 'gi'")


# ---------------------------------------------------------------------------
# install_desktop：装/卸 .desktop 与图标
# ---------------------------------------------------------------------------
def _prepare(tmp_path, monkeypatch):
    """把 XDG_DATA_HOME 指到临时目录，并屏蔽掉系统里的 update-desktop-database。"""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)   # 不真的去刷新缓存
    return tmp_path / "xdg"


def test_install_desktop_then_uninstall(tmp_path, monkeypatch):
    data_home = _prepare(tmp_path, monkeypatch)
    launcher.install_desktop()

    desktop = data_home / "applications" / (cli.APP_ID + ".desktop")
    icon = data_home / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")
    assert desktop.exists() and icon.exists()

    content = desktop.read_text(encoding="utf-8")
    assert content.startswith("[Desktop Entry]")
    assert "Exec=computesec" not in content          # 已被替换成真实路径
    assert launcher.PKG_ROOT in content
    assert "run.py" in content

    launcher.install_desktop(uninstall=True)
    assert not desktop.exists() and not icon.exists()


def test_install_desktop_from_pip_layout(tmp_path, monkeypatch):
    """pip 安装时 data/ 不在包旁边，要从 <prefix>/share 取，Exec= 写成当前命令本身。"""
    data_home = _prepare(tmp_path, monkeypatch)
    prefix = tmp_path / "venv"
    share = prefix / "share"
    (share / "applications").mkdir(parents=True)
    (share / "icons" / "hicolor" / "scalable" / "apps").mkdir(parents=True)
    (share / "applications" / (cli.APP_ID + ".desktop")).write_text(
        "[Desktop Entry]\nExec=computesec\n", encoding="utf-8")
    (share / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")).write_text("<svg/>")
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "site-packages" / "computesec" / "cli.py"))
    monkeypatch.setattr(cli.sys, "prefix", str(prefix))
    monkeypatch.setattr(cli.sys, "argv", [str(prefix / "bin" / "computesec")])
    cli.install_desktop()
    content = (data_home / "applications" / (cli.APP_ID + ".desktop")).read_text(encoding="utf-8")
    assert f"Exec={prefix}/bin/computesec" in content


def test_install_desktop_uninstall_is_idempotent(tmp_path, monkeypatch):
    _prepare(tmp_path, monkeypatch)
    launcher.install_desktop(uninstall=True)          # 什么都没装也不该抛异常


def test_install_desktop_creates_missing_dirs(tmp_path, monkeypatch):
    data_home = _prepare(tmp_path, monkeypatch)
    assert not (data_home / "applications").exists()
    launcher.install_desktop()
    assert (data_home / "applications").is_dir()
    assert (data_home / "icons" / "hicolor" / "scalable" / "apps").is_dir()


def test_share_roots_include_the_user_scheme():
    """pip install --user 把 data-files 装进用户 scheme，只看 sys.prefix 会找不到。"""
    import sysconfig
    assert sysconfig.get_path("data", "posix_user") in cli._share_roots()


def test_install_desktop_without_source_files_is_reported(tmp_path, monkeypatch, capsys):
    """找不到 desktop / 图标时给一句话并返回 1，而不是 FileNotFoundError 的 Traceback。

    pip install --user 的布局下（或只装了包、data-files 缺失时）此前会直接抛栈。
    """
    _prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "site-packages" / "computesec" / "cli.py"))
    monkeypatch.setattr(cli, "_share_roots", lambda: [str(tmp_path / "nowhere")])
    assert launcher.main(["--install"]) == 1
    assert "找不到" in capsys.readouterr().err


def test_install_desktop_falls_back_to_other_share_roots(tmp_path, monkeypatch):
    """data-files 装在 sys.prefix 之外的 scheme 里时同样要能找到。"""
    data_home = _prepare(tmp_path, monkeypatch)
    user_root = tmp_path / "local"
    share = user_root / "share"
    (share / "applications").mkdir(parents=True)
    (share / "icons" / "hicolor" / "scalable" / "apps").mkdir(parents=True)
    (share / "applications" / (cli.APP_ID + ".desktop")).write_text(
        "[Desktop Entry]\nExec=computesec\n", encoding="utf-8")
    (share / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")).write_text("<svg/>")
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "site-packages" / "computesec" / "cli.py"))
    monkeypatch.setattr(cli, "_share_roots", lambda: [str(tmp_path / "nope"), str(user_root)])

    assert cli.install_desktop(launcher=["/opt/computesec"]) is True
    content = (data_home / "applications" / (cli.APP_ID + ".desktop")).read_text(encoding="utf-8")
    assert "Exec=/opt/computesec" in content


def test_install_desktop_requires_the_exec_line(tmp_path, monkeypatch, capsys):
    """源文件里没有 Exec= 行时不能装出一个指向不存在命令的菜单项。"""
    _prepare(tmp_path, monkeypatch)
    root = tmp_path / "src"
    (root / "data" / "icons" / "hicolor" / "scalable" / "apps").mkdir(parents=True)
    (root / "data" / (cli.APP_ID + ".desktop")).write_text("[Desktop Entry]\nName=x\n", encoding="utf-8")
    (root / "data" / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")).write_text("<svg/>")
    monkeypatch.setattr(cli, "__file__", str(root / "computesec" / "cli.py"))

    assert cli.install_desktop() is False
    assert "Exec=computesec" in capsys.readouterr().err


def test_uninstall_reports_unremovable_path(tmp_path, monkeypatch, capsys):
    """目标位置被目录（或不可删的东西）占住时只报一句，不抛异常。"""
    data_home = _prepare(tmp_path, monkeypatch)
    (data_home / "applications" / (cli.APP_ID + ".desktop")).mkdir(parents=True)
    assert cli.install_desktop(uninstall=True) is False
    assert "无法删除" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# XDG 规则：三处共用一个实现（computesec.xdg）
# ---------------------------------------------------------------------------
def test_data_dir_rules_are_shared(monkeypatch, tmp_path):
    """hostdata 与 kernelver 的数据目录必须落在同一个地方。"""
    from computesec import hostdata, kernelver, xdg

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert hostdata._data_dir() == str(tmp_path / "xdg" / "computesec")
    assert kernelver._data_dir() == hostdata._data_dir()
    assert cli._data_home() == xdg.data_home()


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
