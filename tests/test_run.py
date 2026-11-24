# -*- coding: utf-8 -*-
"""run.py / computesec.cli：命令行参数、desktop entry 编码与安装。"""

import os

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


def test_install_desktop_in_place_for_pip_user_layout(tmp_path, monkeypatch, capsys):
    """pip install --user：data-files 就装在 $XDG_DATA_HOME 里，源与目标是同一个文件。

    此前 shutil.copy 抛 SameFileError，--install 只报一句「安装失败」。这里要原地把
    Exec= 改写成真实路径，并且重复执行仍然成功（第二次读到的已是改写后的那一行）。
    """
    user_root = tmp_path / "local"
    share = user_root / "share"
    monkeypatch.setenv("XDG_DATA_HOME", str(share))
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)   # 不真的去刷新缓存
    (share / "applications").mkdir(parents=True)
    (share / "icons" / "hicolor" / "scalable" / "apps").mkdir(parents=True)
    desktop = share / "applications" / (cli.APP_ID + ".desktop")
    icon = share / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")
    desktop.write_text("[Desktop Entry]\nName=ComputeSec\nExec=computesec\nIcon=x\n", encoding="utf-8")
    icon.write_text("<svg/>")
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "site-packages" / "computesec" / "cli.py"))
    monkeypatch.setattr(cli, "_share_roots", lambda: [str(user_root)])

    for _ in range(2):
        assert cli.install_desktop(launcher=["/home/u/.local/bin/computesec"]) is True
        lines = desktop.read_text(encoding="utf-8").splitlines()
        assert [ln for ln in lines if ln.startswith("Exec=")] == ["Exec=/home/u/.local/bin/computesec"]
        assert "Name=ComputeSec" in lines and "Icon=x" in lines
        assert icon.read_text() == "<svg/>"
    assert "安装失败" not in capsys.readouterr().err


def test_install_desktop_keeps_backslashes_in_exec(tmp_path, monkeypatch):
    """Exec= 按整行用正则改写：启动命令里的反斜杠不能被 re 当成转义序列再解释一遍。"""
    data_home = _prepare(tmp_path, monkeypatch)
    weird = "/home/u/a\\b/computesec"
    assert cli.install_desktop(launcher=[weird]) is True
    content = (data_home / "applications" / (cli.APP_ID + ".desktop")).read_text(encoding="utf-8")
    assert f"Exec={cli._quote_desktop_arg(weird)}\n" in content
    assert content.count("Exec=") == 1


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


def _readonly_source_tree(tmp_path):
    root = tmp_path / "src"
    icon_dir = root / "data" / "icons" / "hicolor" / "scalable" / "apps"
    icon_dir.mkdir(parents=True)
    (root / "data" / (cli.APP_ID + ".desktop")).write_text(
        "[Desktop Entry]\nExec=computesec\n", encoding="utf-8")
    src_icon = icon_dir / (cli.APP_ID + ".svg")
    src_icon.write_text("<svg/>", encoding="utf-8")
    os.chmod(src_icon, 0o444)           # 系统目录 / Nix store 里的文件就是只读的
    return root, src_icon


def test_install_desktop_does_not_copy_readonly_mode(tmp_path, monkeypatch):
    """只读源图标装出去后目标应保持可写，重复 --install 不能失败。"""
    data_home = _prepare(tmp_path, monkeypatch)
    root, _src_icon = _readonly_source_tree(tmp_path)
    monkeypatch.setattr(cli, "__file__", str(root / "computesec" / "cli.py"))

    assert cli.install_desktop(launcher=["/opt/computesec"]) is True
    icon = data_home / "icons" / "hicolor" / "scalable" / "apps" / (cli.APP_ID + ".svg")
    assert os.stat(icon).st_mode & 0o200
    assert cli.install_desktop(launcher=["/opt/computesec"]) is True


def test_install_desktop_replaces_readonly_icon_left_by_older_version(tmp_path, monkeypatch):
    """旧版本（shutil.copy）留下的只读目标图标，新版本应能直接覆盖。"""
    data_home = _prepare(tmp_path, monkeypatch)
    root, _src_icon = _readonly_source_tree(tmp_path)
    monkeypatch.setattr(cli, "__file__", str(root / "computesec" / "cli.py"))
    icon_dir = data_home / "icons" / "hicolor" / "scalable" / "apps"
    icon_dir.mkdir(parents=True)
    old = icon_dir / (cli.APP_ID + ".svg")
    old.write_text("<svg old/>", encoding="utf-8")
    os.chmod(old, 0o444)

    assert cli.install_desktop(launcher=["/opt/computesec"]) is True
    assert old.read_text(encoding="utf-8") == "<svg/>"


def test_xdg_display_dir_trailing_slash_symlink_and_nan(monkeypatch, tmp_path):
    import stat
    from computesec import xdg

    monkeypatch.setenv("HOME", str(tmp_path) + "/")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert xdg.display_dir() == "~/.local/share/computesec"

    # 不跟随符号链接 chmod 目标目录
    target = tmp_path / "real"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    xdg_root = tmp_path / "xdg"
    xdg_root.mkdir()
    (xdg_root / "computesec").symlink_to(target)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_root))
    xdg.data_dir()
    assert stat.S_IMODE(target.stat().st_mode) == 0o755

    # NaN 不写入缓存且不破坏旧文件
    cache = tmp_path / "c.json"
    xdg.atomic_write_json(str(cache), {"ok": 1})
    xdg.atomic_write_json(str(cache), {"bad": float("nan")})
    assert cache.read_text(encoding="utf-8") == '{"ok": 1}'


def test_share_roots_include_default_scheme(monkeypatch):
    """Debian/Ubuntu 默认 posix_local 将 data-files 装到 /usr/local，不能漏掉。"""
    orig = cli.sysconfig.get_path
    monkeypatch.setattr(cli.sysconfig, "get_path",
                        lambda name, *args: "/usr/local" if (name == "data" and not args) else orig(name, *args))
    assert "/usr/local" in cli._share_roots()


def test_cli_replaces_readonly_desktop_and_symlink_and_handles_braces_in_prog(tmp_path, monkeypatch, capsys):
    data_home = _prepare(tmp_path, monkeypatch)
    root, src_icon = _readonly_source_tree(tmp_path)
    monkeypatch.setattr(cli, "__file__", str(root / "computesec" / "cli.py"))

    apps_dir = data_home / "applications"
    icon_dir = data_home / "icons" / "hicolor" / "scalable" / "apps"
    apps_dir.mkdir(parents=True)
    icon_dir.mkdir(parents=True)

    # 只读旧 .desktop 与指向源文件的软链都应被安全替换为独立普通文件
    old_desktop = apps_dir / (cli.APP_ID + ".desktop")
    old_desktop.write_text("[Desktop Entry]\nExec=old\n", encoding="utf-8")
    os.chmod(old_desktop, 0o444)
    icon_dst = icon_dir / (cli.APP_ID + ".svg")
    icon_dst.symlink_to(src_icon)

    assert cli.install_desktop(launcher=["/opt/computesec"]) is True
    assert not icon_dst.is_symlink()
    assert "Exec=/opt/computesec" in old_desktop.read_text(encoding="utf-8")

    # prog 含花括号时 --help 不抛 KeyError/ValueError，sys.argv 为空时也不抛 IndexError
    monkeypatch.setattr(cli.sys, "argv", [])
    assert cli.main(["--help"], prog="cs{1}") == 0
    assert "cs{1}" in capsys.readouterr().out


def test_install_desktop_same_path_symlink_icon_survives(tmp_path, monkeypatch):
    """源图标与目标图标是同一个符号链接时，先读后删，不能把源图标删丢。"""
    prefix = tmp_path / "local"
    data_home = prefix / "share"
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "empty" / "computesec" / "cli.py"))
    monkeypatch.setattr(cli, "_share_roots", lambda: [str(prefix)])
    monkeypatch.setattr(cli.shutil, "which", lambda _cmd: None)

    apps_dir = data_home / "applications"
    icon_dir = data_home / "icons" / "hicolor" / "scalable" / "apps"
    apps_dir.mkdir(parents=True)
    icon_dir.mkdir(parents=True)
    (apps_dir / (cli.APP_ID + ".desktop")).write_text("[Desktop Entry]\nExec=computesec\n", encoding="utf-8")

    real_icon = tmp_path / "real.svg"
    real_icon.write_text("<svg>ok</svg>", encoding="utf-8")
    icon_link = icon_dir / (cli.APP_ID + ".svg")
    icon_link.symlink_to(real_icon)

    assert cli.install_desktop(launcher=["/opt/computesec"]) is True
    assert not icon_link.is_symlink()
    assert icon_link.read_text(encoding="utf-8") == "<svg>ok</svg>"
    assert real_icon.read_text(encoding="utf-8") == "<svg>ok</svg>"


def test_install_desktop_readonly_parent_dir_reports_permission_error(tmp_path, monkeypatch, capsys):
    data_home = _prepare(tmp_path, monkeypatch)
    apps_dir = data_home / "applications"
    icon_dir = data_home / "icons" / "hicolor" / "scalable" / "apps"
    apps_dir.mkdir(parents=True)
    icon_dir.mkdir(parents=True)

    def deny_open(path, mode="r", *args, **kwargs):
        if "w" in mode and str(path).startswith(str(data_home)):
            raise PermissionError(13, "Permission denied", str(path))
        return orig_open(path, mode, *args, **kwargs)

    import builtins
    orig_open = builtins.open
    monkeypatch.setattr(builtins, "open", deny_open)
    assert cli.install_desktop(launcher=["/opt/computesec"]) is False
    err = capsys.readouterr().err
    assert "Permission denied" in err
    assert "No such file or directory" not in err


def test_default_launcher_normalizes_relative_which_hit(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.sys, "argv", ["computesec"])
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "./bin/computesec")
    got = cli._default_launcher()
    assert len(got) == 1 and os.path.isabs(got[0])


def test_xdg_display_dir_unnormalized_home_and_atomic_write_type_error(monkeypatch, tmp_path):
    from computesec import xdg

    monkeypatch.setenv("HOME", str(tmp_path) + "/./sub/..")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert xdg.display_dir() == "~/.local/share/computesec"

    cache = tmp_path / "t.json"
    xdg.atomic_write_json(str(cache), {"ok": 1})
    xdg.atomic_write_json(str(cache), {"bad": {1, 2, 3}})
    assert cache.read_text(encoding="utf-8") == '{"ok": 1}'


def test_default_launcher_empty_argv_checks_path_and_venv_bin(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.sys, "argv", [])
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/computesec" if name == "computesec" else None)
    assert cli._default_launcher() == ["/usr/bin/computesec"]

    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    script = venv_bin / "computesec"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cli.sys, "executable", str(venv_bin / "python3"))
    assert cli._default_launcher() == [str(script)]


def test_default_launcher_bare_name_not_found_and_relative_home_display_dir(monkeypatch):
    from computesec import xdg

    monkeypatch.setattr(cli.sys, "argv", ["computesec"])
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cli.sys, "executable", "")
    assert cli._default_launcher() == ["computesec"]

    monkeypatch.setenv("HOME", "relative/home")
    monkeypatch.setenv("XDG_DATA_HOME", "/var/tmp/csdata")
    assert xdg.display_dir() == "/var/tmp/csdata/computesec"
