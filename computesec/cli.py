# -*- coding: utf-8 -*-
"""命令行入口：参数分发与桌面集成。本模块不 import gi。

run.py（源码直接运行；Flatpak 里它就是 /app/bin/computesec）与 pip 安装出的
`computesec` 命令共用这里，保证两者行为一致：

- --version / --help 在没有图形环境、没有 PyGObject 的机器上也能用；
- 缺 PyGObject / GTK / libadwaita 时给出发行版安装命令，而不是一段 Traceback；
- 不认识的参数（包括不带横线的，如误输的 `install`）一律报错退出，不会被悄悄
  交给 GApplication——那样只会得到一句 "This application can not open files"。
"""

import os
import shutil
import sys

from . import data, xdg

APP_ID = data.APP_ID


def _quote_desktop_arg(arg):
    """按 Desktop Entry 规范编码 Exec 中的单个参数（不是 shell 引号）。"""
    reserved = ' \t\n\r"\'\\><~|&;$*?#()`'
    quoted = not arg or any(ch in arg for ch in reserved)
    if quoted:
        # Exec 层：双引号内这些字符需要前置反斜杠。
        arg = "".join("\\" + ch if ch in ('"', '`', '$', '\\') else ch for ch in arg)
    # desktop string 层先于 Exec 层解码，因此上面的反斜杠还需再转义一次。
    arg = (arg.replace("\\", "\\\\")
              .replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r"))
    # %u 等是启动器字段代码；字面百分号必须写成 %%。
    arg = arg.replace("%", "%%")
    return f'"{arg}"' if quoted else arg


def _data_home():
    """XDG_DATA_HOME；规则与 computesec.xdg 共用一份。"""
    return xdg.data_home()


def _source_files():
    """.desktop 与图标的来源。

    源码树与 Flatpak（/app/lib/computesec）里，它们在程序包旁边的 data/ 下；
    pip 安装时 data/ 不属于 Python 包，由 data-files 装到了 <prefix>/share 下。
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(root, "data")
    desktop = os.path.join(src, APP_ID + ".desktop")
    icon = os.path.join(src, "icons", "hicolor", "scalable", "apps", APP_ID + ".svg")
    if os.path.isfile(desktop) and os.path.isfile(icon):
        return desktop, icon
    share = os.path.join(sys.prefix, "share")
    return (os.path.join(share, "applications", APP_ID + ".desktop"),
            os.path.join(share, "icons", "hicolor", "scalable", "apps", APP_ID + ".svg"))


def install_desktop(uninstall=False, launcher=None):
    """把 .desktop 与图标装到（或移出）$XDG_DATA_HOME。

    launcher 是写进 Exec= 的命令行（参数列表）；默认是当前被执行的这个脚本。
    """
    data_home = _data_home()
    apps_dir = os.path.join(data_home, "applications")
    icon_dir = os.path.join(data_home, "icons", "hicolor", "scalable", "apps")
    desktop_path = os.path.join(apps_dir, APP_ID + ".desktop")
    icon_path = os.path.join(icon_dir, APP_ID + ".svg")
    if uninstall:
        for p in (desktop_path, icon_path):
            if os.path.exists(p):
                os.remove(p)
                print("已删除", p)
    else:
        src_desktop, src_icon = _source_files()
        launcher = launcher or [os.path.abspath(sys.argv[0])]
        os.makedirs(apps_dir, exist_ok=True)
        os.makedirs(icon_dir, exist_ok=True)
        shutil.copy(src_icon, icon_path)
        with open(src_desktop, encoding="utf-8") as f:
            content = f.read()
        exec_line = " ".join(_quote_desktop_arg(a) for a in launcher)
        content = content.replace("Exec=computesec", f"Exec={exec_line}")
        with open(desktop_path, "w", encoding="utf-8") as f:
            f.write(content)
        print("已安装", desktop_path)
        print("已安装", icon_path)
    for cmd in (["update-desktop-database", apps_dir],
                ["gtk-update-icon-cache", "-f", "-t", os.path.join(data_home, "icons", "hicolor")]):
        if shutil.which(cmd[0]):
            os.spawnvp(os.P_WAIT, cmd[0], cmd)
    print("完成。")


HELP = """\
用法: {prog} [选项]

  （无选项）      启动图形界面
  --install       安装 .desktop 与图标到 ~/.local/share，使任务栏/启动器正确显示图标
  --uninstall     移除上面安装的文件
  --version, -V   打印版本号
  -h, --help      显示本帮助
"""


def _print_help(prog, stream=None):
    # 不把 sys.stdout 写成默认参数：那样会在导入时就把流固定下来，
    # 之后（测试、重定向）替换 sys.stdout 就不再生效。
    (stream or sys.stdout).write(HELP.format(prog=prog))


def _missing_deps_message(err):
    msg = (f"缺少依赖：{err}\n"
           "请安装 PyGObject、GTK4 与 libadwaita：\n"
           "  Fedora:        sudo dnf install python3-gobject gtk4 libadwaita fwupd\n"
           "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 fwupd\n"
           "  Arch:          sudo pacman -S python-gobject gtk4 libadwaita fwupd\n")
    if sys.prefix != sys.base_prefix:
        msg += (f"\n当前运行在虚拟环境中（{sys.prefix}）。PyGObject 只能由发行版提供，"
                "创建虚拟环境时需要加 --system-site-packages 才能看到它。\n")
    return msg


# 认识的参数。启动 GUI 时不带任何参数。
_OPTIONS = {
    "--version": "version", "-V": "version",
    "--help": "help", "-h": "help",
    "--install": "install",
    "--uninstall": "uninstall",
}


def _parse(argv):
    """把参数列表解析成 (动作, 未知参数列表)。

    逐个识别，而不是用 ``"--install" in argv`` 这样的成员判断：那种写法下
    ``computesec --version --install`` 会静默只做先命中的那一件，
    ``computesec --install --instal``（打错一个字母）也会被正确参数"带过"。
    """
    actions, unknown = [], []
    for arg in argv:
        action = _OPTIONS.get(arg)
        if action is None:
            unknown.append(arg)
        elif action not in actions:
            actions.append(action)
    return actions, unknown


def main(argv=None, prog=None, launcher=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    prog = prog or os.path.basename(sys.argv[0] or "") or "computesec"
    # 参数在导入 gi 之前处理：没有图形环境的机器上，--version / --help 也该能用。
    actions, unknown = _parse(argv)
    if unknown:
        sys.stderr.write(f"未知参数：{' '.join(unknown)}\n\n")
        _print_help(prog, sys.stderr)
        return 2
    if len(actions) > 1:
        # --install 与 --version 同时给出时，任何"先命中哪个做哪个"的规则都是
        # 用户没写清楚的意图，直接报错比猜要诚实。
        sys.stderr.write(f"参数不能同时使用：{' '.join(a for a in argv if a in _OPTIONS)}\n\n")
        _print_help(prog, sys.stderr)
        return 2
    action = actions[0] if actions else None
    if action == "version":
        print(f"{APP_ID} {data.VERSION}")
        return 0
    if action == "help":
        _print_help(prog)
        return 0
    if action == "install":
        install_desktop(launcher=launcher)
        return 0
    if action == "uninstall":
        install_desktop(uninstall=True)
        return 0
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
    except (ImportError, ValueError) as e:
        sys.stderr.write(_missing_deps_message(e))
        return 1
    from .main import main as gui_main
    # 参数已在上面处理完毕，不再交给 GApplication 解析。
    return gui_main([sys.argv[0]])
