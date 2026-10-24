#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ComputeSec 启动器

  python3 run.py                # 直接运行
  python3 run.py --install      # 安装 .desktop 与图标到 ~/.local/share，使任务栏/启动器正确显示图标
  python3 run.py --uninstall    # 移除上述文件

Flatpak 打包时本文件被安装为 /app/bin/computesec，程序包位于 /app/lib/computesec/。
"""

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_ID = "uk._92li.lingyicute.ComputeSec"

# 定位程序包：源码目录 或 /app/lib/computesec
for cand in (HERE, os.path.join(HERE, "..", "lib", "computesec")):
    if os.path.isdir(os.path.join(cand, "computesec")):
        sys.path.insert(0, os.path.abspath(cand))
        PKG_ROOT = os.path.abspath(cand)
        break
else:
    sys.stderr.write("找不到 computesec 程序包。\n")
    sys.exit(1)


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
    from computesec import xdg
    return xdg.data_home()


def install_desktop(uninstall=False):
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
        os.makedirs(apps_dir, exist_ok=True)
        os.makedirs(icon_dir, exist_ok=True)
        shutil.copy(os.path.join(PKG_ROOT, "data", "icons", "hicolor", "scalable", "apps", APP_ID + ".svg"), icon_path)
        with open(os.path.join(PKG_ROOT, "data", APP_ID + ".desktop"), encoding="utf-8") as f:
            content = f.read()
        exec_line = f"{_quote_desktop_arg(sys.executable)} {_quote_desktop_arg(os.path.join(PKG_ROOT, 'run.py'))}"
        content = content.replace("Exec=computesec", f"Exec={exec_line}")
        with open(desktop_path, "w", encoding="utf-8") as f:
            f.write(content)
        print("已安装", desktop_path)
        print("已安装", icon_path)
    for cmd in (["update-desktop-database", apps_dir], ["gtk-update-icon-cache", "-f", "-t", os.path.join(data_home, "icons", "hicolor")]):
        if shutil.which(cmd[0]):
            os.spawnvp(os.P_WAIT, cmd[0], cmd)
    print("完成。")


HELP = """\
用法: run.py [选项]

  （无选项）      启动图形界面
  --install       安装 .desktop 与图标到 ~/.local/share，使任务栏/启动器正确显示图标
  --uninstall     移除上面安装的文件
  --version, -V   打印版本号
  -h, --help      显示本帮助
"""


def _print_help(stream=None):
    # 不把 sys.stdout 写成默认参数：那样会在导入时就把流固定下来，
    # 之后（测试、重定向）替换 sys.stdout 就不再生效。
    (stream or sys.stdout).write(HELP)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # 参数在导入 gi 之前处理：没有图形环境的机器上，--version / --help 也该能用。
    if "--version" in argv or "-V" in argv:
        from computesec import data
        print(f"{APP_ID} {data.VERSION}")
        return 0
    if "-h" in argv or "--help" in argv:
        _print_help()
        return 0
    if "--install" in argv:
        install_desktop()
        return 0
    if "--uninstall" in argv:
        install_desktop(uninstall=True)
        return 0
    unknown = [a for a in argv if a.startswith("-")]
    if unknown:
        sys.stderr.write(f"未知选项：{' '.join(unknown)}\n\n")
        _print_help(sys.stderr)
        return 2
    try:
        import gi  # noqa: F401
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
    except (ImportError, ValueError) as e:
        sys.stderr.write(
            f"缺少依赖：{e}\n"
            "请安装 PyGObject、GTK4 与 libadwaita：\n"
            "  Fedora:        sudo dnf install python3-gobject gtk4 libadwaita fwupd\n"
            "  Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 fwupd\n"
            "  Arch:          sudo pacman -S python-gobject gtk4 libadwaita fwupd\n")
        return 1
    from computesec.main import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
