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
APP_ID = "io.github.lingyicute.ComputeSec"

# 定位程序包：源码目录 或 /app/lib/computesec
for cand in (HERE, os.path.join(HERE, "..", "lib", "computesec")):
    if os.path.isdir(os.path.join(cand, "computesec")):
        sys.path.insert(0, os.path.abspath(cand))
        PKG_ROOT = os.path.abspath(cand)
        break
else:
    sys.stderr.write("找不到 computesec 程序包。\n")
    sys.exit(1)


def install_desktop(uninstall=False):
    home = os.path.expanduser("~")
    apps_dir = os.path.join(home, ".local", "share", "applications")
    icon_dir = os.path.join(home, ".local", "share", "icons", "hicolor", "scalable", "apps")
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
        with open(os.path.join(PKG_ROOT, "data", APP_ID + ".desktop")) as f:
            content = f.read()
        exec_line = f"{sys.executable} {os.path.join(PKG_ROOT, 'run.py')}"
        content = content.replace("Exec=computesec", f"Exec={exec_line}")
        with open(desktop_path, "w") as f:
            f.write(content)
        print("已安装", desktop_path)
        print("已安装", icon_path)
    for cmd in (["update-desktop-database", apps_dir], ["gtk-update-icon-cache", "-f", "-t", os.path.join(home, ".local", "share", "icons", "hicolor")]):
        if shutil.which(cmd[0]):
            os.spawnvp(os.P_WAIT, cmd[0], cmd)
    print("完成。")


if __name__ == "__main__":
    if "--install" in sys.argv:
        install_desktop()
        sys.exit(0)
    if "--uninstall" in sys.argv:
        install_desktop(uninstall=True)
        sys.exit(0)
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
        sys.exit(1)
    from computesec.main import main
    sys.exit(main())
