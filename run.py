#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ComputeSec 启动器

  python3 run.py                # 直接运行
  python3 run.py --install      # 安装 .desktop 与图标到 ~/.local/share，使任务栏/启动器正确显示图标
  python3 run.py --uninstall    # 移除上述文件
  python3 run.py --help         # 全部选项

Flatpak 打包时本文件被安装为 /app/bin/computesec，程序包位于 /app/lib/computesec/。
参数处理在 computesec/cli.py 里，与 pip 安装出的 computesec 命令共用。
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# 定位程序包：源码目录 或 /app/lib/computesec
for cand in (HERE, os.path.join(HERE, "..", "lib", "computesec")):
    if os.path.isdir(os.path.join(cand, "computesec")):
        sys.path.insert(0, os.path.abspath(cand))
        PKG_ROOT = os.path.abspath(cand)
        break
else:
    sys.stderr.write("找不到 computesec 程序包。\n")
    sys.exit(1)

from computesec import cli  # noqa: E402
from computesec.cli import APP_ID, _data_home, _quote_desktop_arg  # noqa: E402,F401  (供测试与旧代码引用)

# 从源码目录安装 .desktop 时，Exec= 写成「当前解释器 + 本文件」。
_LAUNCHER = [sys.executable, os.path.abspath(__file__)]


def install_desktop(uninstall=False):
    return cli.install_desktop(uninstall, launcher=_LAUNCHER)


def main(argv=None):
    return cli.main(argv, prog="run.py", launcher=_LAUNCHER)


if __name__ == "__main__":
    sys.exit(main())
