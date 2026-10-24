# -*- coding: utf-8 -*-
"""XDG 数据目录：一处实现，三处共用。

这条规则此前在 run.py、hostdata.py、kernelver.py 里各抄了一份，而且已经开始
漂移——hostdata 那份会顺手把历史遗留的 0755 目录收紧成 0700，kernelver 那份
不会。规则本身很短，但"抄三份"意味着改一处就得记得改三处。

本模块不 import gi，也不 import 本包里的其它模块，可以被 cli.py 这种只做参数
处理与安装的入口直接使用。
"""

import os


def data_home():
    """$XDG_DATA_HOME；按 XDG 规范，相对路径视为无效并忽略。"""
    base = os.environ.get("XDG_DATA_HOME") or ""
    if not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "share")
    return base


def data_dir(name="computesec", create=True):
    """本程序的数据目录，默认创建并把权限收紧到 0700。

    目录里可能存有用户粘贴的完整 `sudo sysctl -a` 输出（含内核地址、主机名），
    只应给当前用户读写。create=False 时只算路径、不碰文件系统。
    """
    d = os.path.join(data_home(), name)
    if not create:
        return d
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        # 旧版本以 0755 创建，这里顺手收紧（仅本程序的私有目录）。
        if (os.stat(d).st_mode & 0o077) != 0:
            os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def display_dir(name="computesec"):
    """给人看的数据目录路径：家目录缩成 ``~``，其余原样。

    界面上的提示（采集向导的"数据仅保存在本机（…）"）不能写死
    ``~/.local/share/computesec/``：遵守 XDG 规范的用户会把 XDG_DATA_HOME 指到
    别处，写死之后那句提示就是错的。只算路径，不碰文件系统。
    """
    d = data_dir(name, create=False)
    home = os.path.expanduser("~")
    if home and home != os.sep and (d == home or d.startswith(home + os.sep)):
        return "~" + d[len(home):]
    return d
