# -*- coding: utf-8 -*-
"""XDG 数据目录：一处实现，三处共用。

这条规则此前在 run.py、hostdata.py、kernelver.py 里各抄了一份，而且已经开始
漂移——hostdata 那份会顺手把历史遗留的 0755 目录收紧成 0700，kernelver 那份
不会。规则本身很短，但"抄三份"意味着改一处就得记得改三处。

本模块不 import gi，也不 import 本包里的其它模块，可以被 run.py 这种只做安装
的入口直接使用。
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
