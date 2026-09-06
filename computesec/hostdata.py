# -*- coding: utf-8 -*-
"""宿主机数据的“用户协助采集”。

背景
----
1. ``vm.mmap_rnd_bits`` / ``vm.mmap_rnd_compat_bits`` 等 sysctl 条目的
   /proc/sys 文件权限为 0600 root:root，普通用户读不到；
2. Flatpak 沙箱内 /proc 被重新挂载，另有若干 sysctl 条目被屏蔽；
3. 用 ``flatpak-spawn --host`` 在宿主机上执行命令属于“沙箱逃逸级”权限
   （拿到它等于拿到用户全部权限），对一个只读检测工具来说过于侵入。

因此改为：引导用户在自己的终端里执行只读命令，复制输出后回到窗口点击
“我已复制结果”，程序从剪贴板读取并解析。整个过程不需要任何提权权限，
用户也能看到自己到底执行了什么。

结果缓存在 XDG 数据目录中，并记录 boot_id：重启后自动失效（因为 sysctl
可能已经改变），同一次开机内不再重复打扰用户。
"""

import fnmatch
import json
import os
import re
import time

CACHE_NAME = "hostdata.json"
SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-/:]+$")
# 判断粘贴的内容确实是 sysctl 输出的“锚点”键
SYSCTL_ANCHORS = ("kernel.ostype", "kernel.osrelease", "kernel.version", "kernel.hostname",
                  "fs.file-max", "net.ipv4.ip_forward", "vm.max_map_count")


def _data_dir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    d = os.path.join(base, "computesec")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# 解析器：每个解析器接收剪贴板文本，返回 (数据, 错误信息)
# ---------------------------------------------------------------------------
def parse_sysctl(text):
    """解析 ``sysctl -a`` 输出为 {key: value}。"""
    if not text or not text.strip():
        return None, "剪贴板是空的。请先在终端中执行命令，并复制它的完整输出。"
    values = {}
    denied = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("sysctl:") or "permission denied on key" in low:
            denied += 1
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        # 去掉可能被一起复制进来的 shell 提示符
        if " " in key or not SYSCTL_KEY_RE.match(key) or "." not in key:
            continue
        values[key] = " ".join(val.split())
    if len(values) < 30 or not any(a in values for a in SYSCTL_ANCHORS):
        return None, ("剪贴板里的内容看起来不是 sysctl 的完整输出（只解析出 %d 个条目）。"
                      "请确认已执行上面的命令，并复制了它打印的全部内容。" % len(values))
    meta = {}
    if denied:
        meta["denied"] = denied
    return {"values": values, "meta": meta}, ""


def parse_lsblk(text):
    """解析 ``lsblk -J`` 的 JSON 输出。"""
    if not text or not text.strip():
        return None, "剪贴板是空的。请先在终端中执行命令，并复制它的完整输出。"
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None, "剪贴板里没有找到 JSON 内容。请确认复制的是 lsblk -J 命令的完整输出。"
    try:
        j = json.loads(text[start:end + 1])
    except ValueError as e:
        return None, f"JSON 解析失败：{e}。请重新复制完整输出（不要漏掉开头的 {{ 或结尾的 }}）。"
    if "blockdevices" not in j:
        return None, "JSON 中没有 blockdevices 字段，这似乎不是 lsblk -J 的输出。"
    return j, ""


# ---------------------------------------------------------------------------
# 步骤定义
# ---------------------------------------------------------------------------
class Step:
    def __init__(self, key, title, why, command, parser, required=True, hint=""):
        self.key = key
        self.title = title
        self.why = why
        self.command = command
        self.parser = parser
        self.required = required
        self.hint = hint


STEPS = [
    Step(
        key="sysctl",
        title="读取完整的内核运行时参数",
        why=("vm.mmap_rnd_bits、vm.mmap_rnd_compat_bits 等 ASLR 相关参数的文件权限是 root 独占，"
             "普通用户无法读取；在 Flatpak 沙箱里还有更多条目被屏蔽。"
             "请以 root 身份把它们全部打印出来，让 ComputeSec 能得到真实数值。"),
        command="sudo sysctl -a 2>/dev/null",
        parser=parse_sysctl,
        required=True,
        hint="终端中选中全部输出后按 Ctrl+Shift+C 复制（多数终端里 Ctrl+C 是中断）。"),
    Step(
        key="lsblk",
        title="读取磁盘分区文件系统类型",
        why=("用于检测机器上是否存在 NTFS 分区或 Windows 安装。这一步不需要 root，"
             "但 Flatpak 沙箱内看不到宿主机的块设备信息。"),
        command="lsblk -J -o NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT",
        parser=parse_lsblk,
        required=False,
        hint="如果这台机器上只有 Linux 文件系统，跳过这一步也不影响其它检测。"),
]


# ---------------------------------------------------------------------------
# 存储
# ---------------------------------------------------------------------------
class HostData:
    """用户协助采集到的宿主机数据。"""

    def __init__(self, payload=None):
        self.payload = payload or {}

    # -- 访问 ------------------------------------------------------------
    def get(self, key):
        entry = self.payload.get("steps", {}).get(key)
        return entry.get("data") if entry else None

    def has(self, key):
        return self.get(key) is not None

    @property
    def sysctl_values(self):
        d = self.get("sysctl")
        return (d or {}).get("values") or {}

    @property
    def lsblk(self):
        return self.get("lsblk")

    @property
    def collected_at(self):
        return self.payload.get("collected_at", 0)

    @property
    def collected_boot_id(self):
        return self.payload.get("boot_id", "")

    @property
    def skipped(self):
        return bool(self.payload.get("skipped"))

    @property
    def any_data(self):
        return any(self.has(s.key) for s in STEPS)

    @property
    def fresh(self):
        """本次开机内采集的数据才算新鲜（重启后 sysctl 可能已改变）。"""
        bid = boot_id()
        return bool(self.payload) and (not bid or self.collected_boot_id == bid)

    @property
    def age_text(self):
        if not self.collected_at:
            return ""
        secs = max(0, int(time.time() - self.collected_at))
        if secs < 60:
            return "刚刚"
        if secs < 3600:
            return f"{secs // 60} 分钟前"
        if secs < 86400:
            return f"{secs // 3600} 小时前"
        return f"{secs // 86400} 天前"

    def sysctl_lookup(self, key):
        """按 sysctl 键（可含 * 通配符）查找。返回 {具体键: 值}。"""
        values = self.sysctl_values
        if not values:
            return {}
        if "*" in key:
            return {k: v for k, v in values.items() if fnmatch.fnmatchcase(k, key)}
        return {key: values[key]} if key in values else {}

    # -- 修改 ------------------------------------------------------------
    def set(self, key, data):
        self.payload.setdefault("steps", {})[key] = {"data": data, "at": int(time.time())}
        self.payload["skipped"] = False

    def mark_done(self, skipped=False):
        self.payload["collected_at"] = int(time.time())
        self.payload["boot_id"] = boot_id()
        self.payload["skipped"] = bool(skipped)

    # -- 持久化 ----------------------------------------------------------
    @classmethod
    def load(cls):
        path = os.path.join(_data_dir(), CACHE_NAME)
        try:
            with open(path) as f:
                return cls(json.load(f))
        except (OSError, ValueError):
            return cls()

    def save(self):
        path = os.path.join(_data_dir(), CACHE_NAME)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self.payload, f)
            os.replace(tmp, path)
        except OSError:
            pass

    @staticmethod
    def clear():
        try:
            os.remove(os.path.join(_data_dir(), CACHE_NAME))
        except OSError:
            pass


# 进程内共享的当前数据（checks.collect() 读取它）
CURRENT = HostData()


def set_current(hd):
    global CURRENT
    CURRENT = hd or HostData()
    return CURRENT
