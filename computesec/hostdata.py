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

from . import xdg

CACHE_NAME = "hostdata.json"
SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-/:]+$")
# 判断粘贴的内容确实是 sysctl 输出的“锚点”键
SYSCTL_ANCHORS = ("kernel.ostype", "kernel.osrelease", "kernel.version", "kernel.hostname",
                  "fs.file-max", "net.ipv4.ip_forward", "vm.max_map_count")


def _data_dir(create=True):
    """本程序的数据目录（规则见 computesec.xdg）。只读查询传 create=False，不在磁盘上留痕。"""
    return xdg.data_dir(create=create)


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
            # "sysctl:" 前缀不等于权限问题：procps 3.3.12 及更早（RHEL 7 的 3.3.10、
            # Ubuntu 18.04 / Debian 9 的 3.3.12）在 stable_secret 未配置时，sudo 下
            # 也会为每个网卡打印一条 `sysctl: reading key "net.ipv6.conf.*.stable_secret"`
            # （内核在 read() 时返回 EIO，procps 用 xwarnx 输出，不带错误原因；
            # 3.3.13 起这一行被静默忽略）。它与是否 sudo 无关，不能计入 denied。
            # zh_CN 译文：4.0.4 及更早是「读取%s 时出错」，4.0.5 起是「读取键 "%s"」。
            # 其余行照旧计数——按 "sysctl:" 前缀而不是英文子串识别，zh_CN 的
            # 权限拒绝行（旧译「…权限被拒绝」、新译「对键 … 的权限不够」）才不会被漏掉；
            # 无法识别读错消息的其它语言退回旧行为（全部计数），宁可多提示也不漏提示。
            if "reading key" in low or "读取键" in line or ("读取" in line and "时出错" in line):
                continue
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
    j = None
    last_err = None
    try:
        j = json.loads(text[start:end + 1])
    except ValueError as e:
        last_err = e
        # 终端提示符中若恰巧含有 { 或 }，从每个 { 起尝试解码首个完整 JSON 对象
        decoder = json.JSONDecoder()
        pos = start
        while pos >= 0:
            try:
                cand, _ = decoder.raw_decode(text, pos)
                if isinstance(cand, dict):
                    j = cand
                    # 提示符或先前命令可能也包含 JSON；跳过非 lsblk 对象继续找。
                    if _lsblk_data_ok(cand):
                        break
            except ValueError:
                pass
            pos = text.find("{", pos + 1)
    if j is None:
        return None, f"JSON 解析失败：{last_err}。请重新复制完整输出（不要漏掉开头的 {{ 或结尾的 }}）。"
    if not _lsblk_data_ok(j):
        return None, ("JSON 中的 blockdevices 列表或设备字段无效。"
                      "请执行向导给出的完整命令，确保每个设备包含 NAME 与 FSTYPE。")
    return j, ""


def _payload_ok(payload):
    """判断缓存内容的结构是否可信。

    load() 只能保证"文件是合法 JSON"，而 get()/sysctl_values 等访问器假设
    steps 是 {key: {"data": ...}} 的嵌套字典。若缓存被截断、被手工改坏或被旧版本
    写成别的形状（例如 {"steps": ["oops"]}），那些访问器会抛 AttributeError，
    被 checks.collect() 的兜底吞掉后表现为"整个 sysctl 板块凭空消失、内核得 0 分"，
    既没有报错也没有提示。这里宁可把结构不对的缓存当不存在，让用户重新采集。
    """
    if not isinstance(payload, dict):
        return False
    if not _is_number(payload.get("collected_at", 0)):
        return False
    if not isinstance(payload.get("boot_id", ""), str):
        return False
    steps = payload.get("steps", {})
    if not isinstance(steps, dict):
        return False
    for key, entry in steps.items():
        if not isinstance(entry, dict):
            return False
        # 只校验认识的步骤；data 缺失表示这一步没有数据，是合法的。
        check = _STEP_DATA_OK.get(key)
        if check is not None and "data" in entry and not check(entry["data"]):
            return False
    return True


def _is_number(v):
    # bool 是 int 的子类，但 True 当时间戳显然是坏数据。
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    # json.load 认 NaN / Infinity 这两个字面量，但它们同样不是时间戳：拿去做减法、
    # 取整会抛 ValueError / OverflowError。
    return v == v and abs(v) != float("inf")


def _sysctl_data_ok(d):
    if not isinstance(d, dict) or not isinstance(d.get("values"), dict):
        return False
    return all(isinstance(k, str) and isinstance(v, str) for k, v in d["values"].items())


def _lsblk_data_ok(d):
    """校验整个设备树，避免缺少 FSTYPE 被误当作「没有 Windows 分区」。"""
    if not isinstance(d, dict) or not isinstance(d.get("blockdevices"), list):
        return False
    pending = list(d["blockdevices"])
    while pending:
        node = pending.pop()
        if not isinstance(node, dict) or not isinstance(node.get("name"), str) or not node["name"]:
            return False
        if "fstype" not in node or (node["fstype"] is not None and not isinstance(node["fstype"], str)):
            return False
        for key in ("label", "mountpoint"):
            if node.get(key) is not None and not isinstance(node[key], str):
                return False
        children = node.get("children")
        if children is not None:
            if not isinstance(children, list):
                return False
            pending.extend(children)
        mounts = node.get("mountpoints")
        if mounts is not None and (not isinstance(mounts, list) or any(
                mount is not None and not isinstance(mount, str) for mount in mounts)):
            return False
    return True


# 各步骤 data 的形状必须与对应解析器（parse_sysctl / parse_lsblk）的产出一致。
_STEP_DATA_OK = {"sysctl": _sysctl_data_ok, "lsblk": _lsblk_data_ok}


def valid_step_index(index):
    """向导步骤索引是否指向 STEPS 中的某一步（-1 = 介绍页，len = 完成页都不算）。"""
    return isinstance(index, int) and 0 <= index < len(STEPS)


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
        steps = self.payload.get("steps")
        entry = steps.get(key) if isinstance(steps, dict) else None
        return entry.get("data") if isinstance(entry, dict) else None

    def has(self, key):
        return self.get(key) is not None

    # 以下访问器在 load() 已校验结构的前提下，对手工构造的 payload 再兜一层：
    # 形状不对时只返回空值，绝不抛异常。
    @property
    def sysctl_values(self):
        d = self.get("sysctl")
        values = d.get("values") if isinstance(d, dict) else None
        return values if isinstance(values, dict) else {}

    @property
    def lsblk(self):
        d = self.get("lsblk")
        return d if _lsblk_data_ok(d) else None

    @property
    def collected_at(self):
        v = self.payload.get("collected_at", 0)
        return v if _is_number(v) else 0

    @property
    def collected_boot_id(self):
        v = self.payload.get("boot_id", "")
        return v if isinstance(v, str) else ""

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
        return self._age(self.collected_at)

    def step_age_text(self, key):
        """某一步的数据是多久以前采集的。

        collected_at 记的是「向导最近一次结束」的时刻：重新打开向导只更新了另一步、
        甚至什么都没粘贴就关掉，它都会被刷新成现在。拿它给 sysctl 快照标年龄，十小时
        前的快照会被说成「刚刚」。每一步自己的 at 才是那份数据的采集时刻；旧缓存或
        手工构造的 payload 没有它时退回 collected_at。
        """
        steps = self.payload.get("steps")
        entry = steps.get(key) if isinstance(steps, dict) else None
        at = entry.get("at") if isinstance(entry, dict) else None
        return self._age(at if _is_number(at) and at > 0 else self.collected_at)

    @staticmethod
    def _age(ts):
        if not ts:
            return ""
        try:
            secs = max(0, int(time.time() - ts))
        except (OverflowError, ValueError):     # 超出 float 范围的整数、NaN / Infinity
            return ""
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
        now = int(time.time())
        self.payload.setdefault("steps", {})[key] = {"data": data, "at": now}
        self.payload["collected_at"] = now
        self.payload["boot_id"] = boot_id()
        self.payload["skipped"] = False

    def mark_done(self, skipped=False):
        self.payload["collected_at"] = int(time.time())
        self.payload["boot_id"] = boot_id()
        self.payload["skipped"] = bool(skipped)

    # -- 持久化 ----------------------------------------------------------
    @classmethod
    def load(cls):
        path = os.path.join(_data_dir(create=False), CACHE_NAME)
        try:
            with open(path) as f:
                payload = json.load(f)
        except (OSError, ValueError):
            return cls()
        return cls(payload if _payload_ok(payload) else None)

    def save(self):
        path = os.path.join(_data_dir(), CACHE_NAME)
        xdg.atomic_write_json(path, self.payload)

    @staticmethod
    def clear():
        try:
            os.remove(os.path.join(_data_dir(create=False), CACHE_NAME))
        except OSError:
            pass


# 进程内共享的当前数据（checks.collect() 读取它）
CURRENT = HostData()


def set_current(hd):
    global CURRENT
    CURRENT = hd or HostData()
    return CURRENT
