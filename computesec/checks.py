# -*- coding: utf-8 -*-
"""系统检测：收集数据并与知识库对比。所有函数均不抛异常，失败时给出可解释的结果。"""

import glob
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from . import data, hostdata, hostinfo

IN_FLATPAK = os.path.exists("/.flatpak-info")
MISSING = object()


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def run(cmd, timeout=40):
    """在本沙箱内执行只读命令。返回 (rc, stdout)，不可用返回 (None, '')。

    注意：本程序**已不再使用** flatpak-spawn --host。持有 org.freedesktop.Flatpak
    的 talk 权限等同于沙箱逃逸，对一个只读检测工具而言过于侵入。宿主机上才有的
    信息改由用户在“数据采集向导”中手动执行命令并粘贴（见 hostdata.py）。
    """
    if IN_FLATPAK:
        return None, ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        return None, ""


def read(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def arch():
    m = platform.machine()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    return m


def cpu_vendor():
    info = read("/proc/cpuinfo")
    if "GenuineIntel" in info:
        return "intel"
    if "AuthenticAMD" in info or "HygonGenuine" in info:
        return "amd"
    return None


def cpu_model():
    lines = read("/proc/cpuinfo").splitlines()
    for line in lines:
        if line.lower().startswith("model name"):
            val = line.split(":", 1)[1].strip()
            if val:
                return val
    for prefix in ("hardware", "cpu model", "uarch", "processor"):
        for line in lines:
            k, sep, val = line.partition(":")
            if sep and k.strip().lower() == prefix and val.strip() and not val.strip().isdigit():
                return val.strip()
    soc = read("/sys/devices/soc0/machine").strip()
    return soc or platform.processor() or platform.machine()


# ---------------------------------------------------------------------------
# HSI
# ---------------------------------------------------------------------------
@dataclass
class HsiItem:
    id: str
    name: str
    summary: str
    level: int
    result: str
    flags: set
    uri: str
    info: dict
    passed: bool
    obsoleted: bool


@dataclass
class HsiReport:
    ok: bool
    error: str = ""
    source: str = ""
    host_id: str = ""
    items: list = field(default_factory=list)

    @property
    def active(self):
        return [i for i in self.items if not i.obsoleted]

    @property
    def failed(self):
        return [i for i in self.active if not i.passed]

    @property
    def fixable(self):
        """用户可自行操作修复的项目（操作系统内 / 固件设置中）。"""
        return [i for i in self.failed if i.info.get("fix") and i.info.get("kind") in ("os", "bios")]

    @property
    def score(self):
        act = self.active
        if not self.ok or not act:
            return 0
        return int(100 * sum(1 for i in act if i.passed) / len(act))


def _flags_to_set(v):
    s = set()
    if isinstance(v, int):
        for bit, name in data.HSI_FLAG_BITS.items():
            if v & bit:
                s.add(name)
    elif isinstance(v, (list, tuple)):
        s.update(str(x) for x in v)
    elif isinstance(v, str):
        s.update(x.strip() for x in v.split("|") if x.strip())
    return s


def _result_to_str(v):
    if isinstance(v, int):
        return data.HSI_RESULT_ENUM.get(v, "unknown")
    return str(v or "unknown")


# 尾段过于通用的属性名，单靠最后一段模糊匹配会跨类别误中（例如把任意 *.Enabled 误判为 IntelBootguard.Enabled）
_HSI_GENERIC_TAILS = {
    "Enabled", "Active", "Verified", "Version", "Policy", "Otp", "Acm", "Updates", "Plugins", "Vars", "Pk", "Db",
}


def _lookup_hsi_info(aid):
    aid = data.HSI_ALIASES.get(aid, aid)
    if aid in data.HSI_ATTRS:
        return data.HSI_ATTRS[aid]
    parts = aid.split(".")
    # 优先尝试最后两段精确匹配（如 com.example.IntelCet.Enabled -> IntelCet.Enabled）
    if len(parts) >= 2:
        tail2 = parts[-2:]
        for k, v in data.HSI_ATTRS.items():
            if k.split(".")[-2:] == tail2:
                return v
    # 尝试去掉厂商前缀的单段模糊匹配（排除通用属性名及存在歧义的尾段）
    tail1 = parts[-1]
    if tail1 and tail1 not in _HSI_GENERIC_TAILS:
        matches = [v for k, v in data.HSI_ATTRS.items() if k.split(".")[-1] == tail1]
        if len(matches) == 1:
            return matches[0]
    return {}


def _normalize_attrs(raw):
    items = []
    for a in raw:
        aid = a.get("AppstreamId", "")
        flags = _flags_to_set(a.get("Flags", 0))
        result = _result_to_str(a.get("HsiResult", 0))
        info = _lookup_hsi_info(aid)
        items.append(HsiItem(
            id=aid, name=info.get("name") or a.get("Name", aid), summary=a.get("Summary") or a.get("Description", ""),
            level=int(a.get("HsiLevel", 0) or 0), result=result, flags=flags, uri=a.get("Uri", ""), info=info,
            passed="success" in flags, obsoleted="obsoleted" in flags))
    items.sort(key=lambda i: (i.passed, i.level, i.name))
    return items


def get_hsi() -> HsiReport:
    # 1) D-Bus（Flatpak 内也可用，需 --system-talk-name=org.freedesktop.fwupd）
    try:
        import gi
        from gi.repository import Gio, GLib
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        proxy = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None, "org.freedesktop.fwupd", "/",
                                       "org.freedesktop.fwupd", None)
        res = proxy.call_sync("GetHostSecurityAttrs", None, Gio.DBusCallFlags.NONE, 60000, None)
        raw = res.unpack()[0]
        host_id = ""
        p = proxy.get_cached_property("HostSecurityId")
        if p is not None:
            host_id = p.unpack()
        if not host_id:
            try:
                pres = bus.call_sync(
                    "org.freedesktop.fwupd", "/", "org.freedesktop.DBus.Properties", "Get",
                    GLib.Variant("(ss)", ("org.freedesktop.fwupd", "HostSecurityId")),
                    GLib.VariantType("(v)"), Gio.DBusCallFlags.NONE, 5000, None)
                host_id = pres.unpack()[0] or ""
            except Exception:
                pass
        if raw:
            return HsiReport(ok=True, source="fwupd D-Bus", host_id=host_id, items=_normalize_attrs(raw))
    except Exception:
        pass
    # 2) fwupdmgr CLI
    rc, out = run(["fwupdmgr", "security", "--json"])
    if out.strip():
        try:
            j = json.loads(out)
            raw = None
            for key in ("SecurityAttributes", "HostSecurityAttributes", "Attributes"):
                if isinstance(j.get(key), list):
                    raw = j[key]
                    break
            if raw is None:
                for v in j.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict) and "AppstreamId" in v[0]:
                        raw = v
                        break
            if raw:
                host_id = j.get("HostSecurityId", "")
                if not host_id:
                    _, txt = run(["fwupdmgr", "security"])
                    m = re.search(r"HSI:\S+(?:\s*\([^)]*\))?", txt or "")
                    host_id = m.group(0) if m else ""
                return HsiReport(ok=True, source="fwupdmgr", host_id=host_id, items=_normalize_attrs(raw))
        except ValueError:
            pass
    err = "无法获取 HSI 数据。请确认已安装并启动 fwupd（sudo systemctl start fwupd）。"
    if IN_FLATPAK:
        err += " Flatpak 版本通过 D-Bus 读取，需要 org.freedesktop.fwupd 的系统总线访问权限（可用 Flatseal 查看）。"
    return HsiReport(ok=False, error=err)


# ---------------------------------------------------------------------------
# 内核参数
# ---------------------------------------------------------------------------
@dataclass
class ParamItem:
    key: str
    expected: Optional[str]
    actual: object          # MISSING / None (无值) / str
    status: str             # ok / missing / wrong / na
    desc: str
    note: str = ""
    cpu: Optional[str] = None

    @property
    def token(self):
        return self.key if self.expected is None else f"{self.key}={self.expected}"


@dataclass
class CmdlineReport:
    arch: str
    cpu: Optional[str]
    cmdline: str
    items: list

    @property
    def applicable(self):
        return [i for i in self.items if i.status != "na"]

    @property
    def missing(self):
        return [i for i in self.items if i.status in ("missing", "wrong")]

    @property
    def score(self):
        ap = self.applicable
        return int(100 * sum(1 for i in ap if i.status == "ok") / len(ap)) if ap else 0


def _norm_key(k):
    return k.replace("-", "_")


# 内核参数别名（如 slub_debug 与 slab_debug 在 mm/slub.c 中同义）
_CMDLINE_KEY_ALIASES = {
    "slub_debug": "slab_debug",
}
# 内核用 kstrtobool 解析的 early_param 型布尔参数，on/1/y 与 off/0/n 等价。
# 这类参数必须写成 key=value；省略 = 的裸 token 无效（内核保持默认值）。
# 注意：x86 的 pti= 只接受 on/off/auto（strcmp 精确匹配），并不使用 kstrtobool，不能放在这里。
_CMDLINE_BOOL_KEYS = {
    "init_on_alloc", "init_on_free", "iommu.passthrough", "iommu.strict",
    "page_alloc.shuffle", "kpti", "random.trust_bootloader", "random.trust_cpu",
    "randomize_kstack_offset", "irqchip.gicv3_pseudo_nmi",
}
# module_param(bool) 型布尔参数：同样经 kstrtobool 解析 on/1/y 与 off/0/n，
# 但 cmdline 上省略 = 的裸 token 会被内核置为真（param_set_bool(val=NULL) → 1）。
_CMDLINE_MODULE_BOOL_KEYS = {
    "kvm_amd.sev", "kvm_amd.sev_es", "kvm_amd.sev_snp", "kvm.mitigate_smt_rsb",
    "module.sig_enforce", "bdev_allow_write_mounted",
}
_BOOL_TRUE = {"1", "on", "y", "yes", "true"}
_BOOL_FALSE = {"0", "off", "n", "no", "false"}

# mitigations= 的合法取值及缓解强度。kernel/cpu.c 的 mitigations_parse_cmdline()
# 对三个值做 strcmp 精确匹配（"nosmt,auto" 等非常规顺序会被整体忽略并保持默认），
# 因此只能按强度序比较，不能做顺序无关的集合比较。
_MITIGATIONS_RANK = {"off": 0, "auto": 1, "auto,nosmt": 2}


def _cmdline_bool_norm(v):
    low = v.strip().lower()
    if low in _BOOL_TRUE:
        return "1"
    if low in _BOOL_FALSE:
        return "0"
    return v.strip()


def _cmdline_value_ok(key, actual, expected):
    if expected is None:
        return actual is not MISSING
    if actual is MISSING:
        return False
    nk = _norm_key(key)
    if actual is None:
        # 裸 token（无 =）仅对 module_param 型布尔参数等价于真；
        # early_param 型会解析失败，内核保持默认值，不能视为已启用。
        if nk not in _CMDLINE_MODULE_BOOL_KEYS:
            return False
        actual = "1"
    if actual == expected:
        return True
    if nk == "efi":
        opts = {x.strip() for x in actual.split(",") if x.strip()}
        return expected in opts
    if nk == "slab_debug":
        # 仅纯增量调试选项可按超集处理。O 会对部分 cache 关闭调试，不能视为增强；
        # 内核对这些单字母选项按大小写敏感解析，因此不能把实际值转成大写。
        if "," not in actual:
            flags = set(actual)
            if flags and flags.issubset(set("FZPUTA")) and set(expected).issubset(flags):
                return True
        return False
    if nk == "mitigations":
        # 仅接受内核合法取值；实际值不弱于期望值即通过（如 aarch64 期望 auto，
        # 用户显式写了更强的 auto,nosmt 同样是内核接受的合法配置）。
        rank_a = _MITIGATIONS_RANK.get(actual)
        rank_e = _MITIGATIONS_RANK.get(expected)
        return rank_a is not None and rank_e is not None and rank_a >= rank_e
    # l1tf= 由内核在固定选项列表（off/flush/flush,nosmt/flush,nowarn/full/full,force）
    # 中做精确匹配，任何改写顺序的值都会被忽略，因此不做集合比较，仅精确匹配。
    if nk in _CMDLINE_BOOL_KEYS or nk in _CMDLINE_MODULE_BOOL_KEYS:
        return _cmdline_bool_norm(actual) == _cmdline_bool_norm(expected)
    return False


def get_cmdline_report() -> CmdlineReport:
    cmdline = read("/proc/cmdline").strip()
    present = {}
    for tok in cmdline.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            nk = _norm_key(k)
            nk = _CMDLINE_KEY_ALIASES.get(nk, nk)
            if nk == "efi" and present.get(nk):
                present[nk] = f"{present[nk]},{v}"
            else:
                present[nk] = v
        else:
            nk = _norm_key(tok)
            nk = _CMDLINE_KEY_ALIASES.get(nk, nk)
            present[nk] = None
    ar, cv = arch(), cpu_vendor()
    items = []
    for p in data.KERNEL_PARAMS:
        if ar not in p["arch"]:
            continue
        exp = p["value"]
        if isinstance(exp, dict):
            exp = exp.get(ar)
        nk = _norm_key(p["key"])
        actual = present.get(nk, MISSING)
        if p.get("cpu") and p["cpu"] != cv and (cv is not None or actual is MISSING):
            status = "na"
        elif actual is MISSING:
            status = "missing"
        elif _cmdline_value_ok(p["key"], actual, exp):
            status = "ok"
        else:
            status = "wrong"
        items.append(ParamItem(key=p["key"], expected=exp, actual=actual, status=status, desc=p["desc"],
                               note=p.get("note", ""), cpu=p.get("cpu")))
    return CmdlineReport(arch=ar, cpu=cv, cmdline=cmdline, items=items)


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------
@dataclass
class SysctlItem:
    key: str
    expected: str
    cmp: str
    actual: dict            # 具体键 -> 值 (None 表示不存在)
    status: str             # ok / missing / na / unknown
    desc: str
    note: str = ""
    source: str = ""        # proc / 用户提供

    @property
    def actual_text(self):
        if self.status == "unknown":
            return "（无法读取，需要 root 权限）"
        if not self.actual:
            return "（内核不支持）"
        vals = {v for v in self.actual.values()}
        if len(vals) == 1:
            v = vals.pop()
            return v if v is not None else "（不存在）"
        return ", ".join(f"{k.split('.')[-2]}={v}" for k, v in sorted(self.actual.items()))


@dataclass
class SysctlReport:
    arch: str
    groups: list        # [(title, [SysctlItem])]
    source: str = "/proc/sys"
    user_supplied: bool = False

    @property
    def all_items(self):
        return [i for _, items in self.groups for i in items]

    @property
    def missing(self):
        return [i for i in self.all_items if i.status == "missing"]

    @property
    def unknown(self):
        """因权限不足而无法判定的条目。"""
        return [i for i in self.all_items if i.status == "unknown"]

    @property
    def score(self):
        ap = [i for i in self.all_items if i.status not in ("na", "unknown")]
        return int(100 * sum(1 for i in ap if i.status == "ok") / len(ap)) if ap else 0


def _sysctl_paths(key):
    path = "/proc/sys/" + key.replace(".", "/")
    if "*" in key:
        return sorted(glob.glob(path))
    return [path] if os.path.exists(path) else []


# 少数 sysctl 读出来是单词、写进去却是数字，两者含义相同。
# 例如 fs.binfmt_misc.status：内核 bm_status_read() 固定返回 "enabled"/"disabled"，
# 而 bm_status_write() 只接受 0 / 1 / -1（parse_command()，写单词会得到 -EINVAL）。
# 因此 "disabled" 与我们期望的 "0" 完全等价，不做归一化会把已加固的机器误报为未设置。
_SYSCTL_WORD_ALIASES = {
    "disabled": "0",
    "enabled": "1",
}


def _sysctl_norm(v):
    """把读到的值归一化，便于与期望值比较。"""
    v = " ".join(v.split())
    return _SYSCTL_WORD_ALIASES.get(v.lower(), v)


def _sysctl_value_ok(actual, expected, cmp):
    if actual is None:
        return False
    a = _sysctl_norm(actual)
    e = _sysctl_norm(expected)
    if cmp == "ge":
        try:
            return int(a) >= int(e)
        except ValueError:
            return a == e
    return a == e


def _sysctl_from_proc(key):
    """从 /proc/sys 读取。返回 (actual, unreadable)。

    unreadable=True 表示文件存在但因权限（EACCES/EPERM）读不到，
    典型例子是 vm.mmap_rnd_bits / vm.mmap_rnd_compat_bits（0600 root:root）。
    """
    actual, unreadable = {}, False
    for p in _sysctl_paths(key):
        # 与 procps sysctl 保持一致：目录名自带的 '.' 转为 '/'（如 VLAN 接口 eth0.100 -> eth0/100）
        rel = p[len("/proc/sys/"):]
        k = ".".join(part.replace(".", "/") for part in rel.split("/"))
        try:
            with open(p) as f:
                actual[k] = f.read().strip()
        except PermissionError:
            unreadable = True
        except OSError:
            actual[k] = None
    return actual, unreadable


def get_sysctl_report() -> SysctlReport:
    hd = hostdata.CURRENT
    user_values = hd.sysctl_values
    groups = []
    for title, entries in data.SYSCTL_GROUPS:
        items = []
        for e in entries:
            key = e["key"]
            cmp = e.get("cmp", "eq")
            actual, unreadable = _sysctl_from_proc(key)
            source = "proc"
            # 用户提供的 sysctl -a（以 root 执行、在宿主机上执行）优先级更高：
            # 它既能补上权限不足的条目，也能补上被 Flatpak 沙箱屏蔽或隔离的条目。
            if user_values:
                supplied = hd.sysctl_lookup(key)
                if supplied:
                    if IN_FLATPAK:
                        # 沙箱里的 /proc/sys 可能属于隔离视图，不能混入宿主机快照。
                        actual = dict(supplied)
                        source = "用户提供"
                    else:
                        # 原生环境保留快照采集后新出现的接口等条目，用户值仅覆盖同名键。
                        merged = dict(actual)
                        merged.update(supplied)
                        if unreadable or merged != actual:
                            source = "用户提供"
                        actual = merged
                    unreadable = False
            if unreadable and not actual:
                status = "unknown"
            elif not actual or all(v is None for v in actual.values()):
                status = "na"
            elif all(_sysctl_value_ok(v, e["value"], cmp) for v in actual.values()):
                status = "ok"
            else:
                status = "missing"
            items.append(SysctlItem(key=key, expected=e["value"], cmp=cmp, actual=actual, status=status,
                                    desc=e["desc"], note=e.get("note", ""), source=source))
        groups.append((title, items))
    src = "/proc/sys + 用户提供的 sysctl -a" if user_values else "/proc/sys"
    return SysctlReport(arch=arch(), groups=groups, source=src, user_supplied=bool(user_values))


# ---------------------------------------------------------------------------
# 硬件品牌
# ---------------------------------------------------------------------------
@dataclass
class HardwareReport:
    sys_vendor: str
    product: str
    board_vendor: str
    bios_vendor: str
    bios_version: str
    model: str
    vendor: dict
    matched_on: str

    @property
    def score(self):
        return data.RATING_SCORE.get(self.vendor["rating"], 50)


def _vendor_kw_match(kw, text):
    # 短缩写（如 "hp"、"msi"）按单词边界匹配，避免把 "touchpad" 等含 "hp" 的普通单词误判为 HP
    if len(kw) <= 3 and kw.isalnum():
        return bool(re.search(rf"\b{re.escape(kw)}\b", text))
    return kw in text


def get_hardware() -> HardwareReport:
    dmi = lambda n: read(f"/sys/class/dmi/id/{n}").strip()
    sv, pn, bv, biosv, biosver = dmi("sys_vendor"), dmi("product_name"), dmi("board_vendor"), dmi("bios_vendor"), dmi("bios_version")
    model = read("/proc/device-tree/model").strip("\x00\n ")
    # D-Bus hostname1 也提供厂商/型号/固件版本（宿主机视角），用于补全沙箱内读不到的字段
    try:
        ident = hostinfo.get_identity()
        sv = sv or ident.hw_vendor
        pn = pn or ident.hw_model
        biosver = biosver or ident.firmware_version
    except Exception:
        pass
    candidates = [("系统厂商", sv), ("产品名称", pn), ("主板厂商", bv), ("设备型号", model)]
    vendor, matched = data.DEFAULT_VENDOR, ""
    for label, text in candidates:
        t = (text or "").lower()
        if not t:
            continue
        for v in data.VENDORS:
            if any(_vendor_kw_match(m, t) for m in v["match"]):
                vendor, matched = v, f"{label}: {text}"
                break
        if matched:
            break
    return HardwareReport(sys_vendor=sv, product=pn, board_vendor=bv, bios_vendor=biosv, bios_version=biosver,
                          model=model, vendor=vendor, matched_on=matched)


# ---------------------------------------------------------------------------
# 使用习惯
# ---------------------------------------------------------------------------
@dataclass
class HabitCheck:
    key: str
    title: str
    status: str         # good / warn / bad / unknown
    summary: str
    details: list       # [str]
    advice: str


@dataclass
class HabitsReport:
    checks: list

    @property
    def score(self):
        pts = {"good": 100, "unknown": 60, "warn": 40, "bad": 0}
        return int(sum(pts.get(c.status, 0) for c in self.checks) / len(self.checks)) if self.checks else 0


def _flatpak_apps():
    apps, source = set(), ""
    dirs = ["/var/lib/flatpak/app", os.path.expanduser("~/.local/share/flatpak/app")]
    for d in dirs:
        try:
            for name in os.listdir(d):
                if os.path.isdir(os.path.join(d, name)):
                    apps.add(name)
            source = "目录扫描"
        except OSError:
            pass
    if not apps:
        rc, out = run(["flatpak", "list", "--app", "--columns=application"])
        if out:
            apps.update(l.strip() for l in out.splitlines() if l.strip() and "." in l)
            source = "flatpak list"
        elif rc == 0 and not source:
            source = "flatpak list"
    return apps, source


def check_flatpak() -> HabitCheck:
    apps, source = _flatpak_apps()
    user_apps = sorted(a for a in apps if not a.startswith(data.FLATPAK_EXCLUDE_PREFIXES) and not a.endswith(".BaseApp"))
    advice = ("使用梨的 harden-flatpak 项目（{url}）默认拒绝除 Wayland 与 dri 之外的所有权限，"
              "配合 Flatseal 按需为每个应用开放最少的权限，可以使 flatpak 的安全性更上一层楼。向应用授予权限时，尽量不要授予 D-Bus（session-bus / system-bus）和进程间通信 (ipc) 等敏感权限。").format(url=data.HARDEN_FLATPAK_URL)
    if not source:
        return HabitCheck("flatpak", "Flatpak 应用使用情况", "unknown", "未能读取 Flatpak 安装列表",
                          ["可能未安装 flatpak，或本程序没有访问权限。"], "建议安装 flatpak 并尽量以 Flatpak 形式安装软件。" + "\n\n" + advice)
    details = [f"共检测到 {len(apps)} 个 Flatpak 应用（排除 runtime、桌面环境自带包以及 ComputeSec 后：{len(user_apps)} 个）。"]
    if len(user_apps) < 5:
        return HabitCheck("flatpak", "Flatpak 应用使用情况", "warn", f"仅有 {len(user_apps)} 个用户安装的 Flatpak 应用", details,
                          "建议尽量使用 Flatpak 形式的软件。Flatpak 通过 bubblewrap 沙箱隔离应用，即便软件具有恶意或被攻击者控制，也难以触及您的系统和敏感数据。\n\n" + advice)
    return HabitCheck("flatpak", "Flatpak 应用使用情况", "good", f"很棒！您已安装 {len(user_apps)} 个 Flatpak 应用", details,
                      "您在使用沙箱化软件方面做得很好，请继续保持！\n\n" + advice)


def check_uptime() -> HabitCheck:
    try:
        secs = float(read("/proc/uptime").split()[0])
    except (ValueError, IndexError):
        return HabitCheck("uptime", "系统运行时间", "unknown", "无法读取 /proc/uptime", [], "")
    days, rem = divmod(int(secs), 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    text = f"{days} 天 {hours} 小时 {mins} 分钟" if days else f"{hours} 小时 {mins} 分钟"
    if secs > 86400:
        return HabitCheck("uptime", "系统运行时间", "warn", f"已连续运行 {text}",
                          ["长时间不重启意味着内核与固件更新没有生效，运行中的进程仍在使用旧版本的库。"],
                          "建议现在进行一次系统更新并重启：Fedora 使用 `sudo dnf upgrade --refresh`（Silverblue: `rpm-ostree upgrade`），Debian/Ubuntu 使用 `sudo apt update && sudo apt full-upgrade`，Arch 使用 `sudo pacman -Syu`，别忘了 `flatpak update` 与 `fwupdmgr update`。")
    return HabitCheck("uptime", "系统运行时间", "good", f"运行时间 {text}，非常好",
                      ["您近期重启过系统，内核与固件更新能够及时生效。"], "请继续保持勤更新、勤重启的好习惯！")


def _usb_devices():
    devs = []
    for d in glob.glob("/sys/bus/usb/devices/*"):
        vid = read(os.path.join(d, "idVendor")).strip()
        if not vid:
            continue
        pid = read(os.path.join(d, "idProduct")).strip().lower()
        product = read(os.path.join(d, "product")).strip()
        manufacturer = read(os.path.join(d, "manufacturer")).strip()
        # 若 sysfs 字符串为空，尝试从 /run/udev/data/+usb:<dev> 补全 hwdb 名称
        if not product or not manufacturer:
            udev_txt = read(f"/run/udev/data/+usb:{os.path.basename(d)}")
            if udev_txt:
                if not manufacturer:
                    m_v = re.search(r"^E:ID_VENDOR_FROM_DATABASE=(.+)$", udev_txt, re.M)
                    if m_v:
                        manufacturer = m_v.group(1).strip()
                if not product:
                    m_p = re.search(r"^E:ID_MODEL_FROM_DATABASE=(.+)$", udev_txt, re.M)
                    if m_p:
                        product = m_p.group(1).strip()
        devs.append(dict(vid=vid.lower(), pid=pid, product=product, manufacturer=manufacturer,
                         cls=read(os.path.join(d, "bDeviceClass")).strip()))
    if devs:
        return devs, "sysfs"
    rc, out = run(["lsusb"])
    for line in out.splitlines():
        m = re.match(r"Bus \d+ Device \d+: ID ([0-9a-f]{4}):([0-9a-f]{4})\s*(.*)", line)
        if m:
            devs.append(dict(vid=m.group(1), pid=m.group(2), product=m.group(3), manufacturer="", cls=""))
    return devs, ("lsusb" if devs else "")


def check_usb() -> HabitCheck:
    devs, source = _usb_devices()
    if not source:
        return HabitCheck("usb", "2.4G 无线接收器", "unknown", "无法枚举 USB 设备", [], "")
    suspects = []
    dedicated_vids = getattr(data, "USB_24G_DEDICATED_VENDORS", set())
    for d in devs:
        if d["vid"] in ("1d6b",):   # Linux Foundation root hubs
            continue
        text = f"{d['manufacturer']} {d['product']}".lower()
        # 排除笔记本内置摄像头等视频设备（Sonix 0c45 / Sunplus 1bcf 常用于内置 UVC 摄像头）
        if any(w in text for w in ("webcam", "camera", "uvc", "integrated_webcam")):
            continue
        hit = None
        if d["vid"] == "046d":
            if d["pid"] in data.LOGITECH_BOLT_PIDS:
                hit = "Logitech Bolt 接收器（使用 BLE 安全连接加密，风险较低，但仍建议有线）"
            elif d["pid"] in data.LOGITECH_UNIFYING_PIDS or any(k in text for k in ("unifying", "lightspeed", "receiver", "nano")):
                hit = "Logitech Unifying/Lightspeed 接收器（曾曝出 MouseJack、KeyJack 等密钥提取与按键注入漏洞）"
        elif d["vid"] in dedicated_vids and any(k in text for k in data.USB_24G_KEYWORDS + ["mouse", "keyboard", "composite"]):
            hit = f"{data.USB_24G_VENDORS[d['vid']]} 2.4G 接收器"
        elif d["vid"] in data.USB_24G_VENDORS and any(k in text for k in data.USB_24G_KEYWORDS):
            hit = f"{data.USB_24G_VENDORS[d['vid']]} 2.4G 接收器"
        elif any(k in text for k in data.USB_24G_KEYWORDS):
            hit = "疑似 2.4G 无线接收器"
        if hit:
            desc_name = " ".join(x for x in (d["manufacturer"], d["product"]) if x)
            suspects.append(f"{d['vid']}:{d['pid']}" + (f" {desc_name}" if desc_name else "") + f" — {hit}")
    if suspects:
        return HabitCheck("usb", "2.4G 无线接收器", "bad", f"发现 {len(suspects)} 个 2.4G 无线接收器", suspects,
                          "绝大多数 2.4G 无线键鼠不加密或使用弱加密，攻击者在数十米外即可嗅探您输入的每一个字符（包括密码、密钥口令），甚至注入按键（MouseJack）。"
                          "高安全性计算请改用有线键鼠；支持蓝牙 LE Secure Connections 的输入设备是次优选择。")
    return HabitCheck("usb", "2.4G 无线接收器", "good", "未发现 2.4G 无线接收器", [f"共枚举 {len(devs)} 个 USB 设备（{source}）。"],
                      "很好！有线或支持蓝牙 LE Secure Connections 的输入设备能有效防止按键被嗅探，请继续保持。")


def _ntfs_from_lsblk_json(j):
    found = []

    def walk(nodes):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            if (n.get("fstype") or "").lower() in ("ntfs", "ntfs3", "exfat-ntfs"):
                mp = n.get("mountpoint")
                if not mp and isinstance(n.get("mountpoints"), list):
                    mp = ", ".join(str(x) for x in n["mountpoints"] if x)
                found.append(f"/dev/{n.get('name')}  {n.get('size', '')}  标签: {n.get('label') or '-'}  挂载: {mp or '-'}")
            walk(n.get("children", []) or [])

    if isinstance(j, dict) and isinstance(j.get("blockdevices"), list):
        walk(j["blockdevices"])
    return found


def _ntfs_partitions():
    found, source = [], ""
    # 1) 用户在采集向导中提供的 lsblk -J 输出（Flatpak 内唯一可靠的来源）
    supplied = hostdata.CURRENT.lsblk
    if supplied:
        found = _ntfs_from_lsblk_json(supplied)
        source = "lsblk（用户提供）"
        return found, source
    rc, out = run(["lsblk", "-J", "-o", "NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT"])
    if out.strip():
        try:
            found = _ntfs_from_lsblk_json(json.loads(out))
            source = "lsblk"
        except ValueError:
            pass
    if not source:
        has_udev_fs = False
        seen_devices = set()
        for f in sorted(glob.glob("/run/udev/data/b*")):
            content = read(f)
            if "E:ID_FS_TYPE=" in content:
                has_udev_fs = True
            if re.search(r"^E:ID_FS_TYPE=(ntfs3?|exfat-ntfs)\s*$", content, re.M | re.I):
                name = re.search(r"^E:DEVNAME=(\S+)", content, re.M)
                devname = name.group(1) if name else ""
                if not devname:
                    uevent = read(f"/sys/dev/block/{os.path.basename(f)[1:]}/uevent")
                    m_dev = re.search(r"^DEVNAME=(\S+)", uevent, re.M)
                    devname = f"/dev/{m_dev.group(1)}" if m_dev else f
                label = re.search(r"^E:ID_FS_LABEL=(\S+)", content, re.M)
                found.append(f"{devname}  标签: {label.group(1) if label else '-'}")
                seen_devices.add(devname)
                source = "udev"
        if has_udev_fs and not source:
            source = "udev"
        # udev 数据库可能缺少后挂载设备的记录；即使已有 udev 数据，也必须用挂载表补全。
        for line in read("/proc/mounts").splitlines():
            parts = line.split()
            if len(parts) > 2 and (parts[2] in ("ntfs", "ntfs3", "fuse.ntfs", "fuse.ntfs-3g")
                                   or (parts[2] == "fuseblk" and parts[0].startswith("/dev/"))):
                if parts[0] not in seen_devices:
                    found.append(f"{parts[0]} 挂载于 {parts[1]} ({parts[2]})")
                    seen_devices.add(parts[0])
        source = f"{source} + /proc/mounts" if source else "/proc/mounts"
    return found, source


def _windows_installed():
    hints = []
    for p in ("/boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", "/efi/EFI/Microsoft/Boot/bootmgfw.efi",
              "/boot/EFI/Microsoft/Boot/bootmgfw.efi"):
        if os.path.exists(p):
            hints.append(f"发现 Windows 引导管理器：{p}")
    for f in glob.glob("/sys/firmware/efi/efivars/Boot[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]-*"):
        if "Windows Boot Manager".encode("utf-16-le") in read_bytes(f):
            hints.append(f"UEFI 启动项中存在 Windows Boot Manager（{os.path.basename(f)[:8]}）")
            break
    return hints


def check_ntfs() -> HabitCheck:
    parts, source = _ntfs_partitions()
    win = _windows_installed()
    if not parts and not win and IN_FLATPAK and not hostdata.CURRENT.has("lsblk"):
        return HabitCheck("ntfs", "NTFS / Windows 检测", "unknown", "未能完整枚举磁盘分区",
                          ["Flatpak 沙箱内看不到宿主机的块设备信息。"],
                          "请从主菜单选择「重新采集系统数据」，按向导执行 lsblk 并粘贴结果，即可完成此项检测。")
    if parts or win:
        details = parts + win
        if win:
            summary = "检测到 Windows 安装" + (f"及 {len(parts)} 个 NTFS 分区" if parts else "")
            advice = ("Windows 是闭源系统，无法审计，存在被植入后门的风险，不应当用于高安全性计算。"
                      "更严重的是：当前设备上安装了 Windows，那么 Windows 中的恶意软件或后门可能已经污染了这套 Linux 环境本身、引导分区甚至固件（例如篡改 EFI 分区、写入 UEFI 变量、乃至利用 SMM 漏洞向固件植入 Rootkit）。"
                      "在完全重装系统（最好同时重新刷写固件并重置 UEFI 密钥）之前，此硬件不应当用于高安全性计算。")
        else:
            summary = f"检测到 {len(parts)} 个 NTFS 分区"
            advice = ("NTFS 分区通常意味着与 Windows 共用数据。Windows 无法审计、存在后门风险，不应用于高安全性计算；"
                      "若该分区曾在 Windows 中使用，其中的文件（尤其是可执行文件、Office 文档、宏）可能已被污染。建议将必要数据迁移到加密的 Linux 文件系统（LUKS + btrfs/ext4）后移除 NTFS 分区。")
        return HabitCheck("ntfs", "NTFS / Windows 检测", "bad", summary, details, advice)
    return HabitCheck("ntfs", "NTFS / Windows 检测", "good", "未发现 NTFS 分区或 Windows 安装", [f"检测方式：{source or '综合'}"],
                      "太棒了！纯 Linux 环境避免了闭源系统带来的不可审计风险，请继续保持。")


def get_habits() -> HabitsReport:
    return HabitsReport(checks=[check_flatpak(), check_uptime(), check_usb(), check_ntfs()])


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
@dataclass
class Report:
    hsi: HsiReport
    cmdline: CmdlineReport
    sysctl: SysctlReport
    hardware: HardwareReport
    habits: HabitsReport
    arch: str
    cpu: str
    os_name: str
    kernel: str
    in_flatpak: bool
    identity: object = None         # hostinfo.HostIdentity
    hostdata: object = None         # hostdata.HostData

    @property
    def kernel_score(self):
        return (self.cmdline.score + self.sysctl.score) // 2

    @property
    def overall(self):
        parts = [self.hsi.score if self.hsi.ok else 50, self.kernel_score, self.hardware.score, self.habits.score]
        return sum(parts) // len(parts)


def _safe(fn, fallback):
    try:
        return fn()
    except Exception as e:  # 保证 UI 永远能渲染
        return fallback(e)


def collect() -> Report:
    ident = _safe(hostinfo.get_identity, lambda e: hostinfo.HostIdentity(dbus_error=str(e)))
    return Report(
        hsi=_safe(get_hsi, lambda e: HsiReport(ok=False, error=f"检测时出错：{e}")),
        cmdline=_safe(get_cmdline_report, lambda e: CmdlineReport(arch=arch(), cpu=cpu_vendor(), cmdline=f"读取失败：{e}", items=[])),
        sysctl=_safe(get_sysctl_report, lambda e: SysctlReport(arch=arch(), groups=[])),
        hardware=_safe(get_hardware, lambda e: HardwareReport("", "", "", "", "", "", data.DEFAULT_VENDOR, "")),
        habits=_safe(get_habits, lambda e: HabitsReport(checks=[HabitCheck("err", "检测出错", "unknown", str(e), [], "")])),
        arch=arch(), cpu=cpu_model(), os_name=ident.os_name, kernel=ident.kernel, in_flatpak=IN_FLATPAK,
        identity=ident, hostdata=hostdata.CURRENT,
    )
