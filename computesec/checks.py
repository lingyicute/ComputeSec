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

from . import data

IN_FLATPAK = os.path.exists("/.flatpak-info")
MISSING = object()


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def run(cmd, timeout=40):
    """执行命令；Flatpak 内通过 flatpak-spawn --host 在宿主机执行。返回 (rc, stdout)，不可用返回 (None, '')。"""
    if IN_FLATPAK:
        cmd = ["flatpak-spawn", "--host"] + list(cmd)
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
    for line in read("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor() or platform.machine()


def os_release():
    d = {}
    for line in read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


def kernel_version():
    return platform.release()


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


def _lookup_hsi_info(aid):
    aid = data.HSI_ALIASES.get(aid, aid)
    if aid in data.HSI_ATTRS:
        return data.HSI_ATTRS[aid]
    # 尝试去掉厂商前缀的模糊匹配
    for k, v in data.HSI_ATTRS.items():
        if k.split(".")[-1] == aid.split(".")[-1]:
            return v
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
        from gi.repository import Gio
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        proxy = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None, "org.freedesktop.fwupd", "/",
                                       "org.freedesktop.fwupd", None)
        res = proxy.call_sync("GetHostSecurityAttrs", None, Gio.DBusCallFlags.NONE, 60000, None)
        raw = res.unpack()[0]
        host_id = ""
        p = proxy.get_cached_property("HostSecurityId")
        if p is not None:
            host_id = p.unpack()
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
    if rc is None and IN_FLATPAK:
        err += " Flatpak 版本需要 org.freedesktop.fwupd D-Bus 访问权限或 flatpak-spawn 权限。"
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


def get_cmdline_report() -> CmdlineReport:
    cmdline = read("/proc/cmdline").strip()
    present = {}
    for tok in cmdline.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            present[_norm_key(k)] = v
        else:
            present[_norm_key(tok)] = None
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
        if p.get("cpu") and cv and p["cpu"] != cv:
            status = "na"
        elif actual is MISSING:
            status = "missing"
        elif exp is None:
            status = "ok"
        elif actual == exp:
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
    status: str             # ok / missing / na
    desc: str
    note: str = ""

    @property
    def actual_text(self):
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

    @property
    def all_items(self):
        return [i for _, items in self.groups for i in items]

    @property
    def missing(self):
        return [i for i in self.all_items if i.status == "missing"]

    @property
    def score(self):
        ap = [i for i in self.all_items if i.status != "na"]
        return int(100 * sum(1 for i in ap if i.status == "ok") / len(ap)) if ap else 0


def _sysctl_paths(key):
    path = "/proc/sys/" + key.replace(".", "/")
    if "*" in key:
        return sorted(glob.glob(path))
    return [path] if os.path.exists(path) else []


def _sysctl_value_ok(actual, expected, cmp):
    if actual is None:
        return False
    a = " ".join(actual.split())
    e = " ".join(expected.split())
    if cmp == "ge":
        try:
            return int(a) >= int(e)
        except ValueError:
            return a == e
    return a == e


def get_sysctl_report() -> SysctlReport:
    groups = []
    for title, entries in data.SYSCTL_GROUPS:
        items = []
        for e in entries:
            paths = _sysctl_paths(e["key"])
            actual = {}
            for p in paths:
                k = p[len("/proc/sys/"):].replace("/", ".")
                try:
                    with open(p) as f:
                        actual[k] = f.read().strip()
                except OSError:
                    actual[k] = None
            cmp = e.get("cmp", "eq")
            if not actual:
                status = "na"
            elif all(_sysctl_value_ok(v, e["value"], cmp) for v in actual.values()):
                status = "ok"
            else:
                status = "missing"
            items.append(SysctlItem(key=e["key"], expected=e["value"], cmp=cmp, actual=actual, status=status,
                                    desc=e["desc"], note=e.get("note", "")))
        groups.append((title, items))
    return SysctlReport(arch=arch(), groups=groups)


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


def get_hardware() -> HardwareReport:
    dmi = lambda n: read(f"/sys/class/dmi/id/{n}").strip()
    sv, pn, bv, biosv, biosver = dmi("sys_vendor"), dmi("product_name"), dmi("board_vendor"), dmi("bios_vendor"), dmi("bios_version")
    model = read("/proc/device-tree/model").strip("\x00\n ")
    candidates = [("系统厂商", sv), ("产品名称", pn), ("主板厂商", bv), ("设备型号", model)]
    vendor, matched = data.DEFAULT_VENDOR, ""
    for label, text in candidates:
        t = (text or "").lower()
        if not t:
            continue
        for v in data.VENDORS:
            if any(m in t for m in v["match"]):
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
    return apps, source


def check_flatpak() -> HabitCheck:
    apps, source = _flatpak_apps()
    user_apps = sorted(a for a in apps if not a.startswith(data.FLATPAK_EXCLUDE_PREFIXES))
    advice = ("使用梨的 harden-flatpak 项目（{url}）默认拒绝除 Wayland 与 dri 之外的所有权限，"
              "配合 Flatseal 按需为每个应用开放最少的权限，可以使 flatpak 的安全性更上一层楼。向应用授予权限时，尽量不要授予 D-Bus（session-bus / system-bus）与进程间通信 (ipc) 等敏感权限。").format(url=data.HARDEN_FLATPAK_URL)
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
        devs.append(dict(vid=vid.lower(), pid=read(os.path.join(d, "idProduct")).strip().lower(),
                         product=read(os.path.join(d, "product")).strip(), manufacturer=read(os.path.join(d, "manufacturer")).strip(),
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
    for d in devs:
        if d["vid"] in ("1d6b",):   # Linux Foundation root hubs
            continue
        text = f"{d['manufacturer']} {d['product']}".lower()
        hit = None
        if d["vid"] == "046d":
            if d["pid"] in data.LOGITECH_BOLT_PIDS:
                hit = "Logitech Bolt 接收器（使用 BLE 安全连接加密，风险较低，但仍建议有线）"
            elif d["pid"] in data.LOGITECH_UNIFYING_PIDS or any(k in text for k in ("unifying", "lightspeed", "receiver", "nano")):
                hit = "Logitech Unifying/Lightspeed 接收器（曾曝出 MouseJack、KeyJack 等密钥提取与按键注入漏洞）"
        elif d["vid"] in data.USB_24G_VENDORS and any(k in text for k in data.USB_24G_KEYWORDS + ["mouse", "keyboard", "composite"]):
            hit = f"{data.USB_24G_VENDORS[d['vid']]} 2.4G 接收器"
        elif any(k in text for k in data.USB_24G_KEYWORDS):
            hit = "疑似 2.4G 无线接收器"
        if hit:
            suspects.append(f"{d['vid']}:{d['pid']} {d['manufacturer']} {d['product']} — {hit}")
    if suspects:
        return HabitCheck("usb", "2.4G 无线接收器", "bad", f"发现 {len(suspects)} 个 2.4G 无线接收器", suspects,
                          "大多数 2.4G 无线键鼠不加密或使用弱加密，攻击者在数十米外即可嗅探您输入的每一个字符（包括密码、密钥口令），甚至注入按键（MouseJack）。"
                          "高安全性计算请改用有线键鼠；蓝牙 LE Secure Connections 是次优选择。")
    return HabitCheck("usb", "2.4G 无线接收器", "good", "未发现 2.4G 无线接收器", [f"共枚举 {len(devs)} 个 USB 设备（{source}）。"],
                      "很好！有线或蓝牙安全连接的输入设备能有效防止按键被嗅探，请继续保持。")


def _ntfs_partitions():
    found, source = [], ""
    rc, out = run(["lsblk", "-J", "-o", "NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT"])
    if out.strip():
        try:
            def walk(nodes):
                for n in nodes:
                    if (n.get("fstype") or "").lower() in ("ntfs", "ntfs3", "exfat-ntfs"):
                        found.append(f"/dev/{n.get('name')}  {n.get('size', '')}  标签: {n.get('label') or '-'}  挂载: {n.get('mountpoint') or '-'}")
                    walk(n.get("children", []) or [])
            walk(json.loads(out).get("blockdevices", []))
            source = "lsblk"
        except ValueError:
            pass
    if not source:
        for f in glob.glob("/run/udev/data/b*"):
            content = read(f)
            if "E:ID_FS_TYPE=ntfs" in content:
                name = re.search(r"E:DEVNAME=(\S+)", content)
                label = re.search(r"E:ID_FS_LABEL=(\S+)", content)
                found.append(f"{name.group(1) if name else f}  标签: {label.group(1) if label else '-'}")
                source = "udev"
    if not source:
        for line in read("/proc/mounts").splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[2] in ("ntfs", "ntfs3", "fuseblk"):
                found.append(f"{parts[0]} 挂载于 {parts[1]} ({parts[2]})")
        source = "/proc/mounts"
    return found, source


def _windows_installed():
    hints = []
    for p in ("/boot/efi/EFI/Microsoft/Boot/bootmgfw.efi", "/efi/EFI/Microsoft/Boot/bootmgfw.efi"):
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
    if parts or win:
        details = parts + win
        if win:
            summary = "检测到 Windows 安装" + (f"及 {len(parts)} 个 NTFS 分区" if parts else "")
            advice = ("Windows 是闭源系统，无法审计，存在被植入后门的风险，不应当用于高安全性计算。"
                      "更严重的是：当前设备上安装了 Windows，那么 Windows 中的恶意软件或后门可能已经污染了固件、引导分区乃至这套 Linux 环境本身（例如篡改 EFI 分区、写入 UEFI 变量）。"
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
    osr = os_release()
    return Report(
        hsi=_safe(get_hsi, lambda e: HsiReport(ok=False, error=f"检测时出错：{e}")),
        cmdline=_safe(get_cmdline_report, lambda e: CmdlineReport(arch=arch(), cpu=cpu_vendor(), cmdline=f"读取失败：{e}", items=[])),
        sysctl=_safe(get_sysctl_report, lambda e: SysctlReport(arch=arch(), groups=[])),
        hardware=_safe(get_hardware, lambda e: HardwareReport("", "", "", "", "", "", data.DEFAULT_VENDOR, "")),
        habits=_safe(get_habits, lambda e: HabitsReport(checks=[HabitCheck("err", "检测出错", "unknown", str(e), [], "")])),
        arch=arch(), cpu=cpu_model(), os_name=osr.get("PRETTY_NAME", "Linux"), kernel=kernel_version(), in_flatpak=IN_FLATPAK,
    )
