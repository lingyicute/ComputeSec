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

from . import data, hostdata, hostinfo, kernelver, xdg

IN_FLATPAK = os.path.exists("/.flatpak-info")


def _flatpak_shared_subsystems():
    """返回 Flatpak 沙箱与宿主共享的子系统集合（取 /.flatpak-info 的 [Context] shared=）。

    flatpak-metadata(5)：/.flatpak-info 描述沙箱的**实际生效**配置，[Context] 的
    shared 是以分号分隔的列表（network、ipc）。配置文件缺失或格式异常时返回空集合
    ——宁可当作"什么都没共享"，也不要凭空相信沙箱内的读数。
    """
    text = read("/.flatpak-info")
    if not text:
        return set()
    m = re.search(r"^shared=(.*)$", text, re.M)
    if not m:
        return set()
    return {x.strip() for x in m.group(1).split(";") if x.strip()}


def _flatpak_shares_network():
    return "network" in _flatpak_shared_subsystems()
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

    @property
    def undetermined(self):
        """fwupd 拿不到判定所需的数据（Flags 含 missing-data）：既非通过，也非失败。"""
        return not self.passed and "missing-data" in self.flags


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
    def undetermined(self):
        """fwupd 拿不到判定所需数据的项目（Flags 含 missing-data）。

        这类项目既不是"通过"也不是"未通过"——常见于虚拟机、缺少 TPM 的老机器、
        或固件没有暴露对应接口。它不该计入 failed，更不该被列成"可以修复"。
        """
        return [i for i in self.active if i.undetermined]

    @property
    def failed(self):
        und = {id(i) for i in self.undetermined}
        return [i for i in self.active if not i.passed and id(i) not in und]

    @property
    def fixable(self):
        """用户可自行操作修复的项目（操作系统内 / 固件设置中）。"""
        return [i for i in self.failed if i.info.get("fix") and i.info.get("kind") in ("os", "bios")]

    @property
    def scored(self):
        """参与评分的项目：排除被废弃的与无法判定的。"""
        und = {id(i) for i in self.undetermined}
        return [i for i in self.active if id(i) not in und]

    @property
    def score(self):
        """0-100 的通过率；无法评估时返回 None（而不是误导性的 0）。

        取整口径：分项评分一律用 int() **截断**，不用四舍五入。用户在界面上能
        看到「x / y 项通过」，分项分必须能被手算复现：2/3 就是 66，四舍五入成 67
        会让"通过项数 ÷ 可评估项数"对不上，看起来像算错了。

        综合分（Report.overall）不同：它是几个分数的平均，没有"项数"可数，因此
        那边用四舍五入（见 Report._mean）。两处口径不同是有意的——改这里之前请先
        确认界面上的"x / y"是否也需要跟着改。
        """
        if not self.ok:
            return None
        act = self.scored
        if not act:
            return None
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
    # Amd.RollbackProtection 与 Bios.RollbackProtection 是 fwupd 的两个不同检测项，
    # 单凭末段无法区分归属；真实 ID 直接命中，跨厂商的两段尾缀也各自唯一。
    "RollbackProtection",
}


def _hsi_tail_is_generic(tail):
    """末段是否过于通用，不能单凭它推断检测项含义。

    除通用词本身外，也要挡住"通用词 + 编号"的写法：例如 Version20 虽然目前
    是唯一的末段，但 com.example.Version20 与 TPM 2.0 毫无关系，只因末段
    唯一就关联过去会把说明和修复建议安到无关的检测项上。
    """
    for generic in _HSI_GENERIC_TAILS:
        if tail == generic:
            return True
        rest = tail[len(generic):]
        if tail.startswith(generic) and rest and rest.strip("0123456789_") == "":
            return True
    return False


def _lookup_hsi_info(aid):
    aid = data.HSI_ALIASES.get(aid, aid)
    if aid in data.HSI_ATTRS:
        return data.HSI_ATTRS[aid]
    parts = aid.split(".")
    # 1) 最后两段精确匹配（如 com.example.IntelCet.Enabled -> IntelCet.Enabled）。
    #    必须唯一命中：将来若出现两个同尾段的条目，宁可退回到 fwupd 自带的
    #    Name/Summary，也不要随手挑一条把说明安错。data.HSI_ATTRS 的两段尾缀
    #    当前无重复，tests 里有一条不变量测试锁死这一点。
    if len(parts) >= 2:
        tail2 = parts[-2:]
        matches = [v for k, v in data.HSI_ATTRS.items() if k.split(".")[-2:] == tail2]
        if len(matches) == 1:
            return matches[0]
    # 2) 去掉厂商前缀的单段匹配，仅当末段不通用且唯一命中时采用。
    tail1 = parts[-1]
    if tail1 and not _hsi_tail_is_generic(tail1):
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
        """0-100 的通过率；没有可评估项（如非 x86/arm 架构）时返回 None。

        与 HsiReport.score 相同，这里用 int() 截断（不是四舍五入），
        以便与界面上「x / y 项」的手算结果一致；理由详见 HsiReport.score。
        """
        ap = self.applicable
        return int(100 * sum(1 for i in ap if i.status == "ok") / len(ap)) if ap else None


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
    "kpti", "random.trust_bootloader", "random.trust_cpu",
    "randomize_kstack_offset", "irqchip.gicv3_pseudo_nmi",
    "ia32_emulation",   # arch/x86/entry/common.c: kstrtobool，off/0/n 等价
}
# module_param(bool) 型布尔参数：同样经 kstrtobool 解析 on/1/y 与 off/0/n，
# 但 cmdline 上省略 = 的裸 token 会被内核置为真（param_set_bool(val=NULL) → 1）。
_CMDLINE_MODULE_BOOL_KEYS = {
    "kvm_amd.sev", "kvm_amd.sev_es", "kvm_amd.sev_snp", "kvm.mitigate_smt_rsb",
    "module.sig_enforce", "bdev_allow_write_mounted",
    # mm/shuffle.c 用 module_param_cb 注册、底层走 param_set_bool（FL_NOARG），
    # 因此裸 token 同样等价于真，归类应与上面的 module_param(bool) 一致。
    "page_alloc.shuffle",
}
# 处理函数按逗号逐个解析子选项、且多次出现时依次累加的参数（efi_parse_options、
# intel_iommu_setup、parse_amd_iommu_options、x86 iommu_setup 都是
# `while (*str) { strncmp…; str += strcspn(str, ","); }`）。同名 token 出现多次时
# 要按顺序拼起来，只保留最后一个会丢掉前面已经生效的选项。
_CMDLINE_COMMA_KEYS = {"efi", "intel_iommu", "amd_iommu", "iommu"}
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


def _iommu_opts_ok(nk, opts, expected):
    """按内核的解析方式判断逗号分隔的 IOMMU 子选项是否达到推荐值。

    三个处理函数都用 strncmp 做前缀匹配，因此这里也用 startswith。
    """
    if nk == "intel_iommu" and expected == "on":
        # drivers/iommu/intel/iommu.c intel_iommu_setup()：on / off 后者覆盖前者。
        # igfx_off 让集成显卡绕过 DMA 重映射，tboot_noforce 让 tboot 下不强制开启
        # （内核原话 "could expose security risk for tboot"）——都是给 IOMMU 开了
        # 口子，不算达到推荐值。sm_on、strict 等不削弱隔离的子选项不影响结论。
        state = None
        for o in opts:
            if o.startswith("on"):
                state = "on"
            elif o.startswith("off"):
                state = "off"
            elif o.startswith(("igfx_off", "tboot_noforce")):
                return False
        return state == "on"
    if nk == "amd_iommu" and expected == "force_isolation":
        # drivers/iommu/amd/init.c parse_amd_iommu_options()：off 一出现即禁用，
        # 与先后无关；注意 AMD 上没有 "on" 这个选项（会被当成 Unknown option）。
        if any(o.startswith("off") for o in opts):
            return False
        return any(o.startswith("force_isolation") for o in opts)
    if nk == "iommu" and expected == "force":
        # arch/x86/kernel/pci-dma.c iommu_setup()：各项是独立的 if，force 与 noforce
        # 后者覆盖前者（"forcesac" 同样以 force 开头，内核也会置 force_iommu）；
        # off 关闭 IOMMU，pt 让设备直通、绕过地址转换。
        forced = False
        for o in opts:
            if o.startswith(("off", "pt")):
                return False
            if o.startswith("force"):
                forced = True
            elif o.startswith("noforce"):
                forced = False
        return forced
    return False


def _cmdline_value_ok(key, actual, expected):
    if expected is None:
        return actual is not MISSING
    if actual is MISSING:
        return False
    nk = _norm_key(key)
    if nk == "slab_debug" and not actual:
        # mm/slub.c setup_slub_debug()：没有 "=选项"（裸 token 或 "slab_debug="）时
        # 直接 goto out，启用 DEBUG_DEFAULT_FLAGS = 一致性检查 F | 红区 Z | 投毒 P |
        # 记录调用者 U，严格强于推荐的 FZ。
        actual = "FZPU"
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
    if nk in ("intel_iommu", "amd_iommu", "iommu"):
        return _iommu_opts_ok(nk, [x for x in actual.split(",") if x], expected)
    if nk == "slab_debug":
        # 仅纯增量调试选项可按超集处理。O 会对部分 cache 关闭调试，不能视为增强。
        # mm/slub.c 的 parse_slub_debug_flags() 用 switch (tolower(*str)) 解析单字母
        # 选项，因此 FZ / fz / fZp 完全等价，必须先统一大小写再比较。
        flags = set(actual.upper())
        if "," not in actual and ";" not in actual:
            if flags and flags.issubset(set("FZPUTA")) and set(expected.upper()).issubset(flags):
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
            if nk in _CMDLINE_COMMA_KEYS and present.get(nk):
                present[nk] = f"{present[nk]},{v}"
            else:
                present[nk] = v
        else:
            nk = _norm_key(tok)
            nk = _CMDLINE_KEY_ALIASES.get(nk, nk)
            # 裸 token（无 =）不该抹掉同名的带值 token：内核会把两者分别交给各自的
            # 处理函数——slab_debug 的裸 token 仍会启用 DEBUG_DEFAULT_FLAGS，efi 的
            # 裸 token 被 parse_efi_cmdline(NULL) 拒绝并保持原值——丢掉带值形式只会
            # 让已知信息消失。module_param(bool) 例外：内核按最后一次出现生效，
            # 裸 token 等价于真，必须照旧覆盖才能与内核结论一致。
            if present.get(nk) is not None and nk not in _CMDLINE_MODULE_BOOL_KEYS:
                continue
            present[nk] = None
    ar, cv = arch(), cpu_vendor()
    running = kernelver.parse_release(platform.release())
    items = []
    for p in data.KERNEL_PARAMS:
        if ar not in p["arch"]:
            continue
        exp = p["value"]
        if isinstance(exp, dict):
            exp = exp.get(ar)
        if p.get("before_kernel"):
            # 同一取值在新旧内核上语义不同（如 rodata=）：低于分界版本、或解析不出
            # 版本时用旧取值。Flatpak 沙箱与宿主机共用内核，platform.release() 即宿主机内核。
            cutoff, legacy = p["before_kernel"]
            if running is None or running[:2] < cutoff:
                exp = legacy
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
def _sysctl_value_text(v):
    """把一项 sysctl 的读数变成界面上的文字。

    None 表示「文件在、但 read() 失败」（_sysctl_from_proc 的 OSError 分支；内核
    在 stable_secret 未配置时对 net.ipv6.conf.*.stable_secret 就返回 EIO）。这不是
    「内核不支持这一项」，写成「（不存在）」会把排查方向带偏，因此与真正读不到的
    情形分开表述。
    """
    return "（无法读取）" if v is None else v


@dataclass
class SysctlItem:
    key: str
    expected: str
    cmp: str
    actual: dict            # 具体键 -> 值 (None 表示不存在)
    status: str             # ok / missing / na / unknown / unverified
    desc: str
    note: str = ""
    source: str = ""        # proc / 用户提供 / 快照缺失

    @property
    def actual_text(self):
        if self.status == "unverified":
            return "（您提供的快照中没有这一项）"
        if self.status == "unknown":
            return "（无法读取，需要 root 权限）"
        if not self.actual:
            return "（内核不支持）"
        vals = {v for v in self.actual.values()}
        if len(vals) == 1:
            return _sysctl_value_text(vals.pop())
        # 多个接口的值不一样时逐个列出。None 必须在这里也翻译成人话：此前只有
        # 「所有接口同一个值」的分支做了翻译，混合情形下界面上会出现「eth0=None」。
        return ", ".join(
            f"{k.split('.')[-2]}={_sysctl_value_text(v)}"
            for k, v in sorted(self.actual.items()))


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
    def unverified(self):
        """Flatpak 内用户快照没有覆盖、又不该拿沙箱读数顶替的条目。"""
        return [i for i in self.all_items if i.status == "unverified"]

    @property
    def scored(self):
        """参与评分的条目：na（内核不支持）、unknown（读不到）、unverified（不可信）都不算。"""
        return [i for i in self.all_items if i.status not in ("na", "unknown", "unverified")]

    @property
    def score(self):
        """0-100 的通过率；没有可评估项时返回 None。

        同样用 int() 截断，理由详见 HsiReport.score。
        """
        ap = self.scored
        return int(100 * sum(1 for i in ap if i.status == "ok") / len(ap)) if ap else None


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
    # net.* 是按网络命名空间复制的 sysctl。Flatpak 默认不共享宿主网络（manifest 未声明
    # --share=network 时，应用跑在私有 netns 里），此时 /proc/sys/net 读到的是**沙箱
    # 自己的**默认值而不是宿主机的加固状态——新 netns 的 rp_filter=0、
    # accept_redirects=1，与推荐值恰好相反。只有确认共享了宿主网络才能采信。
    sandbox_netns = IN_FLATPAK and not _flatpak_shares_network()
    groups = []
    for title, entries in data.SYSCTL_GROUPS:
        items = []
        for e in entries:
            key = e["key"]
            cmp = e.get("cmp", "eq")
            actual, unreadable = _sysctl_from_proc(key)
            source = "proc"
            snapshot_gap = ""
            net_isolated = sandbox_netns and key.startswith("net.")
            # 用户提供的 sysctl -a（以 root 执行、在宿主机上执行）能补上权限不足的
            # 条目，也能补上被 Flatpak 沙箱屏蔽或隔离的条目。但它在本机的地位取决于
            # 环境，两种环境必须分开处理。
            supplied = hd.sysctl_lookup(key) if user_values else {}
            if supplied and IN_FLATPAK:
                # 沙箱里的 /proc/sys 可能属于隔离视图（被屏蔽、被改写、或另一个
                # netns），不能混入宿主机快照，只能整块以快照为准。
                actual = dict(supplied)
                source = "用户提供"
                unreadable = False
            elif net_isolated:
                # Flatpak 没有共享宿主网络：沙箱内的 net.* 属于独立的网络命名空间，
                # 数值来自新 netns 的默认值，与宿主机的加固状态无关。
                actual, source, snapshot_gap = {}, "沙箱网络隔离", "沙箱网络隔离"
                unreadable = False
            elif supplied:
                # 原生环境：/proc/sys 是此刻的真实状态，快照只用来补读不到的键。
                # 反过来让快照覆盖实时值会错两次：用户加固后（快照是加固前采的）
                # 被判成未加固；用户把 sysctl 撤销后（快照里还是加固后的值）却被
                # 判成"已加固"——后者是本程序最不该犯的错。快照的存活期是整次开机
                # （hostdata.fresh 只比对 boot_id），而本程序自己就在提醒用户
                # "长时间不重启"，两者叠在一起，快照可能已经过了一整天。
                filled = {k: v for k, v in supplied.items() if k not in actual}
                if filled:
                    # 这些键在 /proc 里读不到（多半是 EACCES），用快照补上。
                    actual = {**actual, **filled}
                    age = hd.age_text
                    source = f"用户提供（{age}）" if age else "用户提供"
                    unreadable = False
            elif IN_FLATPAK and user_values and not (unreadable and not actual):
                # 沙箱内的 /proc/sys 不是宿主机视图（可能被屏蔽、改写或加了命名空间），
                # 快照没有覆盖这一项时不能拿沙箱读数顶替，否则会把沙箱的值当成
                # 宿主机结果报出来。明确标成 unverified 并排除出评分。
                # 例外：沙箱里这一项完全是「权限不足」（vm.mmap_rnd_bits 等 0600 条目），
                # 快照里又恰好没有——最可能是执行时漏了 sudo、报错被 2>/dev/null 吞掉。
                # 这种情况落到下面的 unknown，界面才会给出「可能没有加 sudo」的提示。
                actual, source, snapshot_gap = {}, "快照缺失", "快照缺失"
                unreadable = False
            if snapshot_gap:
                status = "unverified"
            elif unreadable and not actual:
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
    def dmi(n):
        return read(f"/sys/class/dmi/id/{n}").strip()
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
    status: str         # good / suspect / warn / bad / unknown
    summary: str
    details: list       # [str]
    advice: str


@dataclass
class HabitsReport:
    checks: list

    @property
    def score(self):
        """0-100；读不到（unknown）的条目不计入评分，全部读不到时返回 None。

        两种"不扣分"口径要分清：

        * unknown（读不到）：本程序没权限/没枚举成功（Flatpak 列表读不到、USB 枚举
          失败等），用户无法通过任何操作改善它。按 60 分计入等于凭空扣分，而且其它
          三个板块遇到"无法评估"都是不计分并显示「—」，这里跟随同一口径；
        * suspect（疑似）：只是提醒，按满分计——"疑似"不是证据，不该拉低分数。

        因此打分表里没有 unknown 这一项，它被直接跳过。
        """
        pts = {"good": 100, "suspect": 100, "warn": 40, "bad": 0}
        scored = [c for c in self.checks if c.status in pts]
        if not scored:
            return None
        return int(sum(pts[c.status] for c in scored) / len(scored))


def _flatpak_app_dirs():
    """可能存放已安装 Flatpak 应用的目录（去重，按可靠性排序）。

    - ``/var/lib/flatpak/app``：系统级安装（``flatpak install``，默认）；
    - ``$XDG_DATA_HOME/flatpak/app``：用户级安装。此前这里写死成
      ``~/.local/share/flatpak/app``，遵守 XDG 规范把 XDG_DATA_HOME 指到别处的
      机器上，``flatpak install --user`` 装的应用一个都数不到；
    - ``~/.local/share/flatpak/app``：XDG_DATA_HOME 被指走之后的兜底，也是
      Flatpak 版的唯一可用路径——沙箱里的 XDG_DATA_HOME 是
      ``~/.var/app/<id>/data``，而清单只授予了 ``~/.local/share/flatpak:ro``。
    """
    dirs = ["/var/lib/flatpak/app",
            os.path.join(xdg.data_home(), "flatpak", "app"),
            os.path.join(os.path.expanduser("~"), ".local", "share", "flatpak", "app")]
    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _flatpak_apps():
    apps, source = set(), ""
    dirs = _flatpak_app_dirs()
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
            apps.update(name.strip() for name in out.splitlines() if name.strip() and "." in name)
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


# 2.4G 键鼠相关的建议文案。"已确认"沿用原有措辞，"疑似"只提醒风险、不扣分。
USB_ADVICE_CONFIRMED = ("绝大多数 2.4G 无线键鼠不加密或使用弱加密，攻击者在数十米外即可嗅探您输入的每一个字符"
                        "（包括密码、密钥口令），甚至注入按键（MouseJack）。"
                        "高安全性计算请改用有线键鼠；支持蓝牙 LE Secure Connections 的输入设备是次优选择。")
USB_ADVICE_SUSPECT = ("这些设备的厂商或型号与常见的 2.4G 无线键鼠方案高度重合（例如型号里只写了"
                      "「Wireless Mouse」，或只写了「Receiver」「Dongle」），但没有「2.4G」或键鼠接收器型号之类"
                      "能够确认的字样，ComputeSec 无法确认它是 2.4G 接收器，还是同厂的有线 / 蓝牙设备"
                      "或别的无线接收设备，因此这一项不计入评分。\n\n"
                      "请自行确认：① 拔下该设备后重新检测，看这一条是否消失；② 检查它是否配有一个同样插在 USB 口上的"
                      "小接收器（有则是 2.4G 无线接收器方案）；③ 在终端执行 lsusb -v 查看其接口描述符与供电需求。"
                      "若确认是 2.4G 无线键鼠，请按「已确认」情形处理：改用有线，或支持蓝牙 LE Secure Connections 的设备。")


_LOGITECH_UNIFYING_DESC = "Logitech Unifying/Lightspeed 接收器（曾曝出 MouseJack、KeyJack 等密钥提取与按键注入漏洞）"


def _usb_receiver_kind(d):
    """判定单个 USB 设备与 2.4G 无线键鼠的关系。

    返回 (级别, 说明)：级别为 "bad" 表示可以确认是 2.4G 无线接收设备；
    "suspect" 表示只是疑似（厂商/型号与 2.4G 方案重合，但型号串里没有任何
    接收器字样，可能是同厂的有线或蓝牙产品），需要用户自行确认；
    返回 None 表示与该检测无关。
    """
    text = f"{d['manufacturer']} {d['product']}".lower()
    vid, pid = d["vid"], d["pid"]
    if vid == "046d" and pid in data.LOGITECH_BOLT_PIDS:
        return "bad", "Logitech Bolt 接收器（使用 BLE 安全连接加密，风险较低，但仍建议有线）"
    if vid == "046d" and pid in data.LOGITECH_UNIFYING_PIDS:
        return "bad", _LOGITECH_UNIFYING_DESC
    # 蓝牙适配器、红外接收器、电视棒、无线耳机接收器等：型号里也常写 dongle / receiver，
    # 但与 2.4G 键鼠无关，不能让它们触发「已确认」（会把这一项扣到 0 分）。
    if d.get("cls") in data.USB_NON_INPUT_CLASSES or re.search(data.USB_NON_INPUT_RADIO_RE, text):
        return None
    inputish = any(k in text for k in data.USB_24G_INPUT_KEYWORDS)
    if not inputish and re.search(data.USB_GAME_CONTROLLER_RE, text):
        return None
    # Logitech 的 receiver / dongle 就是其键鼠接收器；但没命中这些词时不能直接
    # 排除——只写了「Wireless Mouse」之类的罗技接收器同样要走下面的通用判定，
    # 否则罗技设备反而比别家少一层「疑似」提示。
    if vid == "046d" and any(k in text for k in data.LOGITECH_RECEIVER_KEYWORDS):
        return "bad", _LOGITECH_UNIFYING_DESC
    strong = bool(re.search(data.USB_24G_CONFIRM_RE, text)) or any(
        k in text for k in data.USB_24G_CONFIRM_KEYWORDS)
    generic = any(k in text for k in data.USB_24G_GENERIC_KEYWORDS)
    dedicated = vid in getattr(data, "USB_24G_DEDICATED_VENDORS", set())
    if strong or (generic and (inputish or dedicated)):
        vendor = data.USB_24G_VENDORS.get(vid)
        return "bad", f"{vendor} 2.4G 接收器" if vendor else "2.4G 无线接收器"
    if generic:
        vendor = data.USB_24G_VENDORS.get(vid)
        return "suspect", (f"{vendor} " if vendor else "") + "无线接收器 / 适配器（型号未标明是键鼠接收器）"
    # 以下拿不到"接收器"的正面证据，只能给疑似：芯片厂商既做 2.4G 方案，也做有线外设，
    # 仅凭 VID 或 "Mouse/Keyboard" 之类的型号串无法区分。
    if vid in getattr(data, "USB_24G_DEDICATED_VENDORS", set()) and any(
            k in text for k in
            data.USB_24G_SUSPECT_KEYWORDS + data.USB_24G_INPUT_KEYWORDS + ["composite"]):
        vendor = data.USB_24G_VENDORS.get(vid, "未知厂商")
        return "suspect", f"{vendor} 键鼠类设备（该厂商专做 2.4G 方案，但型号未标明接收器）"
    if any(k in text for k in data.USB_24G_SUSPECT_KEYWORDS):
        vendor = data.USB_24G_VENDORS.get(vid)
        return "suspect", (f"{vendor} 无线设备（可能是蓝牙，无法确认是 2.4G）" if vendor
                           else "疑似 2.4G 无线设备")
    return None


def check_usb() -> HabitCheck:
    devs, source = _usb_devices()
    if not source:
        return HabitCheck("usb", "2.4G 无线接收器", "unknown", "无法枚举 USB 设备", [], "")
    confirmed, suspects = [], []
    for d in devs:
        if d["vid"] in ("1d6b",):   # Linux Foundation root hubs
            continue
        text = f"{d['manufacturer']} {d['product']}".lower()
        # 排除笔记本内置摄像头等视频设备（Sonix 0c45 / Sunplus 1bcf 常用于内置 UVC 摄像头）；
        # bDeviceClass=0x0e 是 USB Video，即使型号串没写 camera 也不该参与键鼠判定。
        if d.get("cls") == "0e" or any(w in text for w in ("webcam", "camera", "uvc", "integrated_webcam")):
            continue
        kind = _usb_receiver_kind(d)
        if not kind:
            continue
        level, desc = kind
        desc_name = " ".join(x for x in (d["manufacturer"], d["product"]) if x)
        line = f"{d['vid']}:{d['pid']}" + (f" {desc_name}" if desc_name else "") + f" — {desc}"
        (confirmed if level == "bad" else suspects).append(line)
    if confirmed:
        details = confirmed + [f"疑似：{s}" for s in suspects]
        summary = f"发现 {len(confirmed)} 个 2.4G 无线接收器"
        if suspects:
            summary += f"，另有 {len(suspects)} 个疑似设备"
        return HabitCheck("usb", "2.4G 无线接收器", "bad", summary, details, USB_ADVICE_CONFIRMED)
    if suspects:
        return HabitCheck("usb", "2.4G 无线接收器", "suspect",
                          f"发现 {len(suspects)} 个疑似 2.4G 无线设备，需要您自行确认",
                          suspects + [f"（以上仅为疑似，不计入评分；共枚举 {len(devs)} 个 USB 设备，来源：{source}。）"],
                          USB_ADVICE_SUSPECT)
    return HabitCheck("usb", "2.4G 无线接收器", "good", "未发现 2.4G 无线接收器", [f"共枚举 {len(devs)} 个 USB 设备（{source}）。"],
                      "很好！有线或支持蓝牙 LE Secure Connections 的输入设备能有效防止按键被嗅探，请继续保持。")


def _ntfs_from_lsblk_json(j):
    found = []

    def walk(nodes):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            ftype = (n.get("fstype") or "").lower()
            if ftype in data.WINDOWS_FS_TYPES:
                mp = n.get("mountpoint")
                if not mp and isinstance(n.get("mountpoints"), list):
                    mp = ", ".join(str(x) for x in n["mountpoints"] if x)
                line = (f"/dev/{n.get('name')}  {n.get('size', '')}  标签: {n.get('label') or '-'}"
                        f"  挂载: {mp or '-'}")
                if ftype == data.BITLOCKER_FS_TYPE:
                    # 加密卷看不出里面是 NTFS，界面上要说清楚是被什么加密的。
                    line += "  （BitLocker 加密）"
                found.append(line)
            walk(n.get("children", []) or [])

    if isinstance(j, dict) and isinstance(j.get("blockdevices"), list):
        walk(j["blockdevices"])
    return found


def _ntfs_partitions():
    """返回 (命中的分区行, 数据来源)。

    谁优先取决于环境：Flatpak 沙箱内看不到宿主机的块设备，用户提供的 lsblk -J
    快照是唯一可靠来源；原生环境里 lsblk 读到的就是此刻的分区表，而快照可能来自
    几个小时前（它只在同一次开机内有效）。让快照压过实时读数会错两次：刚接上的
    Windows 磁盘被判成「未发现」，已经拆掉或格式化掉的分区却仍然被报出来——
    与 checks.get_sysctl_report 里「原生环境以实时 /proc 为准」的取舍同理。
    """
    supplied = hostdata.CURRENT.lsblk
    if supplied and IN_FLATPAK:
        return _ntfs_from_lsblk_json(supplied), "lsblk（用户提供）"
    found, source = [], ""
    rc, out = run(["lsblk", "-J", "-o", "NAME,FSTYPE,LABEL,SIZE,MOUNTPOINT"])
    if out.strip():
        try:
            found = _ntfs_from_lsblk_json(json.loads(out))
            source = "lsblk"
        except ValueError:
            pass
    if not source and supplied:
        # 原生环境里 lsblk 也不可用（极简容器、util-linux 被裁掉）时才退回快照。
        found = _ntfs_from_lsblk_json(supplied)
        source = "lsblk（用户提供）"
    if not source:
        has_udev_fs = False
        seen_devices = set()
        for f in sorted(glob.glob("/run/udev/data/b*")):
            content = read(f)
            if "E:ID_FS_TYPE=" in content:
                has_udev_fs = True
            m_fs = re.search(r"^E:ID_FS_TYPE=(%s)\s*$" % "|".join(data.WINDOWS_FS_TYPES),
                             content, re.M | re.I)
            if m_fs:
                name = re.search(r"^E:DEVNAME=(\S+)", content, re.M)
                devname = name.group(1) if name else ""
                if not devname:
                    uevent = read(f"/sys/dev/block/{os.path.basename(f)[1:]}/uevent")
                    m_dev = re.search(r"^DEVNAME=(\S+)", uevent, re.M)
                    devname = f"/dev/{m_dev.group(1)}" if m_dev else f
                label = re.search(r"^E:ID_FS_LABEL=(\S+)", content, re.M)
                line = f"{devname}  标签: {label.group(1) if label else '-'}"
                if m_fs.group(1).lower() == data.BITLOCKER_FS_TYPE:
                    line += "  （BitLocker 加密）"
                found.append(line)
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
        label = ("NTFS / BitLocker 分区" if any("BitLocker" in p for p in parts) else "NTFS 分区")
        if win:
            summary = "检测到 Windows 安装" + (f"及 {len(parts)} 个 {label}" if parts else "")
            advice = ("Windows 是闭源系统，无法审计，存在被植入后门的风险，不应当用于高安全性计算。"
                      "更严重的是：当前设备上安装了 Windows，那么 Windows 中的恶意软件或后门可能已经污染了这套 Linux 环境本身、引导分区甚至固件（例如篡改 EFI 分区、写入 UEFI 变量、乃至利用 SMM 漏洞向固件植入 Rootkit）。"
                      "在完全重装系统（最好同时重新刷写固件并重置 UEFI 密钥）之前，此硬件不应当用于高安全性计算。")
        else:
            summary = f"检测到 {len(parts)} 个 {label}"
            advice = ("NTFS 分区通常意味着与 Windows 共用数据。Windows 无法审计、存在后门风险，不应用于高安全性计算；"
                      "若该分区曾在 Windows 中使用，其中的文件（尤其是可执行文件、Office 文档、宏）可能已被污染。建议将必要数据迁移到加密的 Linux 文件系统（LUKS + btrfs/ext4）后移除 NTFS 分区。")
        return HabitCheck("ntfs", "NTFS / Windows 检测", "bad", summary, details, advice)
    return HabitCheck("ntfs", "NTFS / Windows 检测", "good", "未发现 NTFS / BitLocker 分区或 Windows 安装", [f"检测方式：{source or '综合'}"],
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
    kernel_support: object = None   # kernelver.KernelSupport（联网检查失败时为 None 或已知的缓存值）

    @staticmethod
    def _mean(values):
        """各分项的平均分，无法评估（None）的分项跳过；全部无法评估时返回 None。

        用整数四舍五入（.5 向上），而不是 // 截断：截断是单向偏低，每个综合分
        都会平白少掉最多 1 分（[80, 79] 截断成 79，实际是 79.5）。
        """
        vals = [v for v in values if v is not None]
        if not vals:
            return None
        return (sum(vals) + len(vals) // 2) // len(vals)

    @property
    def kernel_score(self):
        return self._mean([self.cmdline.score, self.sysctl.score])

    @property
    def overall(self):
        """四项的平均分，跳过无法评估（None）的分项后重新归一；全部无法评估时返回 None。"""
        return self._mean([self.hsi.score if self.hsi.ok else None, self.kernel_score,
                           self.hardware.score, self.habits.score])


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
        identity=ident, hostdata=hostdata.CURRENT, kernel_support=kernelver.CURRENT,
    )
