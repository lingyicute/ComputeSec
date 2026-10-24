# -*- coding: utf-8 -*-
"""内核版本线检查：本机内核是否属于上游 mainline / stable。

为什么需要
----------
Linux 的各个 LTS 分支由于种种原因，均未包含上游全部的安全修复与加固改进。
ComputeSec 推荐的内核启动参数与 sysctl，在这些旧分支上不保证能提供应有的
加固效果：其中一部分参数在旧内核上根本不存在，还有一部分即使写进启动
命令行，也会被内核静默忽略——`init/main.c` 只会打印一句
"Unknown kernel command line parameters …, will be passed to user space"。
更糟的是，参数既然出现在 `/proc/cmdline` 里，本程序就会把它判为"已设置"，从而
给出"已加固"的错误结论。

因此启动时联网取一次 kernel.org 的版本号：若本机内核既不属于 mainline，也不属于
stable，就明确告知用户"不要把这些加固建议当成可靠的依据"，并建议切换到
mainline 或 stable 内核。

隐私与健壮性
------------
- 只向 kernel.org 发一次 GET 请求读取公开的 releases.json，不上报任何信息；
- 结果缓存 24 小时（XDG 数据目录，0600）。失败不弹窗、不影响检测，但「内核加固」页
  会明说「未能核对」并给出重试按钮；
- 本模块不 import gi，可在无 GTK 环境下直接测试。
"""

import json
import os
import platform
import re
import time
import urllib.error
import urllib.request

from . import xdg

RELEASES_URL = "https://www.kernel.org/releases.json"
CACHE_NAME = "kernelver.json"
CACHE_TTL = 24 * 3600
FETCH_TIMEOUT = 6.0
# releases.json 现在约 20 KB。限长读取，避免坏代理 / captive portal 返回一个
# 巨大的响应把内存吃满。
MAX_RESPONSE_BYTES = 1_000_000

# 内核 release 串：6.1.158+ / 7.2.12-200.fc44.x86_64 / 6.18.0-rc3 / 7.3
_RELEASE_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")

TIER_ZH = {
    "mainline": "mainline（上游主线）",
    "stable": "stable（上游稳定版）",
    "older": "较旧的分支（LTS 或已停止维护的版本）",
    "unknown": "无法判断",
}


def _data_dir(create=True):
    """本程序的数据目录（规则见 computesec.xdg）。只读查询传 create=False，不在磁盘上留痕。"""
    return xdg.data_dir(create=create)


def parse_release(text):
    """把内核 release 串解析成 (major, minor, patch)；无法解析时返回 None。

    发行版后缀（-200.fc44.x86_64）、本地版本号（+）、rc 标记（-rc3）都忽略。
    """
    if not isinstance(text, str):
        return None
    m = _RELEASE_RE.match(text.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def parse_releases_json(text):
    """从 kernel.org 的 releases.json 里取出 (mainline, stable) 版本串。

    结构形如 {"releases": [{"moniker": "mainline", "version": "7.3"},
    {"moniker": "stable", "version": "7.2.12"}, {"moniker": "longterm", ...}]}。
    只认 moniker，不认 latest_stable —— 后者在主线刚发布时指向的是 mainline。
    """
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return "", ""
    if not isinstance(doc, dict):
        return "", ""
    mainline = stable = ""
    for rel in doc.get("releases") or []:
        if not isinstance(rel, dict):
            continue
        moniker = rel.get("moniker")
        version = rel.get("version")
        if not isinstance(version, str):
            continue
        if moniker == "mainline" and not mainline:
            mainline = version
        elif moniker == "stable" and not stable:
            stable = version
    return mainline, stable


def classify(release, mainline, stable):
    """判断本机内核落在哪条版本线上。

    返回 "mainline" / "stable" / "older" / "unknown"。以 stable 的
    major.minor 作为"受支持"的门槛：同一条线上落后的点版本（7.2.11 对 7.2.12）
    仍然算 stable，因为下游发行版无论如何都会落后几个补丁。
    """
    cur = parse_release(release)
    ml = parse_release(mainline)
    st = parse_release(stable)
    if cur is None or (ml is None and st is None):
        return "unknown"
    cur_mm = cur[:2]
    if ml is not None and cur_mm >= ml[:2]:
        return "mainline"
    if st is not None and cur_mm >= st[:2]:
        return "stable"
    return "older"


class KernelSupport:
    """本机内核的版本线信息。"""

    def __init__(self, release="", mainline="", stable="", tier="unknown", checked_at=0,
                 error="", stale=False):
        self.release = release or ""
        self.mainline = mainline or ""
        self.stable = stable or ""
        self.tier = tier
        self.checked_at = checked_at
        self.error = error
        # 版本号来自过期缓存、且本次没能连上 kernel.org。此时结论可能已经过时，
        # 界面上必须说明，不能伪装成"刚刚查过"。
        self.stale = bool(stale)

    @property
    def major_minor(self):
        r = parse_release(self.release)
        return f"{r[0]}.{r[1]}" if r else ""

    @property
    def have_upstream(self):
        """是否拿到了 kernel.org 的上游版本号。"""
        return bool(self.mainline or self.stable)

    @property
    def parsed(self):
        """本机 release 串能否解析成 major.minor[.patch]。

        解析不了（例如某些实验分支把 release 写成 ``weird-release``）时，结论同样是
        「无法判断」，但原因与"没连上 kernel.org"完全不同——两者的排查方向一个在
        网卡、一个在内核名字上，界面文案必须分得开。
        """
        return parse_release(self.release) is not None

    @property
    def known(self):
        """能否下结论：既要拿到上游版本号，也要能解析本机内核。"""
        return self.have_upstream and self.parsed

    @property
    def supported(self):
        return self.tier in ("mainline", "stable")

    @property
    def tier_text(self):
        return TIER_ZH.get(self.tier, TIER_ZH["unknown"])

    def age_text(self, now=None):
        """版本号是多久以前拿到的；没有时间戳时返回空串。"""
        if not self.checked_at:
            return ""
        now = int(time.time()) if now is None else int(now)
        secs = max(0, now - int(self.checked_at))
        if secs < 60:
            return "刚刚"
        if secs < 3600:
            return f"{secs // 60} 分钟前"
        if secs < 86400:
            return f"{secs // 3600} 小时前"
        return f"{secs // 86400} 天前"

    def to_dict(self):
        return dict(release=self.release, mainline=self.mainline, stable=self.stable,
                    tier=self.tier, checked_at=self.checked_at, error=self.error)

    @classmethod
    def from_dict(cls, d):
        """从缓存还原。只接受结构完全正确的字典，其余一律当作没有缓存。"""
        if not isinstance(d, dict):
            return None
        for key in ("release", "mainline", "stable", "error"):
            if not isinstance(d.get(key, ""), str):
                return None
        if d.get("tier", "unknown") not in TIER_ZH:
            return None
        try:
            checked_at = int(d.get("checked_at") or 0)
        except (TypeError, ValueError):
            return None
        return cls(release=d.get("release", ""), mainline=d.get("mainline", ""),
                   stable=d.get("stable", ""), tier=d.get("tier", "unknown"),
                   checked_at=checked_at, error=d.get("error", ""))


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """在**每一跳发出之前**拒绝非 https 的重定向目标。

    只在最后检查 resp.geturl() 是不够的：https → http → https 这样的链，中间那一跳
    是明文，攻击者可以把它改写成指向自己（持有合法证书）的 https 地址，最终 URL
    照样以 https:// 开头；而且等到检查时，明文请求早已发出。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            fp.close()
            raise urllib.error.URLError(f"拒绝跟随到非 https 地址的重定向：{newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _urlopen(req, timeout):
    # build_opener 发现传入的是 HTTPRedirectHandler 的子类时，就不再装默认的那个。
    return urllib.request.build_opener(_HttpsOnlyRedirectHandler).open(req, timeout=timeout)


def _default_fetcher(url, timeout):
    """取回 releases.json 正文。

    timeout 是**整次请求**的截止时间，不只是单次 socket 操作的超时。

    ``urlopen(timeout=)`` 只约束单次 connect / read，对端每 5 秒吐 1 个字节时，
    每一次 read() 都在超时之内合法返回，整次请求却可以一直拖下去。后果不是崩溃
    而是更糟：后台线程一直挂着，检查标志位永不复位，「重试」按钮从此点了没有任何
    反应（见 main.start_kernel_check）。因此这里按块读取，每块之前核对一次
    deadline。

    MAX_RESPONSE_BYTES 仍然保留：它防的是"一次给你一大坨"，deadline 防的是
    "一点一点喂给你"，两者互不替代。
    """
    req = urllib.request.Request(url, headers={"User-Agent": "ComputeSec"})
    deadline = time.monotonic() + timeout
    with _urlopen(req, timeout) as resp:
        # 重定向已逐跳校验，这里再核一次最终地址，防止将来有人换掉 opener 而不自知。
        final = resp.geturl() or url
        if not final.startswith("https://"):
            raise ValueError(f"请求被重定向到了非 https 地址：{final}")
        chunks, size = [], 0
        while True:
            if time.monotonic() > deadline:
                raise ValueError(f"读取 {url} 超过 {timeout:g} 秒，已中止")
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            # 超限要明确报错：静默截断的结果是 JSON 解析失败，报出来的却是
            # 「响应里没有版本号」，会把排查方向带偏。
            if size > MAX_RESPONSE_BYTES:
                raise ValueError(f"响应超过 {MAX_RESPONSE_BYTES} 字节，不像是 releases.json")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", "replace")


def fetch_versions(fetcher=None, timeout=FETCH_TIMEOUT, url=RELEASES_URL):
    """取 (mainline, stable)。任何异常都向上抛，由调用方决定是否静默。"""
    read = fetcher or _default_fetcher
    text = read(url, timeout)
    mainline, stable = parse_releases_json(text)
    if not mainline and not stable:
        raise ValueError("kernel.org 的响应里没有 mainline / stable 版本号")
    return mainline, stable


def load_cache(path=None, now=None):
    """读缓存。

    给了 now：只返回仍在 TTL 内的缓存。时间戳缺失（0）或在未来（本机时钟被回拨，
    双系统按本地时间写 RTC 时很常见）都按过期处理，否则这份缓存会永不过期。
    不给 now：联网失败时的回退，只要结构正确、确实带有版本号即可，不看新旧。

    没有 mainline / stable 的缓存一律不认：正常流程不会写出这种文件（取不到版本号
    时 fetch_versions 会抛异常、不写缓存），出现了只能是被改坏的，若当作有效缓存
    就会跳过联网，直接给出「未能核对」。
    """
    path = path or os.path.join(_data_dir(create=False), CACHE_NAME)
    try:
        with open(path) as f:
            st = KernelSupport.from_dict(json.load(f))
    except (OSError, ValueError, TypeError):
        return None
    if st is None or not (st.mainline or st.stable):
        return None
    if now is not None:
        if st.checked_at <= 0 or not 0 <= now - st.checked_at <= CACHE_TTL:
            return None
    return st


def save_cache(st, path=None):
    path = path or os.path.join(_data_dir(), CACHE_NAME)
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)      # 已存在的同名 .tmp 不受 O_CREAT 的 mode 影响
        with os.fdopen(fd, "w") as f:
            json.dump(st.to_dict(), f)
        os.replace(tmp, path)
    except OSError:
        pass


def get_status(release=None, now=None, fetcher=None, cache_path=None, force=False):
    """汇总本机内核的版本线信息。永不抛异常，联网失败时 KernelSupport.error 非空。

    几种来源要在界面上能区分开，所以 checked_at 一律记「版本号实际来自什么时刻」：

    * 缓存仍在 TTL 内（且未 force）→ 直接用，`stale=False`、`checked_at` 保持缓存的时刻；
    * 联网成功 → 刷新缓存，`checked_at` = 现在；
    * 联网失败、缓存已过期 → 退回旧缓存，`stale=True`，`checked_at` 仍是原时刻
      （改写成"现在"会让界面无法告诉用户这个结论究竟有多旧）；
    * 联网失败、缓存仍在 TTL 内（只会发生在 force 时）→ 沿用缓存，`stale=False`，
      但 `error` 照常记下，便于界面告诉用户「这次没刷新成」。

    force=True 用于用户手动「重新检查」：只跳过「TTL 内直接读缓存」这一步，成功后照常
    写缓存，失败后照常回退缓存——否则 24 小时内手动重查根本不会发出请求。
    """
    release = platform.release() if release is None else release
    now = int(time.time()) if now is None else int(now)

    cached = None if force else load_cache(cache_path, now)
    if cached is not None:
        return KernelSupport(release=release, mainline=cached.mainline, stable=cached.stable,
                             tier=classify(release, cached.mainline, cached.stable),
                             checked_at=cached.checked_at)

    try:
        mainline, stable = fetch_versions(fetcher=fetcher)
    except Exception as e:                                        # noqa: BLE001 (离线、代理、DNS 全都要吞掉)
        reason = str(e) or e.__class__.__name__
        # 拿不到就用上次的缓存（哪怕过期）算出一个结论；过期了要标明。
        prev = load_cache(cache_path, None)
        if prev is None:
            return KernelSupport(release=release, checked_at=now, error=reason)
        expired = load_cache(cache_path, now) is None
        return KernelSupport(release=release, mainline=prev.mainline, stable=prev.stable,
                             tier=classify(release, prev.mainline, prev.stable),
                             checked_at=prev.checked_at, error=reason, stale=expired)

    st = KernelSupport(release=release, mainline=mainline, stable=stable,
                       tier=classify(release, mainline, stable), checked_at=now)
    save_cache(st, cache_path)
    return st


# ---------------------------------------------------------------------------
# 面向用户的文案（放在这里以便单元测试，不依赖 GTK）
# ---------------------------------------------------------------------------
SUPPORT_CHECK_NOTE = "版本信息来自 kernel.org 的 releases.json，仅用于判断本机内核属于哪条版本线。"


def fetch_failed_text(st):
    """「未能核对」的直接原因。

    以前所有拿不到结论的情形都写成"没能连上 kernel.org"，可是本机 release 解析
    失败时网络明明是好的，这会把用户引向错误的方向（去查代理、DNS、防火墙）。
    """
    if st.have_upstream and st.release and not st.parsed:
        return f"无法解析本机内核版本串「{st.release}」，因此无法判断它属于哪条版本线。"
    return ("无法从 kernel.org 取得 mainline / stable 版本号"
            "（离线、代理拦截，或 Flatpak 的 network 权限已被收回）。")


def recheck_result_text(st):
    """手动重新检查结束后的一句话提示（Toast）。"""
    if not st.have_upstream:
        return "未能连上 kernel.org，内核版本线仍未核对"
    if not st.parsed:
        return f"已取得上游版本号，但无法解析本机内核「{st.release}」，版本线仍未核对"
    if st.error:
        return f"未能连上 kernel.org，继续沿用 {st.age_text() or '较早'}取得的版本号"
    return f"已重新核对内核版本线：{st.tier_text}"


def warning_text(st):
    """启动弹窗的正文：解释为什么旧分支上这些加固建议不可靠。"""
    return (
        f"检测到您正在使用的内核是 {st.release}（{st.major_minor}），"
        f"既不属于上游 mainline（当前 {st.mainline or '未知'}），"
        f"也不属于 stable（当前 {st.stable or '未知'}）。\n\n"
        "Linux 的各个 LTS 分支由于种种原因，均未包含上游全部的安全修复与加固改进。"
        "本程序据此给出的 sysctl 与内核启动参数建议，在这些旧分支上不保证能提供应有的加固效果："
        "有些参数在这些内核上根本不存在；有些即使写进启动命令行，也会被内核静默忽略"
        "（只在 dmesg 里留下一句“Unknown kernel command line parameters”），"
        "而本程序却会因为参数出现在 /proc/cmdline 里而误判为已加固。\n\n"
        "因此不建议您继续使用这条版本线上的内核：本程序在这些内核上给出的结论，不可作为安全加固的依据。"
        "如果条件允许，建议切换到 mainline 或 stable 内核：Fedora、openSUSE Tumbleweed "
        "等快速更新的发行版默认就跟踪 stable；Debian、Ubuntu LTS 等可以安装发行版提供的新内核"
        "（backports、HWE 或 mainline 内核包）。\n\n"
        "本次检测仍会照常进行，但「内核加固」页面的结论不可作为加固依据。"
    )


def banner_text(st):
    """内核页顶部横幅（比弹窗短）。"""
    return (f"当前内核 {st.release} 不在 mainline（{st.mainline or '未知'}）"
            f"或 stable（{st.stable or '未知'}）上。"
            "旧分支未包含上游全部的安全修复与加固改进，下列 sysctl 与启动参数建议在旧分支上"
            "不保证生效，不可作为加固依据；建议切换到 mainline 或 stable 内核。")


# 进程内共享的最近一次检查结果（checks.collect() 会读取它）
CURRENT = None


def set_current(st):
    global CURRENT
    CURRENT = st
    return CURRENT
