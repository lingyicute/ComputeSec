# -*- coding: utf-8 -*-
"""页面与通用控件构建。每个 build_* 函数接收 Report 与窗口对象并返回一个可滚动的页面控件。"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from . import data  # noqa: E402
from .checks import MISSING  # noqa: E402


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def esc(s):
    return GLib.markup_escape_text(str(s))


STATUS_STYLE = {
    "ok": ("emblem-ok-symbolic", "success"), "good": ("emblem-ok-symbolic", "success"),
    "missing": ("dialog-warning-symbolic", "warning"), "wrong": ("dialog-warning-symbolic", "warning"),
    "warn": ("dialog-warning-symbolic", "warning"),
    "bad": ("dialog-error-symbolic", "error"), "error": ("dialog-error-symbolic", "error"),
    "na": ("dialog-question-symbolic", "dim-label"), "unknown": ("dialog-question-symbolic", "dim-label"),
}
RATING_STYLE = {"good": ("security-high-symbolic", "success"), "neutral": ("security-medium-symbolic", "accent"),
                "caution": ("security-medium-symbolic", "warning"), "bad": ("security-low-symbolic", "error")}


def status_icon(status, size=None):
    name, css = STATUS_STYLE.get(status, STATUS_STYLE["unknown"])
    img = Gtk.Image.new_from_icon_name(name)
    img.add_css_class(css)
    if size:
        img.set_pixel_size(size)
    return img


def score_css(score):
    return "success" if score >= 80 else ("warning" if score >= 50 else "error")


def score_label(score, big=False):
    lbl = Gtk.Label(label=f"{score}")
    lbl.add_css_class(score_css(score))
    lbl.add_css_class("title-1" if big else "title-3")
    return lbl


def level_bar(score):
    bar = Gtk.LevelBar(min_value=0, max_value=100, hexpand=True, valign=Gtk.Align.CENTER)
    bar.add_offset_value("low", 50)
    bar.add_offset_value("high", 80)
    bar.add_offset_value("full", 100)
    bar.set_value(score)
    return bar


def wrapped_label(text, css=(), selectable=False, markup=False):
    lbl = Gtk.Label(xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, selectable=selectable, hexpand=True)
    if markup:
        lbl.set_markup(text)
    else:
        lbl.set_label(text)
    for c in css:
        lbl.add_css_class(c)
    return lbl


def code_block(text):
    lbl = Gtk.Label(label=text, xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, selectable=True, hexpand=True,
                    margin_top=10, margin_bottom=10, margin_start=12, margin_end=12)
    lbl.add_css_class("monospace")
    frame = Gtk.Frame()
    frame.add_css_class("view")
    frame.set_child(lbl)
    return frame


def copy_button(win, text, label="复制"):
    btn = Gtk.Button(valign=Gtk.Align.CENTER)
    btn.set_child(Adw.ButtonContent(icon_name="edit-copy-symbolic", label=label))

    def on_click(_b):
        Gdk.Display.get_default().get_clipboard().set(text)
        win.toast("已复制到剪贴板")

    btn.connect("clicked", on_click)
    return btn


def text_row(title, body, selectable=False):
    row = Adw.ActionRow(title=esc(title), subtitle=esc(body))
    row.set_subtitle_selectable(selectable)
    return row


def group(title, description=None):
    g = Adw.PreferencesGroup(title=title)
    if description:
        g.set_description(description)
    return g


def page(children, max_width=920):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
    for c in children:
        if c is not None:
            box.append(c)
    clamp = Adw.Clamp(maximum_size=max_width, tightening_threshold=640, margin_top=18, margin_bottom=36, margin_start=14, margin_end=14)
    clamp.set_child(box)
    sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
    sw.set_child(clamp)
    return sw


def banner(text, style="success", icon="emblem-ok-symbolic"):
    box = Gtk.Box(spacing=12, margin_top=12, margin_bottom=12, margin_start=14, margin_end=14)
    img = Gtk.Image.new_from_icon_name(icon)
    img.set_pixel_size(28)
    img.add_css_class(style)
    box.append(img)
    box.append(wrapped_label(text, css=("heading",)))
    frame = Gtk.Frame()
    frame.add_css_class("card")
    frame.set_child(box)
    return frame


def praise_row(text):
    row = Adw.ActionRow(title=esc(text))
    row.add_prefix(status_icon("good"))
    row.add_css_class("success")
    return row

def hero(icon_name, title, description=None, css=None, desc_css=None):
    """页面顶部的大图标 + 标题 + 副标题。
    不使用 Adw.StatusPage：它内部自带 Clamp(400px) 与 ScrolledWindow，嵌套在可滚动页面里会被压窄而显示不全。"""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=12, margin_bottom=6, hexpand=True)
    img = Gtk.Image.new_from_icon_name(icon_name)
    img.set_pixel_size(96)
    img.set_halign(Gtk.Align.CENTER)
    if css:
        img.add_css_class(css)
    box.append(img)
    t = Gtk.Label(label=title, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, justify=Gtk.Justification.CENTER,
                  halign=Gtk.Align.CENTER, margin_top=8)
    t.add_css_class("title-1")
    box.append(t)
    if description:
        d = Gtk.Label(label=description, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, justify=Gtk.Justification.CENTER,
                      halign=Gtk.Align.CENTER)
        d.add_css_class("title-4")
        if desc_css:
            d.add_css_class(desc_css)
        box.append(d)
    return box

# ---------------------------------------------------------------------------
# 仪表盘
# ---------------------------------------------------------------------------
def build_dashboard(report, win, navigate):
    overall = report.overall
    head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, halign=Gtk.Align.CENTER, margin_top=6)
    icon = Gtk.Image.new_from_icon_name(data.APP_ID)
    icon.set_pixel_size(96)
    head.append(icon)
    head.append(score_label(overall, big=True))
    grade = "安全状况良好，请继续保持！" if overall >= 80 else ("还有一些可以改进的地方" if overall >= 50 else "存在多项需要处理的风险")
    head.append(wrapped_label(grade, css=("title-4",)))
    head.get_last_child().set_halign(Gtk.Align.CENTER)
    sub = wrapped_label(f"{report.os_name} · 内核 {report.kernel} · {report.arch} · {report.cpu}", css=("dim-label", "caption"))
    sub.set_halign(Gtk.Align.CENTER)
    sub.set_justify(Gtk.Justification.CENTER)
    head.append(sub)

    flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True, max_children_per_line=2, min_children_per_line=1,
                       column_spacing=12, row_spacing=12)
    hsi_txt = (report.hsi.host_id or "已检测") if report.hsi.ok else "无法获取"
    hsi_score = report.hsi.score if report.hsi.ok else 0
    cards = [
        ("hsi", "HSI 固件安全", hsi_score, f"{hsi_txt}｜{len(report.hsi.failed)} 项未通过，其中 {len(report.hsi.fixable)} 项可修复" if report.hsi.ok else report.hsi.error, "security-high-symbolic"),
        ("kernel", "内核加固", report.kernel_score, f"内核参数缺失 {len(report.cmdline.missing)} 项｜sysctl 缺失 {len(report.sysctl.missing)} 项", "emblem-system-symbolic"),
        ("hardware", "硬件品牌", report.hardware.score, f"{report.hardware.vendor['name']} · {data.RATING_ZH[report.hardware.vendor['rating']]}", "computer-symbolic"),
        ("habits", "使用习惯", report.habits.score, "、".join(f"{c.title.split(' ')[0]}{'✓' if c.status == 'good' else '✗' if c.status in ('bad', 'warn') else '?'}" for c in report.habits.checks), "user-info-symbolic"),
    ]
    for key, title, score, desc, icon_name in cards:
        btn = Gtk.Button()
        btn.add_css_class("card")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_top=14, margin_bottom=14, margin_start=14, margin_end=14)
        top = Gtk.Box(spacing=10)
        ic = Gtk.Image.new_from_icon_name(icon_name)
        ic.set_pixel_size(24)
        ic.add_css_class(score_css(score))
        top.append(ic)
        t = Gtk.Label(label=title, xalign=0, hexpand=True)
        t.add_css_class("heading")
        top.append(t)
        top.append(score_label(score))
        box.append(top)
        box.append(level_bar(score))
        d = wrapped_label(desc, css=("dim-label", "caption"))
        d.set_lines(2)
        d.set_ellipsize(Pango.EllipsizeMode.END)
        box.append(d)
        btn.set_child(box)
        btn.connect("clicked", lambda _b, k=key: navigate(k))
        flow.append(btn)

    todo = group("待办摘要", "点击上方卡片查看详情与修复方法")
    n = 0
    if report.hsi.ok:
        for it in report.hsi.fixable[:6]:
            r = Adw.ActionRow(title=esc(it.name), subtitle=esc(data.HSI_KIND_ZH.get(it.info.get("kind"), "")))
            r.add_prefix(status_icon("warn"))
            r.set_activatable(True)
            r.connect("activated", lambda *_: navigate("hsi"))
            todo.add(r)
            n += 1
    if report.cmdline.missing:
        r = Adw.ActionRow(title=f"添加 {len(report.cmdline.missing)} 个内核启动参数", subtitle=esc(" ".join(i.token for i in report.cmdline.missing[:8]) + (" …" if len(report.cmdline.missing) > 8 else "")))
        r.add_prefix(status_icon("warn"))
        r.set_activatable(True)
        r.connect("activated", lambda *_: navigate("kernel"))
        todo.add(r)
        n += 1
    if report.sysctl.missing:
        r = Adw.ActionRow(title=f"设置 {len(report.sysctl.missing)} 个 sysctl 项", subtitle=esc("、".join(i.key for i in report.sysctl.missing[:6]) + (" …" if len(report.sysctl.missing) > 6 else "")))
        r.add_prefix(status_icon("warn"))
        r.set_activatable(True)
        r.connect("activated", lambda *_: navigate("kernel"))
        todo.add(r)
        n += 1
    if report.hardware.vendor["rating"] in ("bad", "caution"):
        r = Adw.ActionRow(title=esc(f"硬件品牌 {report.hardware.vendor['name']}：{data.RATING_ZH[report.hardware.vendor['rating']]}"), subtitle="查看历史安全事件与建议")
        r.add_prefix(status_icon("bad" if report.hardware.vendor["rating"] == "bad" else "warn"))
        r.set_activatable(True)
        r.connect("activated", lambda *_: navigate("hardware"))
        todo.add(r)
        n += 1
    for c in report.habits.checks:
        if c.status in ("bad", "warn"):
            r = Adw.ActionRow(title=esc(c.title), subtitle=esc(c.summary))
            r.add_prefix(status_icon(c.status))
            r.set_activatable(True)
            r.connect("activated", lambda *_: navigate("habits"))
            todo.add(r)
            n += 1
    if n == 0:
        todo.add(praise_row("没有待办事项，您的安全配置非常出色，请继续保持！"))

    note = None
    if report.in_flatpak:
        note = wrapped_label("提示：当前运行在 Flatpak 沙箱中。部分检测通过 D-Bus 与 flatpak-spawn 在宿主机上执行，若结果显示“无法获取”，请确认已授予相应权限。", css=("dim-label", "caption"))
    return page([head, flow, todo, note])


# ---------------------------------------------------------------------------
# HSI
# ---------------------------------------------------------------------------
def _hsi_item_row(it):
    row = Adw.ExpanderRow(title=esc(it.name))
    res = data.HSI_RESULT_ZH.get(it.result, it.result)
    row.set_subtitle(esc(f"{res}" + (f" · {it.summary}" if it.summary and it.summary != it.name else "")))
    row.add_prefix(status_icon("ok" if it.passed else ("warn" if it.info.get("fix") else "bad")))
    lvl = Gtk.Label(label=f"HSI:{it.level}" if it.level else "运行时", valign=Gtk.Align.CENTER)
    lvl.add_css_class("dim-label")
    lvl.add_css_class("caption")
    row.add_suffix(lvl)
    info = it.info
    row.add_row(text_row("检测项含义", info.get("meaning") or it.summary or "fwupd 未提供说明。"))
    row.add_row(text_row("缺失的危害", info.get("risk") or "该项未通过会削弱平台信任链。"))
    if info.get("fix"):
        row.add_row(text_row(f"修复方法（{data.HSI_KIND_ZH.get(info.get('kind'), '')}）", info["fix"]))
    if it.flags - {"success"}:
        row.add_row(text_row("fwupd 标记", ", ".join(sorted(it.flags))))
    row.add_row(text_row("AppStream ID", it.id + (f"  ·  {it.uri}" if it.uri else ""), selectable=True))
    return row


def build_hsi(report, win):
    h = report.hsi
    if not h.ok:
        sp = hero("dialog-error-symbolic", "无法获取 HSI 结果", h.error, "error", desc_css="dim-label")
        hint = group("如何安装 fwupd")
        hint.add(text_row("Fedora / RHEL", "sudo dnf install fwupd && sudo systemctl enable --now fwupd", selectable=True))
        hint.add(text_row("Debian / Ubuntu", "sudo apt install fwupd && sudo systemctl enable --now fwupd", selectable=True))
        hint.add(text_row("Arch Linux", "sudo pacman -S fwupd && sudo systemctl enable --now fwupd", selectable=True))
        hint.add(text_row("手动查看", "fwupdmgr security", selectable=True))
        return page([sp, hint])

    overview = group("总览", "HSI (Host Security ID) 由 fwupd 项目定义，用于衡量平台固件与硬件的安全基线。等级越高越安全，末尾带 ! 表示存在运行时问题。")
    r = Adw.ActionRow(title="Host Security ID", subtitle=esc(h.host_id or "未知"))
    r.add_suffix(score_label(h.score))
    overview.add(r)
    r2 = Adw.ActionRow(title="通过率", subtitle=f"{sum(1 for i in h.active if i.passed)} / {len(h.active)} 项通过 · 数据来源：{esc(h.source)}")
    r2.add_suffix(level_bar(h.score))
    overview.add(r2)

    fix = group("您可以修复", "以下未通过的项目可以由您自行操作修复。按修复途径分组，展开查看具体步骤。")
    fixable = h.fixable
    if not fixable:
        fix.add(praise_row("所有可由用户修复的项目均已通过，做得非常好！" if h.failed else "所有检测项全部通过，这是非常罕见的优秀配置！"))
    for kind in ("os", "bios"):
        for it in [i for i in fixable if i.info.get("kind") == kind]:
            row = Adw.ExpanderRow(title=esc(it.name), subtitle=esc(data.HSI_KIND_ZH[kind]))
            row.add_prefix(status_icon("warn"))
            row.add_row(text_row("为什么要修", it.info.get("risk", "")))
            row.add_row(text_row("如何修复", it.info["fix"]))
            fix.add(row)

    others = [i for i in h.failed if i not in fixable]
    unfix = None
    if others:
        unfix = group("无法自行修复的项目", "这些项目取决于硬件或厂商，若对您的威胁模型至关重要，请考虑更换硬件。")
        for it in others:
            unfix.add(_hsi_item_row(it))

    level_groups = []
    for lvl, title in ((1, "HSI:1 基础安全"), (2, "HSI:2 增强安全"), (3, "HSI:3 理论防护"), (4, "HSI:4 系统防护"), (0, "运行时检查")):
        items = [i for i in h.active if i.level == lvl]
        if not items:
            continue
        g = group(title, f"{sum(1 for i in items if i.passed)} / {len(items)} 项通过")
        for it in items:
            g.add(_hsi_item_row(it))
        level_groups.append(g)
    return page([overview, fix, unfix] + level_groups)


# ---------------------------------------------------------------------------
# 内核加固
# ---------------------------------------------------------------------------
def build_kernel(report, win):
    c, s = report.cmdline, report.sysctl
    cpu_zh = {"intel": "Intel", "amd": "AMD"}.get(c.cpu, "未知/非 x86")
    # ---- cmdline ----
    g1 = group("内核启动参数 (/proc/cmdline)", f"架构 {c.arch} · CPU {cpu_zh}。{data.KERNEL_MACHINE_SPECIFIC_NOTE}")
    g1.set_header_suffix(score_label(c.score))
    g1.add(code_block(c.cmdline or "（无法读取）"))
    for it in sorted(c.items, key=lambda i: ({"missing": 0, "wrong": 0, "ok": 1, "na": 2}[i.status], i.key)):
        row = Adw.ActionRow(title=f"<tt>{esc(it.token)}</tt>")
        sub = it.desc
        if it.note:
            sub += f"  ⚠ {it.note}"
        if it.status == "wrong":
            sub += f"  （当前值：{it.actual}）"
        if it.status == "na":
            sub += f"  （仅 {it.cpu.upper()} 平台适用，已跳过）"
        row.set_subtitle(esc(sub))
        row.add_prefix(status_icon(it.status))
        g1.add(row)

    g_fix = None
    if c.missing:
        tokens = " ".join(i.token for i in c.missing)
        g_fix = group("如何设置内核参数", "缺失的参数见下方代码块；各发行版的命令请用右侧按钮复制（已自动带上参数）。先把缺失参数一次性加入试运行一次；若启动失败，可在 GRUB 菜单按 e 临时删除参数。")
        g_fix.set_header_suffix(copy_button(win, tokens, "复制缺失参数"))
        g_fix.add(code_block(tokens))
        r = text_row("Fedora / RHEL / 使用 grubby 的系统", 'sudo grubby --update-kernel=ALL --args="<上方参数>"')
        r.add_suffix(copy_button(win, f'sudo grubby --update-kernel=ALL --args="{tokens}"', "复制命令"))
        g_fix.add(r)
        g_fix.add(text_row("Debian / Ubuntu / Arch (GRUB)", "编辑 /etc/default/grub，把参数追加到 GRUB_CMDLINE_LINUX_DEFAULT=\"...\" 中，然后运行 sudo update-grub（Arch: sudo grub-mkconfig -o /boot/grub/grub.cfg）。"))
        g_fix.add(text_row("systemd-boot / UKI", "把参数追加到 /etc/kernel/cmdline，然后运行 sudo kernel-install add-all（或重新生成 UKI）。也可编辑 /boot/loader/entries/*.conf 的 options 行。"))
        ostree_cmd = "sudo rpm-ostree kargs " + " ".join(f'--append-if-missing="{i.token}"' for i in c.missing)
        r = text_row("Fedora Silverblue / Kinoite", 'sudo rpm-ostree kargs --append-if-missing="<参数>" …（每个缺失参数一项）')
        r.add_suffix(copy_button(win, ostree_cmd, "复制命令"))
        g_fix.add(r)
        notes = [i for i in c.missing if i.note]
        if notes:
            g_fix.add(text_row("⚠ 副作用提醒", "\n".join(f"{i.token}：{i.note}" for i in notes)))
    else:
        g_fix = group("内核参数")
        g_fix.add(praise_row("推荐的内核启动参数全部已设置，非常出色，请继续保持！"))

    # ---- sysctl ----
    sys_groups = []
    for title, items in s.groups:
        g = group(f"sysctl · {title}", f"{sum(1 for i in items if i.status == 'ok')} / {sum(1 for i in items if i.status != 'na')} 项已设置")
        for it in sorted(items, key=lambda i: ({"missing": 0, "ok": 1, "na": 2}[i.status])):
            row = Adw.ActionRow(title=f"<tt>{esc(it.key)}</tt> = <tt>{esc(it.expected)}</tt>" + (" <small>(≥)</small>" if it.cmp == "ge" else ""))
            sub = it.desc + (f"  ⚠ {it.note}" if it.note else "")
            if it.status == "missing":
                sub += f"  （当前：{it.actual_text}）"
            elif it.status == "na":
                sub += "  （内核不支持或模块未加载）"
            row.set_subtitle(esc(sub))
            row.add_prefix(status_icon(it.status))
            g.add(row)
        sys_groups.append(g)

    g_sfix = None
    if s.missing:
        conf = "# Generated by ComputeSec\n" + "\n".join(f"{i.key} = {i.expected}" for i in s.missing) + "\n"
        g_sfix = group("如何设置 sysctl", "将以下内容写入 /etc/sysctl.d/99-computesec-hardening.conf 后执行 sudo sysctl --system 立即生效并在重启后保持。带 * 的通配符由 systemd-sysctl 支持。")
        g_sfix.set_header_suffix(copy_button(win, conf, "复制配置"))
        g_sfix.add(code_block(conf.strip()))
        cmd = f"sudo tee /etc/sysctl.d/99-computesec-hardening.conf > /dev/null <<'EOF'\n{conf}EOF\nsudo sysctl --system"
        r = text_row("一键写入命令", "用 sudo tee 把上方配置写入 /etc/sysctl.d/99-computesec-hardening.conf，然后执行 sudo sysctl --system。点击右侧按钮复制完整命令（已包含上方配置内容）。")
        r.add_suffix(copy_button(win, cmd, "复制命令"))
        g_sfix.add(r)
        notes = [i for i in s.missing if i.note]
        if notes:
            g_sfix.add(text_row("⚠ 副作用提醒", "\n".join(f"{i.key}：{i.note}" for i in notes)))
        g_sfix.add(text_row("提示", "kernel.kexec_load_disabled 一旦设为 1 直到重启前都无法改回；kernel.io_uring_disabled、kernel.oops_limit/warn_limit 需要较新内核；显示“内核不支持”的项目可以从配置中删掉。"))
    else:
        g_sfix = group("sysctl")
        g_sfix.add(praise_row("推荐的 sysctl 全部已设置，非常出色，请继续保持！"))

    g_arm = None
    if s.arch == "aarch64":
        g_arm = group("aarch64 ASLR 提示")
        g_arm.add(code_block(data.SYSCTL_AARCH64_NOTE))
    return page([g1, g_fix] + sys_groups + [g_sfix, g_arm])


# ---------------------------------------------------------------------------
# 硬件品牌
# ---------------------------------------------------------------------------
def build_hardware(report, win):
    hw = report.hardware
    v = hw.vendor
    icon, css = RATING_STYLE[v["rating"]]
    sp = hero(icon, v["name"], data.RATING_ZH[v["rating"]], css, desc_css=css)

    info = group("检测到的硬件信息")
    for label, val in (("系统厂商", hw.sys_vendor), ("产品名称", hw.product), ("主板厂商", hw.board_vendor),
                       ("固件厂商", hw.bios_vendor), ("固件版本", hw.bios_version), ("设备树型号", hw.model), ("匹配依据", hw.matched_on)):
        if val:
            info.add(text_row(label, val, selectable=True))
    if not (hw.sys_vendor or hw.product or hw.model):
        info.add(text_row("提示", "无法读取 DMI/设备树信息。"))

    hist = group("历史安全 / 隐私事件", "信息来自公开报道与 CVE 记录，仅供参考。")
    for title, desc in v["incidents"]:
        hist.add(text_row(title, desc))

    adv_status = {"good": "good", "neutral": "unknown", "caution": "warn", "bad": "bad"}[v["rating"]]
    adv = group("评估与建议")
    row = Adw.ActionRow(title=esc(v["advice"]))
    row.add_prefix(status_icon(adv_status))
    adv.add(row)
    if v["rating"] == "bad":
        adv.add(text_row("什么是“高安全性计算”", "例如：保管加密货币私钥、PGP/SSH 主密钥、处理机密文件、记者与维权人士的通信、运行受信任的构建环境等。这些场景下硬件层面的任何可疑历史都应被视为不可接受的风险。"))
    elif v["rating"] == "good":
        adv.add(praise_row("您选择了一家信誉良好的硬件厂商，这是安全计算的坚实基础，请继续保持！"))
    general = group("通用建议")
    general.add(text_row("固件更新", "无论品牌如何，都请通过 fwupdmgr update / GNOME 软件保持固件最新，并在固件设置中启用安全启动、TPM 与 IOMMU。"))
    general.add(text_row("开源固件", "若机型支持 coreboot / Dasharo / Heads，刷入开源固件能显著提高可审计性。"))
    return page([sp, info, hist, adv, general])


# ---------------------------------------------------------------------------
# 使用习惯
# ---------------------------------------------------------------------------
def build_habits(report, win):
    hb = report.habits
    all_good = all(c.status == "good" for c in hb.checks)
    top = banner("四项使用习惯检查全部通过！您的安全习惯非常好，请继续保持。", "success") if all_good else None
    groups = []
    for c in hb.checks:
        g = group(c.title)
        g.set_header_suffix(status_icon(c.status, 22))
        head = Adw.ActionRow(title=esc(c.summary))
        head.add_prefix(status_icon(c.status))
        if c.status == "good":
            head.add_css_class("success")
        g.add(head)
        for d in c.details:
            g.add(text_row("详情", d))
        if c.advice:
            g.add(text_row("建议" if c.status != "good" else "继续保持", c.advice))
        if c.key == "flatpak":
            r = text_row("harden-flatpak", data.HARDEN_FLATPAK_URL, selectable=True)
            btn = Gtk.Button(valign=Gtk.Align.CENTER, icon_name="external-link-symbolic" if Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).has_icon("external-link-symbolic") else "web-browser-symbolic")
            btn.connect("clicked", lambda *_: Gtk.UriLauncher.new(data.HARDEN_FLATPAK_URL).launch(win, None, None, None))
            r.add_suffix(btn)
            g.add(r)
            g.add(text_row("快速上手", "git clone https://github.com/lingyicute/harden-flatpak && cd harden-flatpak && ./lockdown.sh\n之后安装 Flatseal（com.github.tchx84.Flatseal）逐个应用按需放开权限。", selectable=True))
        groups.append(g)
    return page([top] + groups)
