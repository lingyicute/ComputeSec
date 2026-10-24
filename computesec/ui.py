# -*- coding: utf-8 -*-
"""页面与通用控件构建。每个 build_* 函数接收 Report 与窗口对象并返回一个可滚动的页面控件。"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from . import data, kernelver  # noqa: E402


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def esc(s):
    return GLib.markup_escape_text(str(s))


# ---------------------------------------------------------------------------
# 应用级样式
# ---------------------------------------------------------------------------
# GtkFlowBox 会把每个子控件自动包进一层 GtkFlowBoxChild，而 libadwaita 为它定义了
# （src/stylesheet/widgets/_views.scss）：
#
#     flowbox > flowboxchild, gridview > child { padding: 3px; border-radius: 9px; }
#     flowbox > flowboxchild,
#     gridview > child.activatable            { &:hover { background-color: …; } }
#
# 注意 .activatable 只限定了 gridview > child，flowboxchild 是无条件匹配的，
# 因此即便 selection-mode=NONE 也会画出悬浮高亮。于是仪表盘上的评分卡片出现两个问题：
#   1. 尺寸：包装层比卡片四周各大 3px（padding），高亮因此“超出”卡片；
#   2. 形状：包装层圆角 9px，而 button.card 是 12px，方角会从圆角外露出来。
#
# 卡片本身（button.card:hover）已经有正确对齐、正确圆角的悬浮效果，包装层那层是多余的。
# 这里只去掉包装层的 padding 与背景，保留焦点框（键盘导航仍需要它）。
_CSS = b"""
flowbox.cards > flowboxchild {
  padding: 0;
  border-radius: 12px;
}
flowbox.cards > flowboxchild:hover,
flowbox.cards > flowboxchild:active,
flowbox.cards > flowboxchild:selected {
  background-color: transparent;
  background-image: none;
}
"""
_css_loaded = False


def ensure_css():
    """把上面的样式挂到默认 display 上（只需一次）。"""
    global _css_loaded
    if _css_loaded:
        return
    display = Gdk.Display.get_default()
    if display is None:
        return
    provider = Gtk.CssProvider()
    try:
        # GTK ≥ 4.12 弃用了带长度参数的 load_from_data，改用 load_from_string
        if hasattr(provider, "load_from_string"):
            provider.load_from_string(_CSS.decode())
        else:
            provider.load_from_data(_CSS)
    except Exception:
        return
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _css_loaded = True


STATUS_STYLE = {
    "ok": ("object-select-symbolic", "success"), "good": ("object-select-symbolic", "success"),
    "missing": ("dialog-warning-symbolic", "warning"), "wrong": ("dialog-warning-symbolic", "warning"),
    "warn": ("dialog-warning-symbolic", "warning"),
    "bad": ("dialog-error-symbolic", "error"), "error": ("dialog-error-symbolic", "error"),
    "na": ("dialog-question-symbolic", "dim-label"), "unknown": ("dialog-question-symbolic", "dim-label"),
    "unverified": ("dialog-question-symbolic", "dim-label"),
    # “疑似”只提醒、不扣分：图标与 warn 一致，但 HabitsReport 给满分
    "suspect": ("dialog-warning-symbolic", "warning"),
    "locked": ("channel-secure-symbolic", "dim-label"),
}
# 使用习惯卡片里的单字符状态标记：疑似（suspect）只提醒、不扣分，用「?」区分于明确的 ✓ / ✗
_HABIT_MARK = {"good": "✓", "suspect": "?", "warn": "✗", "bad": "✗", "unknown": "?"}
_HABIT_ADVICE_TITLE = {"good": "继续保持", "suspect": "请自行确认"}
RATING_STYLE = {"good": ("security-high-symbolic", "success"), "neutral": ("security-medium-symbolic", "accent"),
                "caution": ("security-medium-symbolic", "warning"), "bad": ("security-low-symbolic", "error")}


def status_icon(status, size=None):
    name, css = STATUS_STYLE.get(status, STATUS_STYLE["unknown"])
    img = Gtk.Image.new_from_icon_name(name)
    img.add_css_class(css)
    if size:
        img.set_pixel_size(size)
    return img


# 评分可能是 None：该板块没有任何可评估的项目（例如没有 fwupd、非 x86/arm 架构、
# 或所有条目都因为权限/沙箱限制被排除）。此时显示「—」并标注"无法评估"，
# 而不是把它当成 0 分——0 分意味着"已评估且很差"，与事实不符。
SCORE_NA = "—"


def score_css(score):
    if score is None:
        return "dim-label"
    return "success" if score >= 80 else ("warning" if score >= 50 else "error")


def score_str(score):
    return SCORE_NA if score is None else str(score)


def score_label(score, big=False):
    lbl = Gtk.Label(label=score_str(score))
    lbl.add_css_class(score_css(score))
    lbl.add_css_class("title-1" if big else "title-3")
    if score is None:
        lbl.set_tooltip_text("无法评估：没有可用于评分的检测项")
    return lbl


def level_bar(score):
    bar = Gtk.LevelBar(min_value=0, max_value=100, hexpand=True, valign=Gtk.Align.CENTER)
    bar.add_offset_value("low", 50)
    bar.add_offset_value("high", 80)
    bar.add_offset_value("full", 100)
    bar.set_value(0 if score is None else score)
    if score is None:
        bar.add_css_class("dim-label")
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


def banner(text, style="success", icon="object-select-symbolic"):
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

def kernel_warning_dialog(st):
    """构造"内核不在受支持版本线上"的提示对话框（不显示，由调用方 present）。"""
    body = kernelver.warning_text(st)
    if hasattr(Adw, "AlertDialog"):      # libadwaita >= 1.5
        dlg = Adw.AlertDialog(heading="当前内核不在 mainline / stable 上", body=body)
        dlg.add_response("ok", "我知道了")
        dlg.set_default_response("ok")
        dlg.set_close_response("ok")
        return dlg
    dlg = Adw.MessageDialog(modal=True, heading="当前内核不在 mainline / stable 上", body=body)
    dlg.add_response("ok", "我知道了")
    dlg.set_default_response("ok")
    dlg.set_close_response("ok")
    dlg.connect("response", lambda d, _r: d.close())
    return dlg


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
    if overall is None:
        grade = "无法评估：没有可用的检测项，请检查上面的提示"
    else:
        grade = "安全状况良好，请继续保持！" if overall >= 90 else ("还有一些可以改进的地方" if overall >= 70 else "存在多项需要处理的风险")
    head.append(wrapped_label(grade, css=("title-4",)))
    head.get_last_child().set_halign(Gtk.Align.CENTER)
    parts = [report.os_name, f"内核 {report.kernel}", report.arch]
    if report.cpu and report.cpu != report.arch:
        parts.append(report.cpu)
    sub = wrapped_label(" · ".join(parts), css=("dim-label", "caption"))
    sub.set_halign(Gtk.Align.CENTER)
    sub.set_justify(Gtk.Justification.CENTER)
    head.append(sub)

    ensure_css()
    flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True, max_children_per_line=2, min_children_per_line=1,
                       column_spacing=12, row_spacing=12)
    # 配合 _CSS：去掉 flowboxchild 那层多余且比卡片大一圈的悬浮高亮
    flow.add_css_class("cards")
    hsi_txt = (report.hsi.host_id or "已检测") if report.hsi.ok else "无法获取"
    hsi_score = report.hsi.score
    if report.hsi.ok:
        hsi_desc = f"{hsi_txt}｜{len(report.hsi.failed)} 项未通过，其中 {len(report.hsi.fixable)} 项可修复"
        if report.hsi.undetermined:
            hsi_desc += f"，另有 {len(report.hsi.undetermined)} 项数据缺失无法判定"
    else:
        hsi_desc = report.hsi.error
    cards = [
        ("hsi", "HSI 固件安全", hsi_score, hsi_desc, "security-high-symbolic"),
        ("kernel", "内核加固", report.kernel_score, f"内核参数缺失 {len(report.cmdline.missing)} 项｜sysctl 缺失 {len(report.sysctl.missing)} 项", "emblem-system-symbolic"),
        ("hardware", "硬件品牌", report.hardware.score, f"{report.hardware.vendor['name']} · {data.RATING_ZH[report.hardware.vendor['rating']]}", "computer-symbolic"),
        ("habits", "使用习惯", report.habits.score, "、".join(f"{c.title.split(' ')[0]}{_HABIT_MARK.get(c.status, '?')}" for c in report.habits.checks), "avatar-default-symbolic"),
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
        # 包装层默认也可获得焦点，Tab 导航时会在按钮自身的焦点框之外再画一个；
        # 让焦点直接落到按钮上。
        child = flow.get_last_child()
        if child is not None:
            child.set_focusable(False)

    todo = group("待办摘要", "点击卡片或下方条目查看详情与修复方法")
    n = 0

    def _add_todo(title, subtitle, status, target):
        nonlocal n
        r = Adw.ActionRow(title=title, subtitle=subtitle)
        r.add_prefix(status_icon(status))
        r.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
        r.set_activatable(True)
        r.connect("activated", lambda *_, t=target: navigate(t))
        todo.add(r)
        n += 1

    if report.hsi.ok:
        for it in report.hsi.fixable[:6]:
            _add_todo(esc(it.name), esc(data.HSI_KIND_ZH.get(it.info.get("kind"), "")), "warn", "hsi")
    if report.cmdline.missing:
        _add_todo(f"添加 {len(report.cmdline.missing)} 个内核启动参数",
                  esc(" ".join(i.token for i in report.cmdline.missing[:8]) + (" …" if len(report.cmdline.missing) > 8 else "")),
                  "warn", "kernel")
    if report.sysctl.missing:
        _add_todo(f"设置 {len(report.sysctl.missing)} 个 sysctl 项",
                  esc("、".join(i.key for i in report.sysctl.missing[:6]) + (" …" if len(report.sysctl.missing) > 6 else "")),
                  "warn", "kernel")
    if report.hardware.vendor["rating"] in ("bad", "caution"):
        _add_todo(esc(f"硬件品牌 {report.hardware.vendor['name']}：{data.RATING_ZH[report.hardware.vendor['rating']]}"),
                  "查看历史安全事件与建议",
                  "bad" if report.hardware.vendor["rating"] == "bad" else "warn", "hardware")
    for c in report.habits.checks:
        if c.status in ("bad", "warn", "suspect"):
            _add_todo(esc(c.title), esc(c.summary), c.status, "habits")
    _ks = getattr(report, "kernel_support", None)
    if _ks is not None and _ks.known and not _ks.supported:
        _add_todo(f"当前内核 {esc(_ks.release)} 不在 mainline / stable 版本线上",
                  "旧分支未包含上游全部安全修复与加固改进，下面的加固建议不保证生效", "warn", "kernel")
    if report.hsi.ok and report.hsi.undetermined:
        _add_todo(f"有 {len(report.hsi.undetermined)} 项 HSI 检测因为缺少数据而无法判定",
                  "这不是未通过，也无法通过改配置解决；展开 HSI 页面可查看具体项目", "unknown", "hsi")
    if n == 0:
        todo.add(praise_row("没有待办事项，您的安全配置非常出色，请继续保持！"))

    extras = []
    hd = report.hostdata
    if hd is not None and not hd.any_data:
        g = group("补全检测数据", "有几项信息普通用户权限读不到（如 vm.mmap_rnd_bits）。ComputeSec 不请求提权、也不在宿主机上代您执行命令，"
                                 "而是引导您自己执行一条只读命令并复制结果。")
        r = Adw.ActionRow(title="运行数据采集向导", subtitle="约 30 秒，结果只保存在本机，重启后自动失效")
        r.add_prefix(status_icon("warn"))
        r.add_suffix(_collect_button(win))
        r.set_activatable(True)
        r.connect("activated", lambda *_: win.open_wizard())
        g.add(r)
        extras.append(g)

    note = None
    if report.in_flatpak:
        ident = report.identity
        src = f"系统信息来源：{ident.source}。" if ident is not None and ident.source else ""
        note = wrapped_label(
            "提示：当前运行在 Flatpak 沙箱中。ComputeSec 仅能通过只读 D-Bus 接口（fwupd、hostname1）与沙箱内可读的 /proc、/sys 采集数据，"
            "无法在宿主机上执行命令。" + src, css=("dim-label", "caption"))
    return page([head, flow, todo] + extras + [note])


# ---------------------------------------------------------------------------
# HSI
# ---------------------------------------------------------------------------
def lazy_expander(row, populate):
    """让 Adw.ExpanderRow 的子行在首次展开时才构建。

    折叠状态下这些子行是看不见的，但仍会被创建并参与尺寸计算。HSI 页面上有
    几十个这样的展开行，每行 3-5 个子行，一次性构建会明显拖慢首次绘制。
    """
    # 状态保存在闭包里，而不是往 GObject 上挂属性：PyGObject 的 Python 包装对象
    # 不保证跨 C 边界存活，属性丢失会导致再次展开时重复插入子行。
    done = []

    def on_expanded(r, _pspec):
        if done or not r.get_expanded():
            return
        done.append(True)
        populate(r)
        if handler:
            r.disconnect(handler[0])        # 只需触发一次

    handler = []
    handler.append(row.connect("notify::expanded", on_expanded))
    return row


def _hsi_item_row(it):
    row = Adw.ExpanderRow(title=esc(it.name))
    res = data.HSI_RESULT_ZH.get(it.result, it.result)
    row.set_subtitle(esc(f"{res}" + (f" · {it.summary}" if it.summary and it.summary != it.name else "")))
    fixable = bool(it.info.get("fix") and it.info.get("kind") in ("os", "bios"))
    # undetermined（fwupd 缺少数据）既不是通过也不是失败，用问号图标区分开
    status = "ok" if it.passed else ("unknown" if it.undetermined else ("warn" if fixable else "bad"))
    row.add_prefix(status_icon(status))
    lvl = Gtk.Label(label=f"HSI:{it.level}" if it.level else "运行时", valign=Gtk.Align.CENTER)
    lvl.add_css_class("dim-label")
    lvl.add_css_class("caption")
    row.add_suffix(lvl)

    def populate(r):
        info = it.info
        if it.undetermined:
            r.add_row(text_row("为什么无法判定",
                               "fwupd 将这一项标记为 missing-data：判定所需的数据（固件接口、TPM、"
                               "安全启动变量等）在当前平台上读不到。这不代表该防护缺失，"
                               "也无法通过修改系统配置来「修复」；若要确认真实状态，请进入固件设置自行检查。"))
        r.add_row(text_row("检测项含义", info.get("meaning") or it.summary or "fwupd 未提供说明。"))
        r.add_row(text_row("缺失的危害", info.get("risk") or "该项未通过会削弱平台信任链。"))
        if info.get("fix"):
            kind_zh = data.HSI_KIND_ZH.get(info.get("kind"), "")
            r.add_row(text_row(f"修复方法（{kind_zh}）" if kind_zh else "修复方法", info["fix"]))
        if it.flags - {"success"}:
            r.add_row(text_row("fwupd 标记", ", ".join(sorted(it.flags))))
        r.add_row(text_row("AppStream ID", it.id + (f"  ·  {it.uri}" if it.uri else ""), selectable=True))

    return lazy_expander(row, populate)


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
    scored = h.scored
    passed = sum(1 for i in scored if i.passed)
    r2 = Adw.ActionRow(title="通过率", subtitle=f"{passed} / {len(scored)} 项通过 · 数据来源：{esc(h.source)}"
                        if scored else f"没有可评估的检测项 · 数据来源：{esc(h.source)}")
    r2.add_suffix(level_bar(h.score))
    overview.add(r2)
    if h.undetermined:
        r3 = Adw.ActionRow(title="数据缺失，无法判定",
                           subtitle=f"{len(h.undetermined)} 项检测所需的固件数据由 fwupd 判定为缺失（常见于虚拟机、"
                                    "没有 TPM 的老机器或固件未暴露对应接口）。这些项目不计入通过率，也不是失败。")
        r3.add_prefix(status_icon("unknown"))
        overview.add(r3)

    fix = group("您可以修复", "以下未通过的项目可以由您自行操作修复。按修复途径分组，展开查看具体步骤。")
    fixable = h.fixable
    if not fixable:
        fix.add(praise_row("所有可由用户修复的项目均已通过，做得非常好！" if h.failed else "所有检测项全部通过，这是非常罕见的优秀配置！"))
    for kind in ("os", "bios"):
        for it in [i for i in fixable if i.info.get("kind") == kind]:
            row = Adw.ExpanderRow(title=esc(it.name), subtitle=esc(data.HSI_KIND_ZH[kind]))
            row.add_prefix(status_icon("warn"))

            def populate(r, it=it):
                r.add_row(text_row("为什么要修", it.info.get("risk", "")))
                r.add_row(text_row("如何修复", it.info["fix"]))

            fix.add(lazy_expander(row, populate))

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
def _collect_button(win, label="采集系统数据"):
    btn = Gtk.Button(valign=Gtk.Align.CENTER)
    btn.set_child(Adw.ButtonContent(icon_name="utilities-terminal-symbolic", label=label))
    btn.add_css_class("suggested-action")
    btn.connect("clicked", lambda *_: win.open_wizard())
    return btn


def _kernel_check_button(win, label="重试"):
    """重新核对版本线的按钮。win 可能是测试里的替身，缺方法时就不接。"""
    btn = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
    btn.add_css_class("flat")

    def on_click(_b=None):
        start = getattr(win, "start_kernel_check", None)
        if start is None:
            return
        # 已有检查在进行时 start 返回 False：不再重复提示，结果出来时会另有 Toast。
        if start(force=True) and hasattr(win, "toast"):
            win.toast("正在重新核对内核版本线…")

    btn.connect("clicked", on_click)
    return btn


def _kernel_support_block(report, win=None):
    """内核版本线：给出上游版本号、本机所处的版本线，以及结论是否可信。

    背景：LTS 分支未包含上游全部安全修复与加固改进，部分加固参数在旧内核上不存在，
    或写入命令行后被内核静默忽略（/proc/cmdline 里却仍有——本程序会误判为已设置）。

    三种状态必须能区分开：
      * 还没查过（启动时联网检查与首次检测并行）→ 不显示，免得先闪一下"未能核对"；
      * 查过但没拿到数据 → 明说"未能核对"并给出重试，而不是静默当作没问题；
      * 拿到了但是旧缓存 → 显示结论，同时标注版本号有多旧。
    """
    st = getattr(report, "kernel_support", None)
    if st is None:
        return []

    if not st.known:
        g = group("内核版本线", kernelver.SUPPORT_CHECK_NOTE)
        row = Adw.ActionRow(title="未能核对内核版本线",
                            subtitle="无法从 kernel.org 取得 mainline / stable 版本号"
                                     "（离线、代理拦截，或 Flatpak 的 network 权限已被收回）。"
                                     "这不代表内核有问题，只是本次没有结论。")
        row.add_prefix(status_icon("unknown"))
        if st.error:
            row.set_tooltip_text(st.error)
        row.add_suffix(_kernel_check_button(win))
        g.add(row)
        return [g]

    g = group("内核版本线", kernelver.SUPPORT_CHECK_NOTE)
    g.add(text_row("当前内核", st.release))
    g.add(text_row("mainline", st.mainline or "未知", selectable=True))
    g.add(text_row("stable", st.stable or "未知", selectable=True))
    row = Adw.ActionRow(title=esc(st.tier_text))
    row.add_prefix(status_icon("good" if st.supported else "warn"))
    g.add(row)

    if st.stale:
        age = st.age_text() or "较早"
        old = Adw.ActionRow(title="版本号来自旧缓存",
                            subtitle=f"这些版本号是 {age}取得的，本次没能连上 kernel.org，"
                                     "因此上面的判断可能已经过时。")
        old.add_prefix(status_icon("unknown"))
        if st.error:
            old.set_tooltip_text(st.error)
        old.add_suffix(_kernel_check_button(win))
        g.add(old)
    elif st.checked_at:
        g.add(text_row("核对时间", st.age_text()))

    if st.supported:
        return [g]
    return [banner(kernelver.banner_text(st), "warning", icon="dialog-warning-symbolic"), g]


def build_kernel(report, win):
    c, s = report.cmdline, report.sysctl
    cpu_zh = {"intel": "Intel", "amd": "AMD"}.get(c.cpu, "未知/非 x86")

    # ---- 数据来源 / 采集提示 ----
    # 只有确实存在"拿不到 / 不可信"的条目时才显示这一栏：Flatpak 本身不是问题，
    # 沙箱里能读到的条目（kernel.*、vm.*、fs.* 等）本来就是宿主机视图。
    g_src = None
    n = len(s.unknown)
    m = len(s.unverified)
    m_net = sum(1 for i in s.unverified if i.source == "沙箱网络隔离")
    if s.user_supplied or n or m:
        parts = []
        if s.user_supplied:
            title = "数据来源：您提供的 sysctl -a"
            parts.append(f"已使用您提供的 sysctl 输出（{report.hostdata.age_text if report.hostdata else ''}采集）。")
            if n:
                parts.append(f"仍有 {n} 项无法判定，可能是您执行命令时没有加 sudo。")
            if m:
                parts.append(f"另有 {m} 项不在您提供的输出中（可能被 2>/dev/null 过滤，或该内核没有这一项）；"
                             "沙箱内的读数不可信，已忽略，未计入评分。")
        else:
            title = "部分数据不完整"
            if m_net:
                parts.append(f"当前有 {m_net} 项 net.* 参数只能在宿主机上读取：Flatpak 沙箱没有共享宿主网络，"
                             "沙箱内的 net.* 属于独立的网络命名空间，数值与宿主机的加固状态无关，"
                             "已忽略且未计入评分。")
            if n:
                parts.append(f"当前有 {n} 项 sysctl 因为文件仅 root 可读而无法判定（例如 vm.mmap_rnd_bits），未计入评分。")
            parts.append("点击右侧按钮，按向导在终端执行一条只读命令并复制结果，即可得到完整准确的评估。")
        g_src = group(title, "".join(parts))
        g_src.set_header_suffix(_collect_button(win, "重新采集" if s.user_supplied else "采集系统数据"))

    # ---- cmdline ----
    g1 = group("内核当前启动参数和加固状态", f"架构: {c.arch} · CPU 制造商: {cpu_zh}\n{data.KERNEL_MACHINE_SPECIFIC_NOTE}")
    g1.set_header_suffix(score_label(c.score))
    g1.add(code_block(c.cmdline or "（无法读取）"))
    # 排序权重用 .get 兜底：将来给 ParamItem 加第五种状态时，这里不该变成一个
    # KeyError——那会被 build_page 捕获成整页「页面渲染失败」，代价太大。
    _order = {"missing": 0, "wrong": 0, "ok": 1, "na": 2}
    for it in sorted(c.items, key=lambda i: (_order.get(i.status, 9), i.key)):
        row = Adw.ActionRow(title=f"<tt>{esc(it.token)}</tt>")
        sub = it.desc
        if it.note:
            sub += f"  ⚠ {it.note}"
        if it.status == "wrong":
            sub += f"  （当前值：{it.actual if it.actual is not None else '无参数值'}）"
        if it.status == "na":
            # cpu 为 None 时说明这个 na 不是"平台不适用"造成的（例如将来新增的
            # 版本门控）。UI 抛异常会被 build_page 捕获成"页面渲染失败"，宁可降级成通用文案。
            sub += (f"  （仅 {it.cpu.upper()} 平台适用，已跳过）" if it.cpu
                    else "  （在当前平台上不适用，已跳过）")
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
    order = {"missing": 0, "unknown": 1, "unverified": 1, "ok": 2, "na": 3}
    for title, items in s.groups:
        g = group(f"sysctl · {title}", f"{sum(1 for i in items if i.status == 'ok')} / {sum(1 for i in items if i.status not in ('na', 'unknown', 'unverified'))} 项已设置")
        for it in sorted(items, key=lambda i: (order.get(i.status, 9), i.key)):
            row = Adw.ActionRow(title=f"<tt>{esc(it.key)}</tt> = <tt>{esc(it.expected)}</tt>" + (" <small>(≥)</small>" if it.cmp == "ge" else ""))
            sub = it.desc + (f"  ⚠ {it.note}" if it.note else "")
            if it.status == "missing":
                sub += f"  （当前：{it.actual_text}）"
            elif it.status == "na":
                sub += "  （内核不支持或模块未加载）"
            elif it.status == "unknown":
                sub += "  （该文件仅 root 可读，未参与评分；请用主菜单的「重新采集系统数据」提供 sudo sysctl -a 的结果）"
            elif it.status == "unverified" and it.source == "沙箱网络隔离":
                sub += ("  （Flatpak 沙箱没有共享宿主网络，这一项在沙箱内属于独立的网络命名空间，"
                        "读数与宿主机无关，已忽略且未参与评分；可在「数据采集向导」中提供 sudo sysctl -a 的结果）")
            elif it.status == "unverified":
                sub += ("  （您提供的 sysctl -a 快照中没有这一项；沙箱内的读数不是宿主机视图，"
                        "已忽略且未参与评分）")
            row.set_subtitle(esc(sub))
            row.add_prefix(status_icon("locked" if it.status == "unknown" else it.status))
            if it.source == "用户提供":
                tag = Gtk.Label(label="您提供", valign=Gtk.Align.CENTER)
                tag.add_css_class("caption")
                tag.add_css_class("dim-label")
                row.add_suffix(tag)
            g.add(row)
        sys_groups.append(g)

    g_sfix = None
    if s.missing:
        conf = "# Generated by ComputeSec\n" + "\n".join(f"{i.key} = {i.expected}" for i in s.missing) + "\n"
        g_sfix = group("如何设置 sysctl", "将以下内容写入 /etc/sysctl.d/99-computesec-hardening.conf 后执行 sudo sysctl --system 立即生效并在重启后保持。带 * 的通配符由 systemd-sysctl 支持。")
        g_sfix.set_header_suffix(copy_button(win, conf, "复制配置"))
        g_sfix.add(code_block(conf.strip()))
        cmd = f"sudo tee -a /etc/sysctl.d/99-computesec-hardening.conf > /dev/null <<'EOF'\n{conf}EOF\nsudo sysctl --system"
        r = text_row("一键写入命令", "用 sudo tee -a 把上方配置追加写入 /etc/sysctl.d/99-computesec-hardening.conf，然后执行 sudo sysctl --system。追加模式不会覆盖此前已写入的旧配置；重复执行产生的同名重复条目由 sysctl 按最后一条生效，不影响结果。点击右侧按钮复制完整命令（已包含上方配置内容）。")
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
    return page(_kernel_support_block(report, win) + [g_src, g1, g_fix] + sys_groups + [g_sfix, g_arm])


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

    ident = report.identity
    if ident is not None:
        sysinfo = group("宿主机系统信息", "通过 D-Bus 接口 org.freedesktop.hostname1 读取，因此在 Flatpak 内也是您真实的系统信息，"
                                          "而不是 runtime（org.gnome.Platform）的字段。")
        for label, val in (("操作系统", ident.pretty_name), ("CPE 名称", ident.cpe_name),
                           ("内核", " ".join(x for x in (ident.kernel_name, ident.kernel_release) if x)),
                           ("机箱类型", ident.chassis), ("主机名", ident.static_hostname or ident.hostname),
                           ("数据来源", ident.source)):
            if val:
                sysinfo.add(text_row(label, val, selectable=True))
        if ident.dbus_error:
            fb = f"（已回退到 {ident.source}）" if ident.source else ""
            sysinfo.add(text_row("⚠ D-Bus 读取失败", ident.dbus_error + fb))
        info_extra = sysinfo
    else:
        info_extra = None

    hist = group("历史安全 / 隐私事件", "信息来自公开报道与 CVE 记录，仅供参考。")
    for title, desc in v["incidents"]:
        hist.add(text_row(title, desc))

    adv_status = {"good": "good", "neutral": "unknown", "caution": "warn", "bad": "bad"}[v["rating"]]
    adv = group("评估与建议")
    row = Adw.ActionRow(title=esc(v["advice"]))
    row.add_prefix(status_icon(adv_status))
    adv.add(row)
    if v["rating"] == "bad":
        adv.add(text_row("什么是“高安全性计算”", "顾名思义，是指那些容错率极低、必须抵御高强度攻击的计算场景。比如处理核心机密文件、保管加密货币私钥或关键密钥、运行不能遭到篡改的受信任构建环境，以及高风险群体（如记者、维权人士）的敏感通信与办公等。在这些场景下，硬件层面的任何可疑历史都应被视为不可接受的风险。"))
    elif v["rating"] == "good":
        adv.add(praise_row("您选择了一家信誉良好的硬件厂商，这是安全计算的坚实基础，请继续保持！"))
    general = group("通用建议")
    general.add(text_row("固件更新", "无论品牌如何，都请通过 fwupdmgr update / GNOME 软件保持固件最新，并在固件设置中启用安全启动、TPM 与 IOMMU。"))
    general.add(text_row("开源固件", "若机型支持 coreboot / Dasharo / Heads，刷入开源固件能显著提高可审计性。"))
    return page([sp, info, info_extra, hist, adv, general])


# ---------------------------------------------------------------------------
# 使用习惯
# ---------------------------------------------------------------------------
def build_habits(report, win):
    hb = report.habits
    all_good = all(c.status == "good" for c in hb.checks)
    suspects = [c for c in hb.checks if c.status == "suspect"]
    problems = [c for c in hb.checks if c.status in ("bad", "warn")]
    if all_good:
        top = banner("四项使用习惯检查全部通过！您的安全习惯非常好，请继续保持。", "success")
    elif suspects and not problems:
        top = banner(f"未发现明确风险，但有 {len(suspects)} 项需要您自行确认（不影响评分）。",
                     "warning", icon="dialog-warning-symbolic")
    else:
        top = None
    groups = []
    for c in hb.checks:
        g = group(c.title)
        g.set_header_suffix(status_icon(c.status, 22))
        head = Adw.ActionRow(title=esc(c.summary))
        head.add_prefix(status_icon(c.status))
        if c.status == "good":
            head.add_css_class("success")
        elif c.status == "suspect":
            head.add_css_class("warning")
        g.add(head)
        for d in c.details:
            g.add(text_row("详情", d))
        if c.advice:
            g.add(text_row(_HABIT_ADVICE_TITLE.get(c.status, "建议"), c.advice))
        if c.key == "flatpak":
            r = text_row("harden-flatpak", data.HARDEN_FLATPAK_URL, selectable=True)
            disp = Gdk.Display.get_default()
            has_ext = disp is not None and Gtk.IconTheme.get_for_display(disp).has_icon("external-link-symbolic")
            btn = Gtk.Button(valign=Gtk.Align.CENTER, tooltip_text="在浏览器中打开",
                             icon_name="external-link-symbolic" if has_ext else "web-browser-symbolic")
            btn.connect("clicked", lambda *_: (
                Gtk.UriLauncher.new(data.HARDEN_FLATPAK_URL).launch(win, None, None, None)
                if hasattr(Gtk, "UriLauncher") else Gtk.show_uri(win, data.HARDEN_FLATPAK_URL, Gdk.CURRENT_TIME)
            ))
            r.add_suffix(btn)
            g.add(r)
            g.add(text_row("快速上手", "git clone https://github.com/lingyicute/harden-flatpak && cd harden-flatpak && ./lockdown.sh\n之后安装 Flatseal（com.github.tchx84.Flatseal）逐个应用按需放开权限。", selectable=True))
        groups.append(g)
    return page([top] + groups)
