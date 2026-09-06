# -*- coding: utf-8 -*-
"""启动时的数据采集向导。

分步骤引导用户在自己的终端里执行只读命令，然后点击“我已复制结果”，
程序直接从剪贴板读取并解析——没有难看的粘贴框，也不需要 flatpak-spawn
这类侵入性权限。
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from . import hostdata  # noqa: E402

INTRO_TEXT = (
    "有一部分系统信息，普通用户权限读不到（例如 <tt>vm.mmap_rnd_bits</tt> 这类 ASLR 参数的文件是 "
    "<tt>0600 root:root</tt>），在 Flatpak 沙箱内还有更多条目被屏蔽。\n\n"
    "ComputeSec <b>不会</b>请求提权，也<b>不会</b>使用 <tt>flatpak-spawn --host</tt> 在您的宿主机上执行命令——"
    "那等同于沙箱逃逸，对一个只读检测工具来说权限过大。\n\n"
    "取而代之：下面每一步会给出一条<b>只读命令</b>，请您在自己的终端里执行，"
    "确认输出无误后复制，再回来点击「我已复制结果」。ComputeSec 会从剪贴板读取并解析。\n\n"
    "全程由您掌控：您能看到每一条命令，结果只保存在本机，重启后自动失效。"
)


def _mono_command(text):
    lbl = Gtk.Label(label=text, xalign=0, selectable=True, wrap=True, wrap_mode=Pango.WrapMode.CHAR,
                    hexpand=True, margin_top=12, margin_bottom=12, margin_start=14, margin_end=14)
    lbl.add_css_class("monospace")
    frame = Gtk.Frame()
    frame.add_css_class("view")
    frame.set_child(lbl)
    return frame


def _title(text, css="title-2", center=True):
    lbl = Gtk.Label(label=text, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                    justify=Gtk.Justification.CENTER if center else Gtk.Justification.LEFT,
                    xalign=0.5 if center else 0)
    lbl.add_css_class(css)
    return lbl


def _body(text, css=(), markup=False, center=False):
    lbl = Gtk.Label(wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, xalign=0.5 if center else 0,
                    justify=Gtk.Justification.CENTER if center else Gtk.Justification.LEFT, hexpand=True)
    if markup:
        lbl.set_markup(text)
    else:
        lbl.set_label(text)
    for c in css:
        lbl.add_css_class(c)
    return lbl


class CollectWizard(Adw.Window):
    """采集向导窗口。完成后调用 on_finish(HostData)。"""

    def __init__(self, parent, host_data=None, on_finish=None, allow_skip=True):
        super().__init__(transient_for=parent, modal=True, title="系统数据采集",
                         default_width=680, default_height=620, destroy_with_parent=True)
        self.hd = host_data or hostdata.HostData()
        self.on_finish = on_finish
        self.allow_skip = allow_skip
        self.steps = hostdata.STEPS
        self.index = -1                 # -1 = 介绍页；len(steps) = 完成页
        self._busy = False
        self._finished = False          # 保证 on_finish 只会被调用一次
        self.connect("close-request", self._on_close_request)

        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)
        view = Adw.ToolbarView()
        self.toasts.set_child(view)

        self.header = Adw.HeaderBar(show_end_title_buttons=True)
        self.header_title = Adw.WindowTitle(title="系统数据采集", subtitle="")
        self.header.set_title_widget(self.header_title)
        self.back_btn = Gtk.Button(label="上一步")
        self.back_btn.connect("clicked", lambda *_: self.go(self.index - 1))
        self.header.pack_start(self.back_btn)
        view.add_top_bar(self.header)

        self.progress = Gtk.ProgressBar(show_text=False)
        self.progress.add_css_class("osd")
        view.add_top_bar(self.progress)

        self.bin = Adw.Bin(vexpand=True)
        scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        clamp = Adw.Clamp(maximum_size=560, margin_top=18, margin_bottom=18, margin_start=18, margin_end=18)
        clamp.set_child(self.bin)
        scroll.set_child(clamp)
        view.set_content(scroll)

        # ---- 底部操作栏 ----
        bar = Gtk.Box(spacing=10, margin_top=12, margin_bottom=12, margin_start=14, margin_end=14)
        self.skip_btn = Gtk.Button(label="跳过此步")
        self.skip_btn.add_css_class("flat")
        self.skip_btn.connect("clicked", self.on_skip)
        bar.append(self.skip_btn)
        bar.append(Gtk.Box(hexpand=True))
        self.copy_cmd_btn = Gtk.Button()
        self.copy_cmd_btn.set_child(Adw.ButtonContent(icon_name="edit-copy-symbolic", label="复制命令"))
        self.copy_cmd_btn.connect("clicked", self.on_copy_command)
        bar.append(self.copy_cmd_btn)
        self.primary_btn = Gtk.Button()
        self.primary_btn.add_css_class("suggested-action")
        self.primary_content = Adw.ButtonContent(icon_name="edit-paste-symbolic", label="我已复制结果")
        self.primary_btn.set_child(self.primary_content)
        self.primary_btn.connect("clicked", self.on_primary)
        bar.append(self.primary_btn)
        view.add_bottom_bar(bar)

        self.go(-1)

    # -- 导航 ------------------------------------------------------------
    def go(self, index):
        self.index = max(-1, min(index, len(self.steps)))
        total = len(self.steps) + 1
        self.progress.set_fraction((self.index + 1) / total)
        self.back_btn.set_visible(self.index > -1 and self.index < len(self.steps))
        if self.index == -1:
            self.render_intro()
        elif self.index >= len(self.steps):
            self.render_done()
        else:
            self.render_step(self.steps[self.index])

    def render_intro(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        img = Gtk.Image.new_from_icon_name("utilities-terminal-symbolic")
        img.set_pixel_size(76)
        img.set_margin_top(6)
        box.append(img)
        box.append(_title("需要您帮忙执行几条命令"))
        box.append(_body(INTRO_TEXT, css=("body",), markup=True))
        self.bin.set_child(box)
        self.header_title.set_subtitle("准备开始")
        self.primary_content.set_label("开始")
        self.primary_content.set_icon_name("go-next-symbolic")
        self.copy_cmd_btn.set_visible(False)
        self.skip_btn.set_visible(self.allow_skip)
        self.skip_btn.set_label("全部跳过")

    def render_step(self, step):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.append(_body(f"第 {self.index + 1} / {len(self.steps)} 步" + ("" if step.required else "（可选）"),
                         css=("dim-label", "caption")))
        box.append(_title(step.title, "title-2", center=False))
        box.append(_body(step.why, css=("body",)))
        box.append(_body("请在终端中执行：", css=("heading",)))
        box.append(_mono_command(step.command))
        if step.hint:
            hint = Gtk.Box(spacing=8)
            ic = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            ic.add_css_class("accent")
            ic.set_valign(Gtk.Align.START)
            hint.append(ic)
            hint.append(_body(step.hint, css=("caption", "dim-label")))
            box.append(hint)

        self.status = _body("", css=("caption",))
        self.status.set_visible(False)
        box.append(self.status)

        if self.hd.has(step.key):
            done = Gtk.Box(spacing=8)
            ic = Gtk.Image.new_from_icon_name("object-select-symbolic")
            ic.add_css_class("success")
            done.append(ic)
            done.append(_body("这一步已经采集过，可直接进入下一步，或重新粘贴以更新。", css=("caption", "success")))
            box.append(done)

        self.bin.set_child(box)
        self.header_title.set_subtitle(step.title)
        self.primary_content.set_label("我已复制结果")
        self.primary_content.set_icon_name("edit-paste-symbolic")
        self.copy_cmd_btn.set_visible(True)
        self.skip_btn.set_visible(True)
        self.skip_btn.set_label("下一步" if self.hd.has(step.key) else "跳过此步")

    def render_done(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        got = [s for s in self.steps if self.hd.has(s.key)]
        missing = [s for s in self.steps if not self.hd.has(s.key)]
        img = Gtk.Image.new_from_icon_name("object-select-symbolic" if got else "dialog-information-symbolic")
        img.set_pixel_size(76)
        img.add_css_class("success" if got else "dim-label")
        img.set_margin_top(6)
        box.append(img)
        box.append(_title("采集完成" if got else "未采集任何数据"))
        if got:
            n = len(self.hd.sysctl_values)
            detail = "、".join(s.title for s in got)
            box.append(_body(f"已获取：{detail}。" + (f"\n共解析出 {n} 个 sysctl 条目。" if n else ""),
                             css=("body",), center=True))
        if missing:
            box.append(_body("未提供：" + "、".join(s.title for s in missing)
                             + "。相关检测项会显示为「无法读取」，不影响其它结果；"
                               "您随时可以从主菜单的「重新采集系统数据」再来一次。",
                             css=("body", "dim-label"), center=True))
        box.append(_body("数据仅保存在本机（~/.local/share/computesec/），重启后自动失效。",
                         css=("caption", "dim-label"), center=True))
        self.bin.set_child(box)
        self.header_title.set_subtitle("完成")
        self.primary_content.set_label("开始检测")
        self.primary_content.set_icon_name("view-refresh-symbolic")
        self.copy_cmd_btn.set_visible(False)
        self.skip_btn.set_visible(False)

    # -- 动作 ------------------------------------------------------------
    def toast(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def on_copy_command(self, _b):
        step = self.steps[self.index]
        Gdk.Display.get_default().get_clipboard().set(step.command)
        self.toast("命令已复制，请到终端中粘贴执行")

    def on_skip(self, _b):
        if self.index == -1:
            self.finish(skipped=True)
            return
        self.go(self.index + 1)

    def on_primary(self, _b):
        if self.index == -1:
            self.go(0)
            return
        if self.index >= len(self.steps):
            self.finish()
            return
        self.read_clipboard()

    # -- 剪贴板 ----------------------------------------------------------
    def read_clipboard(self):
        if self._busy:
            return
        self._busy = True
        self.primary_btn.set_sensitive(False)
        self.set_status("正在读取剪贴板…", "dim-label")
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.read_text_async(None, self._on_clipboard_text)

    def _on_clipboard_text(self, clipboard, result):
        self._busy = False
        self.primary_btn.set_sensitive(True)
        try:
            text = clipboard.read_text_finish(result)
        except GLib.Error as e:
            self.set_status(f"无法读取剪贴板：{e.message}", "error")
            return
        except Exception as e:
            self.set_status(f"无法读取剪贴板：{e}", "error")
            return
        step = self.steps[self.index]
        parsed, err = step.parser(text or "")
        if err:
            self.set_status(err, "error")
            return
        self.hd.set(step.key, parsed)
        self.hd.save()
        extra = ""
        if step.key == "sysctl":
            n = len(parsed.get("values", {}))
            extra = f"，共 {n} 个条目"
            denied = parsed.get("meta", {}).get("denied")
            if denied:
                extra += ("；有 %d 行提示权限不足——如果您没有加 sudo，"
                          "请用 sudo 重新执行以获取 vm.mmap_rnd_bits 等参数" % denied)
        self.toast(f"已读取「{step.title}」的结果{extra}")
        GLib.timeout_add(220, lambda: (self.go(self.index + 1), False)[1])

    def set_status(self, text, css):
        self.status.set_label(text)
        for c in ("error", "warning", "success", "dim-label"):
            self.status.remove_css_class(c)
        self.status.add_css_class(css)
        self.status.set_visible(True)

    def _on_close_request(self, *_):
        """用户直接关掉窗口（点 X 或按 Esc）：把已采到的数据落盘并照常通知调用方，
        这样主窗口不会永远停在“正在检测…”。"""
        self._commit(skipped=True)
        return False        # 允许关闭

    def _commit(self, skipped=False):
        if self._finished:
            return
        self._finished = True
        self.hd.mark_done(skipped=skipped and not self.hd.any_data)
        self.hd.save()
        hostdata.set_current(self.hd)
        if self.on_finish:
            self.on_finish(self.hd)

    def finish(self, skipped=False):
        self._commit(skipped=skipped)
        self.close()
