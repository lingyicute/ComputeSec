# -*- coding: utf-8 -*-
"""应用程序入口：窗口、导航、后台检测线程。"""

import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import checks, data, hostdata, ui, wizard  # noqa: E402

PAGES = [
    ("dashboard", "仪表盘", "go-home-symbolic"),
    ("hsi", "HSI 固件安全", "security-high-symbolic"),
    ("kernel", "内核加固", "emblem-system-symbolic"),
    ("hardware", "硬件品牌", "computer-symbolic"),
    ("habits", "使用习惯", "avatar-default-symbolic"),
]
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=data.APP_NAME, default_width=1120, default_height=780)
        self.set_icon_name(data.APP_ID)
        self.report = None
        self.bins = {}
        self.built = set()          # 已构建的页面
        self._idle_build_id = 0     # 空闲增量构建的 source id

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)
        self.split = Adw.NavigationSplitView(min_sidebar_width=200, max_sidebar_width=260)
        self.toast_overlay.set_child(self.split)

        # ---- 侧边栏 ----
        side = Adw.ToolbarView()
        side_hb = Adw.HeaderBar()
        side_hb.set_title_widget(Adw.WindowTitle(title=data.APP_NAME))
        side.add_top_bar(side_hb)
        self.listbox = Gtk.ListBox()
        self.listbox.add_css_class("navigation-sidebar")
        for key, title, icon in PAGES:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(spacing=12, margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
            box.append(Gtk.Image.new_from_icon_name(icon))
            box.append(Gtk.Label(label=title, xalign=0, hexpand=True))
            badge = Gtk.Label(label="")
            badge.add_css_class("caption")
            badge.add_css_class("numeric")
            box.append(badge)
            row.set_child(box)
            row.page_key = key
            row.badge = badge
            self.listbox.append(row)
        self.listbox.connect("row-selected", self.on_row_selected)
        side.set_content(self.listbox)
        self.split.set_sidebar(Adw.NavigationPage.new(side, data.APP_NAME))

        # ---- 内容区 ----
        content = Adw.ToolbarView()
        self.header = Adw.HeaderBar()
        self.title_widget = Adw.WindowTitle(title="仪表盘", subtitle="")
        self.header.set_title_widget(self.title_widget)
        self.refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="重新检测 (Ctrl+R)")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh())
        self.header.pack_start(self.refresh_btn)
        menu = Gio.Menu()
        menu.append("重新检测", "app.refresh")
        menu.append("重新采集系统数据…", "app.collect")
        menu.append("关于", "app.about")
        menu.append("退出", "app.quit")
        self.header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text="主菜单"))
        content.add_top_bar(self.header)
        self.stack = Adw.ViewStack()
        for key, _, _ in PAGES:
            b = Adw.Bin()
            self.stack.add_named(b, key)
            self.bins[key] = b
        content.set_content(self.stack)
        self.content_page = Adw.NavigationPage.new(content, "仪表盘")
        self.split.set_content(self.content_page)

        try:
            bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 760sp"))
            bp.add_setter(self.split, "collapsed", True)
            self.add_breakpoint(bp)
        except Exception:
            pass

        # 窗口关闭时取消待执行的空闲构建，避免回调操作已销毁的控件
        self.connect("close-request", self._on_close)

        self.listbox.select_row(self.listbox.get_row_at_index(0))
        self.show_loading()
        # 启动时：若本次开机尚未采集过宿主机数据，先弹出采集向导
        cached = hostdata.HostData.load()
        if cached.fresh:
            hostdata.set_current(cached)
            self.refresh()
        else:
            hostdata.set_current(hostdata.HostData())
            GLib.idle_add(self.open_wizard)

    # ---- 交互 ----
    def toast(self, text):
        self.toast_overlay.add_toast(Adw.Toast.new(text))

    def open_wizard(self, *_):
        """打开数据采集向导。向导保证 on_finish 恰好回调一次（完成或被关闭）。"""
        existing = hostdata.CURRENT if hostdata.CURRENT.any_data else hostdata.HostData.load()
        if not existing.fresh:
            existing = hostdata.HostData()
        wizard.CollectWizard(self, host_data=existing, on_finish=self.on_wizard_finish).present()
        return False

    def on_wizard_finish(self, _hd):
        self.refresh()

    def on_row_selected(self, _lb, row):
        if row is None:
            return
        # 若该页尚未构建（空闲队列还没轮到），立刻构建，避免切过去是空白
        self.build_page(row.page_key)
        self.stack.set_visible_child_name(row.page_key)
        title = next(t for k, t, _ in PAGES if k == row.page_key)
        self.title_widget.set_title(title)
        self.content_page.set_title(title)
        self.update_subtitle(row.page_key)
        if self.split.get_collapsed():
            self.split.set_show_content(True)

    def navigate(self, key):
        for i, (k, _, _) in enumerate(PAGES):
            if k == key:
                self.listbox.select_row(self.listbox.get_row_at_index(i))
                break

    def update_subtitle(self, key):
        r = self.report
        if r is None:
            self.title_widget.set_subtitle("正在检测…")
            return
        sub = {"dashboard": f"综合评分 {r.overall}", "hsi": (r.hsi.host_id or f"评分 {r.hsi.score}") if r.hsi.ok else "不可用",
               "kernel": f"评分 {r.kernel_score}", "hardware": data.RATING_ZH[r.hardware.vendor["rating"]],
               "habits": f"评分 {r.habits.score}"}.get(key, "")
        self.title_widget.set_subtitle(sub)

    # ---- 检测与渲染 ----
    def show_loading(self):
        for key, b in self.bins.items():
            sp = Adw.StatusPage(title="正在检测系统…", description="正在读取 fwupd、/proc、sysfs 等信息，通常需要几秒钟。")
            spinner = Gtk.Spinner(spinning=True, width_request=40, height_request=40, halign=Gtk.Align.CENTER)
            sp.set_child(spinner)
            b.set_child(sp)

    def refresh(self):
        self.refresh_btn.set_sensitive(False)
        self.title_widget.set_subtitle("正在检测…")

        def worker():
            report = checks.collect()
            GLib.idle_add(self.render, report)

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self, *_):
        if self._idle_build_id:
            GLib.source_remove(self._idle_build_id)
            self._idle_build_id = 0
        return False

    def build_page(self, key):
        """按需构建某一页。已构建过则直接返回。"""
        if key in self.built or self.report is None:
            return
        report = self.report
        builders = {
            "dashboard": lambda: ui.build_dashboard(report, self, self.navigate),
            "hsi": lambda: ui.build_hsi(report, self),
            "kernel": lambda: ui.build_kernel(report, self),
            "hardware": lambda: ui.build_hardware(report, self),
            "habits": lambda: ui.build_habits(report, self),
        }
        try:
            self.bins[key].set_child(builders[key]())
        except Exception as e:  # 页面构建失败时给出可见错误而非崩溃
            import traceback
            traceback.print_exc()
            self.bins[key].set_child(Adw.StatusPage(icon_name="dialog-error-symbolic", title="页面渲染失败", description=str(e)))
        self.built.add(key)

    def _build_pending(self):
        """空闲时逐页构建剩余页面：每次只做一页，让主循环有机会处理输入与绘制。"""
        for key, _, _ in PAGES:
            if key not in self.built:
                self.build_page(key)
                return True        # 还有剩余，下次空闲继续
        self._idle_build_id = 0
        return False

    def render(self, report):
        self.report = report
        # 只构建当前可见的页面，其余留到空闲时增量构建。
        # 一次性构建全部五页会在一个主循环回调里创建数千个控件，
        # 导致窗口在首次绘制前长时间无响应。
        sel = self.listbox.get_selected_row()
        current = sel.page_key if sel else "dashboard"
        self.built = set()
        self.build_page(current)
        if self._idle_build_id:
            GLib.source_remove(self._idle_build_id)
        self._idle_build_id = GLib.idle_add(self._build_pending, priority=GLib.PRIORITY_LOW)
        scores = {"dashboard": report.overall, "hsi": report.hsi.score if report.hsi.ok else None, "kernel": report.kernel_score,
                  "hardware": report.hardware.score, "habits": report.habits.score}
        i = 0
        row = self.listbox.get_row_at_index(i)
        while row is not None:
            s = scores.get(row.page_key)
            row.badge.set_label("" if s is None else str(s))
            for c in ("success", "warning", "error"):
                row.badge.remove_css_class(c)
            if s is not None:
                row.badge.add_css_class(ui.score_css(s))
            i += 1
            row = self.listbox.get_row_at_index(i)
        sel = self.listbox.get_selected_row()
        self.update_subtitle(sel.page_key if sel else "dashboard")
        self.refresh_btn.set_sensitive(True)
        return False


class Application(Adw.Application):
    def __init__(self):
        super().__init__(application_id=data.APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_startup(self):
        Adw.Application.do_startup(self)
        # 让克隆直接运行时也能找到图标（Flatpak / 已安装时由 hicolor 主题提供）
        display = Gdk.Display.get_default()
        if display is not None:
            theme = Gtk.IconTheme.get_for_display(display)
            theme.add_search_path(os.path.join(PROJECT_ROOT, "data", "icons"))
            for p in (os.path.expanduser("~/.local/share/icons"), "/app/share/icons"):
                if os.path.isdir(p):
                    theme.add_search_path(p)
        Gtk.Window.set_default_icon_name(data.APP_ID)
        for name, cb, accel in (("about", self.on_about, None), ("quit", lambda *_: self.quit(), "<Primary>q"),
                                ("refresh", self.on_refresh, "<Primary>r"), ("collect", self.on_collect, "<Primary>d")):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)
            if accel:
                self.set_accels_for_action(f"app.{name}", [accel])

    def do_activate(self):
        win = self.props.active_window or MainWindow(self)
        win.present()

    def on_refresh(self, *_):
        win = self.props.active_window
        if win:
            win.refresh()

    def on_collect(self, *_):
        win = self.props.active_window
        if win:
            win.open_wizard()

    def on_about(self, *_):
        kwargs = dict(
            application_name=data.APP_NAME, application_icon=data.APP_ID, developer_name="Made with ❤️ by lingyicute", version=data.VERSION,
            website=data.HOMEPAGE, issue_url=data.HOMEPAGE + "/issues", license_type=Gtk.License.GPL_3_0,
            copyright="Copyright © 2025-2026 lingyicute",
            comments="评估固件安全 (HSI)、内核加固、硬件品牌信誉与使用习惯，帮助您打造可信、安全的计算环境。",
        )
        if hasattr(Adw, "AboutDialog"):          # libadwaita >= 1.5
            dlg = Adw.AboutDialog(**kwargs)
        else:                                    # libadwaita 1.2 - 1.4
            dlg = Adw.AboutWindow(transient_for=self.props.active_window, **kwargs)
        dlg.add_link("lingyicute's Home", "https://92li.uk")
        dlg.add_link("harden-flatpak 项目主页", data.HARDEN_FLATPAK_URL)
        dlg.add_link("fwupd HSI 规范", "https://fwupd.github.io/libfwupdplugin/hsi.html")
        dlg.add_acknowledgement_section("致谢", ["fwupd / LVFS 项目", "GNOME 与 libadwaita", "Kernel Self Protection Project"])
        if hasattr(Adw, "AboutDialog"):
            dlg.present(self.props.active_window)
        else:
            dlg.present()


def main(argv=None):
    GLib.set_prgname(data.APP_ID)
    GLib.set_application_name(data.APP_NAME)
    app = Application()
    return app.run(argv if argv is not None else sys.argv)


if __name__ == "__main__":
    sys.exit(main())
