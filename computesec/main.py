# -*- coding: utf-8 -*-
"""应用程序入口：窗口、导航、后台检测线程。"""

import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import checks, data, ui  # noqa: E402

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

        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)
        self.split = Adw.NavigationSplitView(min_sidebar_width=200, max_sidebar_width=260)
        self.toast_overlay.set_child(self.split)

        # ---- 侧边栏 ----
        side = Adw.ToolbarView()
        side_hb = Adw.HeaderBar()
        side_hb.set_title_widget(Adw.WindowTitle(title=data.APP_NAME, subtitle="ComputeSec"))
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
        menu.append("关于计算安全小助手", "app.about")
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

        self.listbox.select_row(self.listbox.get_row_at_index(0))
        self.show_loading()
        self.refresh()

    # ---- 交互 ----
    def toast(self, text):
        self.toast_overlay.add_toast(Adw.Toast.new(text))

    def on_row_selected(self, _lb, row):
        if row is None:
            return
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

    def render(self, report):
        self.report = report
        builders = {
            "dashboard": lambda: ui.build_dashboard(report, self, self.navigate),
            "hsi": lambda: ui.build_hsi(report, self),
            "kernel": lambda: ui.build_kernel(report, self),
            "hardware": lambda: ui.build_hardware(report, self),
            "habits": lambda: ui.build_habits(report, self),
        }
        for key, build in builders.items():
            try:
                self.bins[key].set_child(build())
            except Exception as e:  # 页面构建失败时给出可见错误而非崩溃
                import traceback
                traceback.print_exc()
                self.bins[key].set_child(Adw.StatusPage(icon_name="dialog-error-symbolic", title="页面渲染失败", description=str(e)))
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
                                ("refresh", self.on_refresh, "<Primary>r")):
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

    def on_about(self, *_):
        kwargs = dict(
            application_name=data.APP_NAME, application_icon=data.APP_ID, developer_name=data.AUTHOR, version=data.VERSION,
            website=data.HOMEPAGE, issue_url=data.HOMEPAGE + "/issues", license_type=Gtk.License.GPL_3_0,
            copyright="© 2025 lingyicute",
            comments="评估固件安全 (HSI)、内核加固、硬件品牌信誉与使用习惯，帮助您把 Linux 设备打造成可信的计算环境。",
            developers=["lingyicute https://github.com/lingyicute"], designers=["lingyicute"],
        )
        if hasattr(Adw, "AboutDialog"):          # libadwaita >= 1.5
            dlg = Adw.AboutDialog(**kwargs)
        else:                                    # libadwaita 1.2 - 1.4
            dlg = Adw.AboutWindow(transient_for=self.props.active_window, **kwargs)
        dlg.add_link("harden-flatpak", data.HARDEN_FLATPAK_URL)
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
