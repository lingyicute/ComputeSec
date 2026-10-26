# -*- coding: utf-8 -*-
"""应用程序入口：窗口、导航、后台检测线程。"""

import os
import platform
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from . import checks, data, hostdata, kernelver, ui, wizard, xdg  # noqa: E402

PAGES = [
    ("dashboard", "仪表盘", "go-home-symbolic"),
    ("hsi", "HSI 固件安全", "security-high-symbolic"),
    ("kernel", "内核加固", "emblem-system-symbolic"),
    ("hardware", "硬件品牌", "computer-symbolic"),
    ("habits", "使用习惯", "avatar-default-symbolic"),
]
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# start_kernel_check() 的返回值：调用方据此决定要不要提示"正在核对"。
# 都是真值——只要用户明确要求重查（force=True），就一定给出可见反馈，
# 不能出现"点了按钮什么都没发生"的状态。
KERNEL_CHECK_STARTED = "started"      # 立刻启动了一次新检查
KERNEL_CHECK_BUSY = "busy"            # 已有检查在跑，本次请求被忽略
KERNEL_CHECK_QUEUED = "queued"        # 已有检查在跑，本次请求已排队，结束后补跑


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=data.APP_NAME, default_width=1120, default_height=780)
        self.set_icon_name(data.APP_ID)
        self.report = None
        self.bins = {}
        self.built = set()          # 已构建的页面
        self._idle_build_id = 0     # 空闲增量构建的 source id
        self._refreshing = False    # 是否有检测线程正在运行（防止菜单/快捷键重入）
        self._refresh_pending = False  # 检测进行中时又收到了刷新请求，结束后补跑一次
        self._wizard = None         # 当前打开的数据采集向导窗口（防止重复弹出）
        self._kernel_warned = False  # 内核版本线提示本次运行是否已经弹过
        self._kernel_checking = False  # 版本线检查是否正在进行（防止连点菜单并发多线程）
        self._kernel_check_gen = 0     # 检查代际：只有最新一次的结果才允许复位标志位
        self._kernel_pending = 0       # 检查进行中收到的重查请求数，结束后补跑一次
        self._pending_kernel_warning = None  # 等采集向导关闭后再弹的版本线提示

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
        menu.append("重新检查内核版本线", "app.kernelcheck")
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
        # 与首次检测并行：联网核对内核版本线（不阻塞界面；失败不弹窗，内核页会显示「未能核对」）
        self.start_kernel_check()

    # ---- 内核版本线 ----
    def start_kernel_check(self, force=False):
        """后台线程向 kernel.org 取最新的 mainline / stable 版本号。

        只读公开的 releases.json，结果缓存 24 小时；离线、代理、DNS 失败都只是
        拿不到结论，不弹窗、不影响检测本身，内核页会显示「未能核对」与重试按钮。

        force=True 表示用户手动触发：跳过 24 小时缓存真正联网，结束后用 Toast
        报告结果。

        菜单项、重试按钮都直接调这里，连点几下就会并发出几个线程、几次
        缓存写入和几次整页重建，因此用一个标志位挡住。

        返回值（都是真值，调用方据此提示「正在核对」，不会出现"点了没反应"）：

        * KERNEL_CHECK_STARTED —— 立刻启动了一次新检查；
        * KERNEL_CHECK_QUEUED  —— 已有检查在跑，本次 force 请求已排队，结束后补跑；
        * KERNEL_CHECK_BUSY    —— 已有检查在跑，本次（非 force）请求被忽略。

        排队而不是直接丢弃，是因为网络慢时一次检查可能要等满 FETCH_TIMEOUT：
        若此时把用户的点击静默丢掉，重试按钮看上去就是坏的。
        """
        if self._kernel_checking:
            if not force:
                return KERNEL_CHECK_BUSY
            # 用户明确要求重查：排队而不是丢弃。网络慢时（甚至要等满 6 秒的
            # deadline）连点几下，至少每次都有可见反馈，结果也不会被悄悄吞掉。
            self._kernel_pending += 1
            return KERNEL_CHECK_QUEUED
        self._kernel_checking = True
        self._kernel_check_gen += 1
        gen = self._kernel_check_gen

        def worker():
            # get_status 承诺不抛异常；这里再兜一层是因为上面新加了 _kernel_checking
            # 标志——万一真的抛了，标志就再也没人复位，重试按钮会永久失效。
            try:
                st = kernelver.get_status(force=force)
            except Exception as e:                                  # noqa: BLE001
                st = kernelver.KernelSupport(release=platform.release(),
                                             error=str(e) or e.__class__.__name__)
            GLib.idle_add(self.on_kernel_status, st, force, gen)

        threading.Thread(target=worker, daemon=True).start()
        return KERNEL_CHECK_STARTED

    def on_kernel_status(self, st, manual=False, gen=None):
        # 代际比当前小的结果已经过期（用户在它返回之前又发起了一次检查），
        # 直接丢弃：既不能复位新一代的标志位，也不能把旧结果写进 report。
        if gen is not None and gen != self._kernel_check_gen:
            return False
        self._kernel_checking = False
        if manual:
            self.toast(kernelver.recheck_result_text(st))
        kernelver.set_current(st)
        if self.report is not None:
            self.report.kernel_support = st
            # 内核页与仪表盘用到了它，重建这两页（其余页面不受影响）
            for key in ("dashboard", "kernel"):
                if key in self.built:
                    self.built.discard(key)
                    self.build_page(key)
        if st.known and not st.supported and not self._kernel_warned:
            self._kernel_warned = True
            self._pending_kernel_warning = st
            self.show_kernel_warning()
        self._run_pending_kernel_check()
        return False

    def _run_pending_kernel_check(self):
        """把检查进行中收到的重查请求补跑一次。

        只补一次：用户连点十下和点一下想知道的是同一件事，没必要发起十次请求。
        补跑时一律 force=True——用户既然手动点过，就说明他要的是最新结果而不是缓存。
        """
        if not self._kernel_pending:
            return
        self._kernel_pending = 0
        self.start_kernel_check(force=True)

    def show_kernel_warning(self):
        """弹出（或推迟）版本线提示。

        首次运行时采集向导是模态窗口，若此时再叠一个同样以主窗口为父的模态对话框，
        两者会互相抢焦点、甚至被向导挡在后面。因此向导开着就先记下来，等它关闭后再弹。
        """
        if self._pending_kernel_warning is None or self._wizard is not None:
            return False
        st, self._pending_kernel_warning = self._pending_kernel_warning, None
        dlg = ui.kernel_warning_dialog(st)
        if hasattr(Adw, "AlertDialog"):
            dlg.present(self)
        else:
            dlg.set_transient_for(self)
            dlg.present()
        return False

    # ---- 交互 ----
    def toast(self, text):
        self.toast_overlay.add_toast(Adw.Toast.new(text))

    def open_wizard(self, *_):
        """打开数据采集向导。向导保证 on_finish 恰好回调一次（完成或被关闭）。"""
        if self._wizard is not None:
            self._wizard.present()
            return False
        existing = hostdata.CURRENT if hostdata.CURRENT.any_data else hostdata.HostData.load()
        if not existing.fresh:
            existing = hostdata.HostData()
        self._wizard = wizard.CollectWizard(self, host_data=existing, on_finish=self.on_wizard_finish)
        self._wizard.present()
        return False

    def on_wizard_finish(self, _hd):
        self._wizard = None
        self.refresh()
        self.show_kernel_warning()

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
        sub = {"dashboard": f"综合评分 {ui.score_str(r.overall)}",
               "hsi": (r.hsi.host_id or f"评分 {ui.score_str(r.hsi.score)}") if r.hsi.ok else "不可用",
               "kernel": f"评分 {ui.score_str(r.kernel_score)}", "hardware": data.RATING_ZH[r.hardware.vendor["rating"]],
               "habits": f"评分 {ui.score_str(r.habits.score)}"}.get(key, "")
        self.title_widget.set_subtitle(sub)

    # ---- 检测与渲染 ----
    def show_loading(self):
        for _key, b in self.bins.items():
            sp = Adw.StatusPage(title="正在检测系统…", description="正在读取 fwupd、/proc、sysfs 等信息，通常需要几秒钟。")
            spinner = Gtk.Spinner(spinning=True, width_request=40, height_request=40, halign=Gtk.Align.CENTER)
            sp.set_child(spinner)
            b.set_child(sp)

    def refresh(self):
        # 刷新按钮在检测期间会被禁用，但菜单项 / 快捷键 / 向导回调仍可重入。
        # 用标志位串行化：若已有检测在跑，只记一个 pending，等它结束后再跑一次，
        # 这样向导采集到新数据后一定能反映到结果里。
        if self._refreshing:
            self._refresh_pending = True
            return
        self._refreshing = True
        self._refresh_pending = False
        self.refresh_btn.set_sensitive(False)
        self.title_widget.set_subtitle("正在检测…")

        def worker():
            try:
                report = checks.collect()
            except Exception as e:
                import traceback
                traceback.print_exc()
                GLib.idle_add(self.render_error, e)
            else:
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
        # 第一时间复位标志：即使下面的渲染代码中途抛异常，也不会锁死后续刷新
        self._refreshing = False
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
        self._run_pending_refresh()
        return False

    def render_error(self, error):
        self._refreshing = False
        if self._idle_build_id:
            GLib.source_remove(self._idle_build_id)
            self._idle_build_id = 0
        self.title_widget.set_subtitle("检测失败")
        sel = self.listbox.get_selected_row()
        current = sel.page_key if sel else "dashboard"
        targets = self.bins.keys() if self.report is None else (current,)
        for k in targets:
            self.bins[k].set_child(Adw.StatusPage(
                icon_name="dialog-error-symbolic", title="检测时发生错误",
                description=f"{error}\n\n点击刷新按钮重试。"))
        self.refresh_btn.set_sensitive(True)
        self._run_pending_refresh()
        return False

    def _run_pending_refresh(self):
        if self._refresh_pending:
            self._refresh_pending = False
            self.refresh()


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
            # --install 写的就是 $XDG_DATA_HOME/icons（见 cli.install_desktop），
            # 这里必须用同一条规则去找，否则设了 XDG_DATA_HOME 的机器装上菜单项后
            # 仍然找不到图标。
            for p in (os.path.join(xdg.data_home(), "icons"),
                      os.path.join(sys.prefix, "share", "icons"),   # pip install .
                      "/app/share/icons"):                          # Flatpak
                if os.path.isdir(p):
                    theme.add_search_path(p)
        Gtk.Window.set_default_icon_name(data.APP_ID)
        for name, cb, accel in (("about", self.on_about, None), ("quit", lambda *_: self.quit(), "<Primary>q"),
                                ("refresh", self.on_refresh, "<Primary>r"), ("collect", self.on_collect, "<Primary>d"),
                                ("kernelcheck", self.on_kernel_check, None)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self.add_action(act)
            if accel:
                self.set_accels_for_action(f"app.{name}", [accel])

    def _main_window(self):
        win = self.props.active_window
        if isinstance(win, MainWindow):
            return win
        for w in self.get_windows():
            if isinstance(w, MainWindow):
                return w
        return None

    def do_activate(self):
        win = self._main_window() or MainWindow(self)
        win.present()

    def on_refresh(self, *_):
        win = self._main_window()
        if win:
            win.refresh()

    def on_collect(self, *_):
        win = self._main_window()
        if win:
            win.open_wizard()

    def on_kernel_check(self, *_):
        win = self._main_window()
        if win:
            win._kernel_warned = False
            # force=True 一定会返回真值（启动 / 排队），因此总能给出反馈。
            if win.start_kernel_check(force=True):
                win.toast("正在重新核对内核版本线…")

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
