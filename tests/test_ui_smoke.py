# -*- coding: utf-8 -*-
"""无头 GTK 冒烟测试（手动运行，CI 里会因缺少 GTK 而跳过）。

目的：ui.py 的五个页面、版本线弹窗这些代码路径平时没有任何测试覆盖，
GTK 的 API 用法（属性名、枚举、信号）只有真正构建一次才能确认没错。

运行：
    Xvfb :99 & export DISPLAY=:99
    /usr/bin/python3 -m pytest tests/test_ui_smoke.py -q
"""

import os

import pytest

gi = pytest.importorskip("gi", reason="未安装 PyGObject")
if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    pytest.skip("没有可用的显示服务器（可用 Xvfb 提供）", allow_module_level=True)

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from computesec import checks, data, kernelver, ui  # noqa: E402


class _FakeWin(Adw.ApplicationWindow):
    """build_* 只会用到 toast() 与 open_wizard()。"""

    def __init__(self, app):
        super().__init__(application=app)
        self.toasts = []
        self.wizards = 0

    def toast(self, text):
        self.toasts.append(text)

    def open_wizard(self, *_):
        self.wizards += 1


@pytest.fixture(scope="module")
def app():
    application = Adw.Application(application_id="uk._92li.lingyicut.Tests")
    application.register(None)
    yield application


def _item(key, status, actual=None, source="proc"):
    return checks.SysctlItem(key, "1", "eq", actual or {key: "0"}, status, "", source=source)


def _report(ks=None, hsi_undetermined=False, empty_scores=False):
    hsi_items = [
        checks.HsiItem("org.fwupd.hsi.Uefi.SecureBoot", "UEFI 安全启动", "", 1, "enabled", {"success"},
                       "", data.HSI_ATTRS["org.fwupd.hsi.Uefi.SecureBoot"], True, False),
        checks.HsiItem("org.fwupd.hsi.Tpm.Version20", "TPM 2.0", "", 2, "unknown",
                       {"missing-data"} if hsi_undetermined else set(),
                       "", data.HSI_ATTRS["org.fwupd.hsi.Tpm.Version20"],
                       not hsi_undetermined, False),
    ]
    if empty_scores:
        cmd = checks.CmdlineReport("riscv64", None, "", [])
        sysctl = checks.SysctlReport("riscv64", groups=[("组", [_item("a", "na")])])
    else:
        cmd = checks.CmdlineReport("x86_64", "intel", "root=/dev/x ro quiet", [
            checks.ParamItem("lockdown", "confidentiality", checks.MISSING, "missing", "内核锁定", "副作用"),
            checks.ParamItem("pte", "1", "1", "ok", "x", "", None),
            checks.ParamItem("kvm_amd.sev", "1", checks.MISSING, "na", "x", "", "amd"),
        ])
        sysctl = checks.SysctlReport("x86_64", groups=[("网络", [
            _item("net.ipv4.tcp_syncookies", "ok", {"net.ipv4.tcp_syncookies": "1"}),
            _item("net.ipv4.conf.all.rp_filter", "unverified", {}, "沙箱网络隔离"),
            _item("vm.mmap_rnd_bits", "unknown", {}),
            _item("kernel.io_uring_disabled", "missing", {"kernel.io_uring_disabled": "0"}),
        ])], user_supplied=False)
    return checks.Report(
        hsi=checks.HsiReport(ok=True, host_id="HSI:3!", source="D-Bus", items=hsi_items),
        cmdline=cmd, sysctl=sysctl,
        hardware=checks.get_hardware(),
        habits=checks.get_habits(),
        arch="x86_64", cpu="Intel", os_name="TestOS", kernel="7.2.12",
        in_flatpak=False, identity=None, hostdata=checks.hostdata.HostData(), kernel_support=ks)


SUPPORTED = kernelver.KernelSupport("7.2.12", "7.3", "7.2.12", "stable")
OLD_LTS = kernelver.KernelSupport("6.1.158+", "7.3", "7.2.12", "older")


def test_build_all_pages(app):
    win = _FakeWin(app)
    for ks in (None, OLD_LTS, SUPPORTED,
               kernelver.KernelSupport("6.1.158", error="network unreachable")):
        for kw in ({}, {"hsi_undetermined": True}, {"empty_scores": True}):
            report = _report(ks=ks, **kw)
            assert isinstance(ui.build_dashboard(report, win, lambda k: None), Gtk.ScrolledWindow)
            assert isinstance(ui.build_hsi(report, win), Gtk.ScrolledWindow)
            assert isinstance(ui.build_kernel(report, win), Gtk.ScrolledWindow)
            assert isinstance(ui.build_hardware(report, win), Gtk.ScrolledWindow)
            assert isinstance(ui.build_habits(report, win), Gtk.ScrolledWindow)


def test_score_helpers_accept_none(app):
    assert ui.score_str(None) == ui.SCORE_NA
    assert ui.score_css(None) == "dim-label"
    assert isinstance(ui.score_label(None), Gtk.Label)
    assert isinstance(ui.level_bar(None), Gtk.LevelBar)


def test_kernel_warning_dialog(app):
    dlg = ui.kernel_warning_dialog(OLD_LTS)
    assert dlg is not None
    win = _FakeWin(app)
    if hasattr(Adw, "AlertDialog"):
        dlg.present(win)
    else:
        dlg.set_transient_for(win)
        dlg.present()
    dlg.close()


def test_hsi_page_without_fwupd(app):
    report = _report()
    report.hsi = checks.HsiReport(ok=False, error="org.freedesktop.fwupd is not available")
    win = _FakeWin(app)
    assert isinstance(ui.build_hsi(report, win), Gtk.ScrolledWindow)
    assert isinstance(ui.build_dashboard(report, win, lambda k: None), Gtk.ScrolledWindow)


def test_main_window_constructs(app):
    """真正创建 MainWindow：能验证菜单、动作与信号连接没有写错。"""
    from computesec import main as app_main
    win = app_main.MainWindow(app)
    win.present()
    assert win.listbox.get_row_at_index(0) is not None
    win.destroy()
