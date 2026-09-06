# -*- coding: utf-8 -*-
"""宿主机身份信息。

Flatpak 沙箱内 /etc/os-release 属于 runtime（org.gnome.Platform），读到的是
"GNOME Platform" 而不是用户真实的发行版。正确做法是走 D-Bus 的
org.freedesktop.hostname1 接口（systemd 提供，权限：--system-talk-name），
它返回的是宿主机的字段。若 D-Bus 不可用，再退回到 /run/host/os-release
（Flatpak 会把宿主机的 os-release 绑定挂载到这里），最后才是 /etc/os-release。

本模块不依赖 checks.py，避免循环导入。
"""

import os
import platform
from dataclasses import dataclass, field

IN_FLATPAK = os.path.exists("/.flatpak-info")

HOSTNAME1_BUS = "org.freedesktop.hostname1"
HOSTNAME1_PATH = "/org/freedesktop/hostname1"

# hostname1 属性 -> 本模块字段
_HOSTNAME1_FIELDS = (
    ("OperatingSystemPrettyName", "pretty_name"),
    ("OperatingSystemCPEName", "cpe_name"),
    ("KernelName", "kernel_name"),
    ("KernelRelease", "kernel_release"),
    ("KernelVersion", "kernel_build"),
    ("HardwareVendor", "hw_vendor"),
    ("HardwareModel", "hw_model"),
    ("FirmwareVersion", "firmware_version"),
    ("Chassis", "chassis"),
    ("Hostname", "hostname"),
    ("StaticHostname", "static_hostname"),
)


@dataclass
class HostIdentity:
    pretty_name: str = ""
    cpe_name: str = ""
    kernel_name: str = ""
    kernel_release: str = ""
    kernel_build: str = ""
    hw_vendor: str = ""
    hw_model: str = ""
    firmware_version: str = ""
    chassis: str = ""
    hostname: str = ""
    static_hostname: str = ""
    os_release: dict = field(default_factory=dict)
    source: str = ""            # 数据来源，用于在界面上说明
    dbus_error: str = ""        # D-Bus 失败原因（若有）

    @property
    def os_name(self):
        return (self.pretty_name
                or self.os_release.get("PRETTY_NAME")
                or self.os_release.get("NAME")
                or "Linux")

    @property
    def kernel(self):
        return self.kernel_release or platform.release()


def _read(path, default=""):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def parse_os_release(text):
    d = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        d[k.strip()] = v
    return d


def _dbus_hostname1():
    """通过 D-Bus 读取宿主机 hostname1 属性。返回 (dict, error)。"""
    try:
        import gi
        from gi.repository import Gio, GLib
    except Exception as e:                                  # pragma: no cover
        return {}, f"PyGObject 不可用：{e}"
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        res = bus.call_sync(
            HOSTNAME1_BUS, HOSTNAME1_PATH, "org.freedesktop.DBus.Properties", "GetAll",
            GLib.Variant("(s)", (HOSTNAME1_BUS,)), GLib.VariantType("(a{sv})"),
            Gio.DBusCallFlags.NONE, 8000, None)
        props = res.unpack()[0]
        return {k: v for k, v in props.items() if isinstance(v, str)}, ""
    except Exception as e:
        return {}, str(e)


def _host_os_release_text():
    """宿主机 os-release 文本（非 D-Bus 途径）。返回 (text, source)。"""
    if IN_FLATPAK:
        # Flatpak 默认把宿主机 os-release 挂到 /run/host/os-release
        for p in ("/run/host/os-release", "/run/host/etc/os-release", "/run/host/usr/lib/os-release"):
            t = _read(p)
            if t.strip():
                return t, p
        return "", ""
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        t = _read(p)
        if t.strip():
            return t, p
    return "", ""


_CACHE = None


def get_identity(refresh=False) -> HostIdentity:
    """读取宿主机身份信息。结果会被缓存（这些字段在一次运行内不会变），
    避免每次检测都产生多次 D-Bus 往返。"""
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE
    ident = _build_identity()
    _CACHE = ident
    return ident


def _build_identity() -> HostIdentity:
    ident = HostIdentity()

    props, err = _dbus_hostname1()
    if props:
        for prop, attr in _HOSTNAME1_FIELDS:
            val = props.get(prop, "")
            if val:
                setattr(ident, attr, val)
        ident.source = "D-Bus org.freedesktop.hostname1"
    else:
        ident.dbus_error = err

    text, src = _host_os_release_text()
    if text:
        ident.os_release = parse_os_release(text)
        if not ident.source:
            ident.source = src
        elif not ident.pretty_name:
            ident.source += f" + {src}"

    if not ident.pretty_name:
        ident.pretty_name = ident.os_release.get("PRETTY_NAME", "")

    # 兜底：runtime 的 /etc/os-release（Flatpak 内不准确，仅在别无选择时使用）
    if not ident.pretty_name and not ident.os_release:
        ident.os_release = parse_os_release(_read("/etc/os-release"))
        ident.pretty_name = ident.os_release.get("PRETTY_NAME", "")
        ident.source = "/etc/os-release（Flatpak 内为 runtime 字段，可能不准确）" if IN_FLATPAK else "/etc/os-release"

    if not ident.kernel_release:
        ident.kernel_release = platform.release()
    return ident
