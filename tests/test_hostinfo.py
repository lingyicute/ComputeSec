# -*- coding: utf-8 -*-
"""hostinfo.py 单元测试。

本模块不 import gi（D-Bus 那条路径是惰性导入），所以在没有 GTK 的环境里也能测。
D-Bus 与 os-release 的来源用 monkeypatch 替换，不依赖真实系统。
"""

from computesec import hostinfo


# ---------------------------------------------------------------------------
# os-release 解析
# ---------------------------------------------------------------------------
def test_parse_os_release_basic():
    text = (
        'NAME="Fedora Linux"\n'
        "VERSION_ID=44\n"
        "PRETTY_NAME='Fedora Linux 44 (Workstation)'\n"
        "# 注释行应被忽略\n"
        "\n"
        "MALFORMED_LINE\n"
        "ID=fedora\n"
    )
    d = hostinfo.parse_os_release(text)
    assert d["NAME"] == "Fedora Linux"          # 双引号被剥掉
    assert d["VERSION_ID"] == "44"              # 数字不加引号
    assert d["PRETTY_NAME"] == "Fedora Linux 44 (Workstation)"   # 单引号同样剥掉
    assert d["ID"] == "fedora"
    assert "MALFORMED_LINE" not in d
    assert "# 注释行应被忽略" not in d


def test_parse_os_release_keeps_inner_quotes_and_equals():
    d = hostinfo.parse_os_release('A="say \'hi\'"\nB=a=b=c\nC=""\nD="\n')
    assert d["A"] == "say 'hi'"
    assert d["B"] == "a=b=c"                    # 只在第一个 = 处切分
    assert d["C"] == ""
    assert d["D"] == '"'                        # 单个引号不算成对，原样保留


def test_parse_os_release_empty():
    assert hostinfo.parse_os_release("") == {}


# ---------------------------------------------------------------------------
# HostIdentity 的回退顺序
# ---------------------------------------------------------------------------
def test_os_name_fallback_chain():
    assert hostinfo.HostIdentity(pretty_name="Fedora 44").os_name == "Fedora 44"
    assert hostinfo.HostIdentity(os_release={"PRETTY_NAME": "Debian 13"}).os_name == "Debian 13"
    assert hostinfo.HostIdentity(os_release={"NAME": "Alpine"}).os_name == "Alpine"
    assert hostinfo.HostIdentity().os_name == "Linux"


def test_kernel_falls_back_to_platform(monkeypatch):
    assert hostinfo.HostIdentity(kernel_release="7.2.12").kernel == "7.2.12"
    monkeypatch.setattr(hostinfo.platform, "release", lambda: "9.9.9-test")
    assert hostinfo.HostIdentity().kernel == "9.9.9-test"


# ---------------------------------------------------------------------------
# _build_identity：D-Bus 优先，os-release 兜底
# ---------------------------------------------------------------------------
def test_build_identity_prefers_dbus(monkeypatch):
    props = {"OperatingSystemPrettyName": "Fedora Linux 44", "KernelRelease": "7.2.12",
             "Chassis": "laptop", "UnknownProperty": "x"}
    monkeypatch.setattr(hostinfo, "_dbus_hostname1", lambda: (props, ""))
    monkeypatch.setattr(hostinfo, "_host_os_release_text", lambda: ('PRETTY_NAME="runtime"\n', "/run/host/os-release"))
    ident = hostinfo._build_identity()
    assert ident.pretty_name == "Fedora Linux 44"
    assert ident.kernel_release == "7.2.12"
    assert ident.chassis == "laptop"
    assert ident.source == "D-Bus org.freedesktop.hostname1"
    assert ident.dbus_error == ""
    # os-release 仍然被读入，用于补全其它字段
    assert ident.os_release["PRETTY_NAME"] == "runtime"


def test_build_identity_falls_back_to_host_os_release(monkeypatch):
    monkeypatch.setattr(hostinfo, "_dbus_hostname1", lambda: ({}, "no such service"))
    monkeypatch.setattr(hostinfo, "_host_os_release_text",
                        lambda: ('NAME="Debian GNU/Linux"\nPRETTY_NAME="Debian 13 (Trixie)"\n', "/run/host/os-release"))
    ident = hostinfo._build_identity()
    assert ident.dbus_error == "no such service"
    assert ident.source == "/run/host/os-release"
    assert ident.os_name == "Debian 13 (Trixie)"
    assert ident.kernel_release                  # 兜底到 platform.release()


def test_build_identity_marks_runtime_os_release_in_flatpak(monkeypatch):
    monkeypatch.setattr(hostinfo, "_dbus_hostname1", lambda: ({}, "unavailable"))
    monkeypatch.setattr(hostinfo, "_host_os_release_text", lambda: ("", ""))
    monkeypatch.setattr(hostinfo, "IN_FLATPAK", True)
    monkeypatch.setattr(hostinfo, "_read", lambda path, default="": (
        'NAME="GNOME Platform"\nPRETTY_NAME="GNOME Platform 50"\n' if path == "/etc/os-release" else default))
    ident = hostinfo._build_identity()
    assert "可能不准确" in ident.source
    assert ident.pretty_name == "GNOME Platform 50"


def test_dbus_error_is_kept_for_display(monkeypatch):
    monkeypatch.setattr(hostinfo, "_dbus_hostname1", lambda: ({}, "org.freedesktop.DBus.Error.ServiceUnknown"))
    monkeypatch.setattr(hostinfo, "_host_os_release_text", lambda: ('PRETTY_NAME="Arch Linux"\n', "/etc/os-release"))
    ident = hostinfo._build_identity()
    assert ident.dbus_error.startswith("org.freedesktop.DBus.Error")
    assert ident.pretty_name == "Arch Linux"


# ---------------------------------------------------------------------------
# os-release 的路径选择
# ---------------------------------------------------------------------------
def test_host_os_release_paths_native(monkeypatch):
    seen = []

    def fake_read(path, default=""):
        seen.append(path)
        return 'PRETTY_NAME="X"\n' if path == "/usr/lib/os-release" else default

    monkeypatch.setattr(hostinfo, "IN_FLATPAK", False)
    monkeypatch.setattr(hostinfo, "_read", fake_read)
    text, src = hostinfo._host_os_release_text()
    assert text and src == "/usr/lib/os-release"
    assert seen[0] == "/etc/os-release"          # 先试 /etc，再试 /usr/lib


def test_host_os_release_paths_flatpak(monkeypatch):
    seen = []

    def fake_read(path, default=""):
        seen.append(path)
        return default                          # 全都读不到

    monkeypatch.setattr(hostinfo, "IN_FLATPAK", True)
    monkeypatch.setattr(hostinfo, "_read", fake_read)
    assert hostinfo._host_os_release_text() == ("", "")
    # Flatpak 内只看 /run/host/**，绝不把 runtime 的 /etc/os-release 当宿主机
    assert all(p.startswith("/run/host/") for p in seen)


# ---------------------------------------------------------------------------
# 缓存
# ---------------------------------------------------------------------------
def test_get_identity_caches(monkeypatch):
    calls = []
    monkeypatch.setattr(hostinfo, "_CACHE", None)
    monkeypatch.setattr(hostinfo, "_build_identity", lambda: (calls.append(1), hostinfo.HostIdentity(pretty_name="A"))[1])
    assert hostinfo.get_identity().pretty_name == "A"
    assert hostinfo.get_identity().pretty_name == "A"
    assert len(calls) == 1
    hostinfo.get_identity(refresh=True)
    assert len(calls) == 2
