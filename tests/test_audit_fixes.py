# -*- coding: utf-8 -*-
import pytest

from computesec import checks, cli, data, hostdata


@pytest.mark.parametrize("cmdline,want", [
    ("hash_pointers=always no_hash_pointers=0", "wrong"),
    ("hash_pointers=always no_hash_pointers=1", "wrong"),
    ("no_hash_pointers=1 hash_pointers=always", "ok"),
])
def test_no_hash_pointers_with_value_disables_hashing(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["hash_pointers"]
    assert item.status == want


@pytest.mark.parametrize("cmdline,want", [
    ("slab_nomerge slab_merge=1", "missing"),
    ("slub_nomerge slub_merge=0", "missing"),
    ("slab_merge=1 slab_nomerge", "ok"),
])
def test_slab_merge_with_value_overrides_earlier_nomerge(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["slab_nomerge"]
    assert item.status == want


@pytest.mark.parametrize("cmdline,want,actual", [
    ("quiet loglevel=0", "ok", "0"),
    ("debug loglevel=0", "ok", "0"),
    ("loglevel=0 quiet", "wrong", "quiet"),
    ("loglevel=0 debug", "wrong", "debug"),
    ("loglevel=0 quiet=1", "wrong", "quiet"),
    ("loglevel=0 quiet loglevel=0", "ok", "0"),
])
def test_later_quiet_or_debug_overrides_loglevel_zero(monkeypatch, cmdline, want, actual):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["loglevel"]
    assert item.status == want
    assert item.actual == actual


@pytest.mark.parametrize("cmdline,want", [
    ("ignore_loglevel loglevel=0", "wrong"),
    ("loglevel=0 ignore_loglevel", "wrong"),
    ("loglevel=0 printk.ignore_loglevel", "wrong"),
    ("loglevel=0 printk.ignore_loglevel=1", "wrong"),
    ("ignore_loglevel loglevel=0 printk.ignore_loglevel=0", "ok"),
    ("printk.ignore_loglevel=0 ignore_loglevel loglevel=0", "ok"),
])
def test_ignore_loglevel_bypasses_loglevel_zero(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["loglevel"]
    assert item.status == want


@pytest.mark.parametrize("cmdline,iommu_want,pt_want", [
    ("iommu=force,pt iommu.passthrough=0", "ok", "ok"),
    ("iommu=force,pt iommu.passthrough=1", "wrong", "wrong"),
    ("iommu=pt iommu.passthrough=0", "wrong", "ok"),
    ("iommu=off,force,pt iommu.passthrough=0", "wrong", "ok"),
])
def test_x86_later_passthrough_zero_reconciles_iommu_force(monkeypatch, cmdline, iommu_want, pt_want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    by_key = {i.key: i for i in checks.get_cmdline_report().items}
    assert by_key["iommu"].status == iommu_want
    assert by_key["iommu.passthrough"].status == pt_want


def test_sysctl_rejects_python_underscores_non_ascii_digits_and_invalid_rp_filter(monkeypatch):
    assert checks._sysctl_value_ok("3_2", "32", "ge") is False
    assert checks._sysctl_value_ok("３２", "32", "ge") is False
    assert checks._sysctl_value_ok("5_0", "100", "le") is False

    entries = [e for _, grp in data.SYSCTL_GROUPS for e in grp if e["key"].endswith(".rp_filter")]
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("test", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData())
    for bad_iface in ("-1", "abc", "1_0"):
        vals = {
            "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.conf.default.rp_filter": "1",
            "net.ipv4.conf.eth0.rp_filter": bad_iface,
        }
        monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _, v=vals: (v, set()))
        item = checks.get_sysctl_report().all_items[0]
        assert item.status == "missing"


def test_hardware_strips_interior_nul_in_dt_model_and_detects_vm_bios_vendor(monkeypatch):
    files = {
        "/sys/class/dmi/id/sys_vendor": "LENOVO\n",
        "/sys/class/dmi/id/product_name": "20XW\n",
        "/sys/class/dmi/id/bios_vendor": "QEMU\n",
        "/proc/device-tree/model": "Raspberry\x00Pi 5\r\n\x00",
    }
    monkeypatch.setattr(checks, "read", lambda p, d="": files.get(p, d))
    monkeypatch.setattr(checks.hostinfo, "get_identity", lambda refresh=False: checks.hostinfo.HostIdentity())
    hw = checks.get_hardware()
    assert "\x00" not in hw.model and hw.model == "RaspberryPi 5"
    assert hw.vendor is data.VM_VENDOR
    assert hw.matched_on == "固件厂商: QEMU"


def test_usb_devices_cleans_nul_bytes_and_reads_composite_interface_classes(monkeypatch):
    def fake_glob(pat):
        if pat == "/sys/bus/usb/devices/*":
            return ["/sys/bus/usb/devices/1-4"]
        if pat == "/sys/bus/usb/devices/1-4/1-4:*/bInterfaceClass":
            return ["/sys/bus/usb/devices/1-4/1-4:1.0/bInterfaceClass",
                    "/sys/bus/usb/devices/1-4/1-4:1.1/bInterfaceClass"]
        return []

    files = {
        "/sys/bus/usb/devices/1-4/idVendor": "8087\x00\n",
        "/sys/bus/usb/devices/1-4/idProduct": "0033\x00\n",
        "/sys/bus/usb/devices/1-4/manufacturer": "Intel\x00\n",
        "/sys/bus/usb/devices/1-4/product": "USB Dongle\x00\n",
        "/sys/bus/usb/devices/1-4/bDeviceClass": "ef\n",
        "/sys/bus/usb/devices/1-4/1-4:1.0/bInterfaceClass": "e0\n",
        "/sys/bus/usb/devices/1-4/1-4:1.1/bInterfaceClass": "e0\n",
    }
    monkeypatch.setattr(checks.glob, "glob", fake_glob)
    monkeypatch.setattr(checks, "read", lambda p, d="": files.get(p, d))
    devs, _ = checks._usb_devices()
    assert devs == [{"vid": "8087", "pid": "0033", "product": "USB Dongle", "manufacturer": "Intel", "cls": "e0"}]
    assert checks.check_usb().status == "good"


def test_ntfs_from_lsblk_json_handles_deeply_nested_children_without_recursion_error():
    leaf = {"name": "dm-999", "fstype": "ntfs", "label": "Deep", "size": "1G", "mountpoint": None}
    cur = leaf
    for idx in range(1500):
        cur = {"name": f"dm-{idx}", "fstype": None, "children": [cur]}
    payload = {"blockdevices": [cur]}
    assert hostdata._lsblk_data_ok(payload) is True
    found = checks._ntfs_from_lsblk_json(payload)
    assert len(found) == 1 and "/dev/dm-999" in found[0]


def test_mounts_parser_preserves_unicode_spaces_and_decodes_utf8_octal_bytes(monkeypatch):
    assert checks._unescape_mount_field(r"/mnt/\344\270\255\346\226\207\040盘") == "/mnt/中文 盘"
    assert checks._unescape_mount_field(r"a\134040b") == r"a\040b"
    assert checks._unescape_mount_field(r"\777") == r"\777"

    monkeypatch.setattr(checks.hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))
    monkeypatch.setattr(checks.glob, "glob", lambda _: [])
    mounts = "/dev/sda2 /run/media/u/新加卷\u3000D ntfs3 rw,relatime 0 0\n"
    monkeypatch.setattr(checks, "read", lambda p, d="": mounts if p == "/proc/mounts" else d)
    found, _ = checks._ntfs_partitions()
    assert len(found) == 1 and "新加卷　D" in found[0]


def test_cli_default_launcher_supports_python_dash_m_invocation(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli.sys, "argv", [cli.__file__, "--install"])
    monkeypatch.setattr(cli.sys, "executable", "/usr/bin/python3")
    assert cli.install_desktop() is True
    desktop = (tmp_path / "xdg" / "applications" / f"{cli.APP_ID}.desktop").read_text(encoding="utf-8")
    assert "Exec=/usr/bin/python3 -m computesec.cli" in desktop
