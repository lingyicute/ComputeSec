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
