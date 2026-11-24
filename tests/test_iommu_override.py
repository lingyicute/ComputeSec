# -*- coding: utf-8 -*-
import pytest

from computesec import checks


@pytest.mark.parametrize("vendor,key,cmdline", [
    ("intel", "intel_iommu", "iommu=off intel_iommu=on"),
    ("intel", "intel_iommu", "intel_iommu=on iommu=force,off"),
    ("amd", "amd_iommu", "iommu=off amd_iommu=force_isolation"),
])
def test_x86_iommu_off_overrides_vendor_iommu(monkeypatch, vendor, key, cmdline):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: vendor)
    monkeypatch.setattr(checks, "read", lambda path, default="": cmdline if path == "/proc/cmdline" else default)
    by_key = {item.key: item for item in checks.get_cmdline_report().items}
    assert by_key[key].status == "wrong"
    assert by_key[key].actual == "iommu=off"


@pytest.mark.parametrize("arch_name,cmdline,want", [
    ("x86_64", "iommu.passthrough=0 iommu=pt", "wrong"),
    ("x86_64", "iommu.passthrough=0 iommu=force,pt", "wrong"),
    ("x86_64", "iommu.passthrough=0 iommu=pt,nopt", "ok"),
    ("x86_64", "iommu.passthrough=0 iommu=pt iommu=nopt", "ok"),
    ("x86_64", "iommu=pt iommu.passthrough=0", "ok"),
    ("aarch64", "iommu.passthrough=0 iommu=pt", "ok"),
])
def test_x86_later_iommu_pt_overrides_passthrough_zero(monkeypatch, arch_name, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: arch_name)
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel" if arch_name == "x86_64" else None)
    monkeypatch.setattr(checks, "read", lambda path, default="": cmdline if path == "/proc/cmdline" else default)
    by_key = {item.key: item for item in checks.get_cmdline_report().items}
    assert by_key["iommu.passthrough"].status == want
    if want == "wrong":
        assert by_key["iommu.passthrough"].actual == "iommu=pt"
