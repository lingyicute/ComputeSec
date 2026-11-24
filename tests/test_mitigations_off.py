# -*- coding: utf-8 -*-
from computesec import checks


def test_mitigations_off_overrides_individual_x86_mitigations(monkeypatch):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    cmdline = (
        "mitigations=off pti=on spectre_v2=on "
        "spec_store_bypass_disable=on l1tf=full,force gather_data_sampling=force"
    )
    monkeypatch.setattr(checks, "read", lambda path, default="": cmdline if path == "/proc/cmdline" else default)
    report = checks.get_cmdline_report()
    by_key = {item.key: item for item in report.items}
    for key in ("pti", "spectre_v2", "spec_store_bypass_disable", "l1tf", "gather_data_sampling"):
        assert by_key[key].status == "wrong"
        assert by_key[key].actual == "mitigations=off"


def test_later_mitigations_re_enables_individual_x86_mitigations(monkeypatch):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    cmdline = "mitigations=off mitigations=auto,nosmt pti=on spectre_v2=on"
    monkeypatch.setattr(checks, "read", lambda path, default="": cmdline if path == "/proc/cmdline" else default)
    report = checks.get_cmdline_report()
    by_key = {item.key: item for item in report.items}
    assert by_key["mitigations"].status == "ok"
    assert by_key["pti"].status == "ok"
    assert by_key["spectre_v2"].status == "ok"
