# -*- coding: utf-8 -*-
from computesec import checks, hostinfo


def test_cpu_model_strips_nul_bytes_from_soc0(monkeypatch):
    def fake_read(path, default=""):
        if path == "/sys/devices/soc0/machine":
            return "Raspberry Pi 5\x00\n"
        return default

    monkeypatch.setattr(checks, "read", fake_read)
    assert checks.cpu_model() == "Raspberry Pi 5"


def test_get_hardware_strips_nul_bytes_from_dmi(monkeypatch):
    def fake_read(path, default=""):
        if path == "/sys/class/dmi/id/sys_vendor":
            return "Framework\x00\n"
        return default

    monkeypatch.setattr(checks, "read", fake_read)
    monkeypatch.setattr(hostinfo, "get_identity", lambda refresh=False: hostinfo.HostIdentity())
    hw = checks.get_hardware()
    assert hw.sys_vendor == "Framework"
    assert hw.vendor["name"] == "Framework"
