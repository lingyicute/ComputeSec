"""Unreadable wildcard members must never turn into a successful check."""

import io

import pytest

from computesec import checks, hostdata

KEY = "net.ipv4.conf.*.accept_redirects"
ALL = KEY.replace("*", "all")
ETH = KEY.replace("*", "eth0")
WLAN = KEY.replace("*", "wlan0")


def test_proc_keeps_permission_denied_member(monkeypatch):
    paths = ["/proc/sys/" + key.replace(".", "/") for key in (ALL, ETH)]
    monkeypatch.setattr(checks, "_sysctl_paths", lambda _key: paths)

    def fake_open(path):
        if path == paths[1]:
            raise PermissionError(path)
        return io.StringIO("0\n")

    monkeypatch.setattr("builtins.open", fake_open)
    actual, unreadable = checks._sysctl_from_proc(KEY)
    assert actual == {ALL: "0", ETH: None}
    assert unreadable


@pytest.mark.parametrize("actual,supplied,status", [
    ({ALL: "0", ETH: None}, {}, "unknown"),
    ({ALL: "1", ETH: None}, {}, "missing"),
    ({ETH: None}, {}, "unknown"),
    ({ALL: "0", ETH: None}, {ETH: "0"}, "ok"),
    ({ALL: "0", ETH: None}, {ETH: "1"}, "missing"),
    ({ALL: "0", ETH: None, WLAN: None}, {ETH: "0"}, "unknown"),
])
def test_partial_read_is_not_a_pass(monkeypatch, actual, supplied, status):
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": supplied}}}})
    monkeypatch.setattr(hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [
        ("test", [{"key": KEY, "value": "0", "desc": "test"}]),
    ])
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _key: (actual, True))
    report = checks.get_sysctl_report()
    assert report.all_items[0].status == status
    if status == "unknown":
        assert report.score is None
        assert report.scored == []
    if supplied:
        assert report.all_items[0].actual[ETH] == supplied[ETH]


def test_io_failure_is_unknown_not_unsupported(monkeypatch):
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [
        ("test", [{"key": KEY, "value": "0", "desc": "test"}]),
    ])
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _key: ({ETH: None}, False))
    assert checks.get_sysctl_report().all_items[0].status == "unknown"
