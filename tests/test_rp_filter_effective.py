import pytest
from computesec import checks, data, hostdata

@pytest.mark.parametrize("all_value,default,iface,want", [
    ("1", "1", "2", "missing"), ("1", "0", "0", "ok"),
    ("0", "1", "1", "ok"), ("0", "0", "1", "missing"),
    ("2", "1", "1", "missing"), (None, "1", "1", "unknown"),
    ("1", "1", None, "unknown"), (None, "1", "2", "missing"), (None, "1", "3", "missing"),
])
@pytest.mark.parametrize("sandbox", [False, True])
def test_effective_reverse_path_filter(monkeypatch, all_value, default, iface, want, sandbox):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group if e["key"].endswith(".rp_filter")]
    assert len(entries) == 1 and entries[0]["key"] == "net.ipv4.conf.*.rp_filter"
    values = {f"net.ipv4.conf.{name}.rp_filter": value for name, value in (
        ("all", all_value), ("default", default), ("eth0", iface))}
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("test", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", sandbox)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: True)
    snapshot = {k: v for k, v in values.items() if v is not None}
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": snapshot}}}}) if sandbox else hostdata.HostData()
    monkeypatch.setattr(hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _: (values, set()))
    item = checks.get_sysctl_report().all_items[0]
    assert item.status == want
    assert item.actual == (snapshot if sandbox else values)


@pytest.mark.parametrize("names", [("all",), ("all", "default"), ("all", "eth0")])
def test_incomplete_interface_snapshot_cannot_pass(names):
    actual = {f"net.ipv4.conf.{name}.rp_filter": "1" for name in names}
    compared = checks._sysctl_effective_values("net.ipv4.conf.*.rp_filter", actual)
    assert any(value is None for value in compared.values())
