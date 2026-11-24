from computesec import checks, data, hostdata


def test_privacy_checks_existing_interfaces_not_just_defaults(monkeypatch):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group
               if e["key"].endswith(".use_tempaddr")]
    assert len(entries) == 1
    assert entries[0]["key"] == "net.ipv6.conf.*.use_tempaddr"
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("privacy", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    values = {f"net.ipv6.conf.{name}.use_tempaddr": value
              for name, value in (("all", "2"), ("default", "2"), ("eth0", "0"))}
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData({"steps": {
        "sysctl": {"data": {"values": values}}}}))
    report = checks.get_sysctl_report()
    assert report.all_items[0].status == "missing"
    assert "eth0=0" in report.all_items[0].actual_text


def test_irrelevant_all_and_loopback_values_do_not_fail_privacy(monkeypatch):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group
               if e["key"].endswith(".use_tempaddr")]
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("privacy", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData())
    values = {f"net.ipv6.conf.{name}.use_tempaddr": value for name, value in (
        ("all", "0"), ("lo", "-1"), ("default", "2"), ("eth0", "3"))}
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _: (values, set()))
    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "ok"
    assert "net.ipv6.conf.all.use_tempaddr" not in item.actual
    assert "net.ipv6.conf.lo.use_tempaddr" not in item.actual


def test_flatpak_snapshot_with_only_skipped_ifaces_is_unverified(monkeypatch):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group
               if e["key"].endswith(".use_tempaddr")]
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("privacy", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: True)
    values = {"net.ipv6.conf.all.use_tempaddr": "2", "net.ipv6.conf.lo.use_tempaddr": "-1"}
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData({"steps": {
        "sysctl": {"data": {"values": values}}}}))
    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "unverified"
    assert item.source == "快照缺失"


def test_native_denied_skipped_iface_does_not_taint_live_source(monkeypatch):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group
               if e["key"].endswith(".use_tempaddr")]
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("privacy", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    proc_vals = {
        "net.ipv6.conf.all.use_tempaddr": None,
        "net.ipv6.conf.default.use_tempaddr": "2",
        "net.ipv6.conf.eth0.use_tempaddr": "2",
    }
    monkeypatch.setattr(checks, "_sysctl_from_proc",
                        lambda _: (proc_vals, {"net.ipv6.conf.all.use_tempaddr"}))
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData({"steps": {
        "sysctl": {"data": {"values": {"net.ipv6.conf.all.use_tempaddr": "2"}}}}}))
    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "ok"
    assert item.source == "proc"


def test_missing_default_use_tempaddr_cannot_pass(monkeypatch):
    entries = [e for _, group in data.SYSCTL_GROUPS for e in group
               if e["key"].endswith(".use_tempaddr")]
    monkeypatch.setattr(data, "SYSCTL_GROUPS", [("privacy", entries)])
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData({"steps": {
        "sysctl": {"data": {"values": {"net.ipv6.conf.eth0.use_tempaddr": "2"}}}}}))
    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "unknown"
