from computesec import checks, data


def test_ipv6_source_route_is_disabled_with_negative_value():
    entry = next(e for _, entries in data.SYSCTL_GROUPS for e in entries
                 if e["key"] == "net.ipv6.conf.*.accept_source_route")
    assert entry["value"] == "-1"
    assert not checks._sysctl_value_ok("0", entry["value"], entry.get("cmp", "eq"))
    assert checks._sysctl_value_ok("-1", entry["value"], entry.get("cmp", "eq"))
