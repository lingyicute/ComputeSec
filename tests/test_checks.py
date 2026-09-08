# -*- coding: utf-8 -*-
"""checks.py 单元测试：比对逻辑与评分规则。

只覆盖不依赖 GTK / D-Bus / 外部命令的纯逻辑，外加两个对本机 /proc 的
宽松冒烟测试（只断言结构合法，不断言具体数值）。
"""

import pytest

from computesec import checks, data


# ---------------------------------------------------------------------------
# 小工具函数
# ---------------------------------------------------------------------------

def test_norm_key():
    assert checks._norm_key("iommu.passthrough") == "iommu.passthrough"
    assert checks._norm_key("kvm-intel.vmentry_l1d_flush") == "kvm_intel.vmentry_l1d_flush"


def test_sysctl_norm():
    assert checks._sysctl_norm("  1  ") == "1"
    assert checks._sysctl_norm("a   b\tc") == "a b c"
    # fs.binfmt_misc.status 读出来是单词、写入是数字，两者等价
    assert checks._sysctl_norm("disabled") == "0"
    assert checks._sysctl_norm("enabled") == "1"
    assert checks._sysctl_norm("DISABLED") == "0"


@pytest.mark.parametrize("actual,expected,cmp,want", [
    ("1", "1", "eq", True),
    ("0", "1", "eq", False),
    ("disabled", "0", "eq", True),   # 别名归一化
    ("enabled", "1", "eq", True),
    (None, "1", "eq", False),
    ("3", "1", "ge", True),
    ("1", "3", "ge", False),
    ("32", "32", "ge", True),
    ("on", "on", "ge", True),        # 非数字回退到字符串比较
    ("on", "off", "ge", False),
])
def test_sysctl_value_ok(actual, expected, cmp, want):
    assert checks._sysctl_value_ok(actual, expected, cmp) is want


def test_flags_to_set():
    assert checks._flags_to_set(1) == {"success"}
    assert checks._flags_to_set(3) == {"success", "obsoleted"}
    assert checks._flags_to_set(["a", "b"]) == {"a", "b"}
    assert checks._flags_to_set("a|b") == {"a", "b"}
    assert checks._flags_to_set(0) == set()


def test_result_to_str():
    assert checks._result_to_str(1) == "enabled"
    assert checks._result_to_str(8) == "not-encrypted"
    assert checks._result_to_str(99) == "unknown"
    assert checks._result_to_str("enabled") == "enabled"
    assert checks._result_to_str("") == "unknown"
    assert checks._result_to_str(None) == "unknown"


def test_lookup_hsi_info():
    direct = checks._lookup_hsi_info("org.fwupd.hsi.Uefi.SecureBoot")
    assert direct["name"] == "UEFI 安全启动"
    # 别名解析
    alias = checks._lookup_hsi_info("org.fwupd.hsi.Cet.Enabled")
    assert alias["name"] == "控制流强制技术 (CET) 支持"
    # 去掉厂商前缀的模糊匹配
    fuzzy = checks._lookup_hsi_info("com.example.Foo.SecureBoot")
    assert fuzzy["name"] == "UEFI 安全启动"
    # 完全未知返回空字典（调用方用 .get 做降级）
    assert checks._lookup_hsi_info("org.example.Nope") == {}


# ---------------------------------------------------------------------------
# NTFS 解析
# ---------------------------------------------------------------------------

def test_ntfs_from_lsblk_json():
    j = {"blockdevices": [
        {"name": "sda", "fstype": None, "label": None, "size": "500G",
         "mountpoint": None, "children": [
             {"name": "sda1", "fstype": "vfat", "label": "EFI",
              "size": "512M", "mountpoint": "/boot/efi"},
             {"name": "sda2", "fstype": "ntfs", "label": "DATA",
              "size": "200G", "mountpoint": None},
             {"name": "sda3", "fstype": "NTFS3", "label": None,
              "size": "10G", "mountpoint": None},
         ]},
    ]}
    found = checks._ntfs_from_lsblk_json(j)
    assert len(found) == 2
    assert any("/dev/sda2" in f for f in found)
    assert any("/dev/sda3" in f for f in found)  # fstype 大小写不敏感


def test_ntfs_from_lsblk_json_empty():
    assert checks._ntfs_from_lsblk_json({"blockdevices": []}) == []
    assert checks._ntfs_from_lsblk_json({}) == []


# ---------------------------------------------------------------------------
# 评分规则
# ---------------------------------------------------------------------------

def _hsi_item(name, passed, kind="os", fix="do this", obsoleted=False):
    return checks.HsiItem(
        id=f"org.test.{name}", name=name, summary="", level=1,
        result="enabled" if passed else "not-enabled",
        flags={"success"} if passed else set(), uri="",
        info={"fix": fix, "kind": kind} if fix else {}, passed=passed,
        obsoleted=obsoleted)


def test_hsi_report_score():
    r = checks.HsiReport(ok=True, items=[
        _hsi_item("a", True), _hsi_item("b", True), _hsi_item("c", False)])
    assert r.score == 66
    assert len(r.active) == 3
    assert len(r.failed) == 1
    # obsoleted 的条目不参与统计
    r.items.append(_hsi_item("old", False, obsoleted=True))
    assert len(r.active) == 3
    assert r.score == 66


def test_hsi_report_score_unavailable():
    assert checks.HsiReport(ok=False).score == 0
    assert checks.HsiReport(ok=True, items=[]).score == 0


def test_hsi_report_fixable_only_os_and_bios_with_fix():
    r = checks.HsiReport(ok=True, items=[
        _hsi_item("os-fix", False, kind="os"),
        _hsi_item("bios-fix", False, kind="bios"),
        _hsi_item("oem-fix", False, kind="oem"),
        _hsi_item("no-fix", False, fix=""),
        _hsi_item("passed", True),
    ])
    assert {i.name for i in r.fixable} == {"os-fix", "bios-fix"}


def test_param_item_token():
    assert checks.ParamItem("slab_nomerge", None, None, "ok", "").token == "slab_nomerge"
    assert checks.ParamItem("lockdown", "confidentiality", "confidentiality", "ok", "").token == \
        "lockdown=confidentiality"


def test_cmdline_report_score():
    r = checks.CmdlineReport(arch="x86_64", cpu="intel", cmdline="", items=[
        checks.ParamItem("a", "1", "1", "ok", ""),
        checks.ParamItem("b", "1", checks.MISSING, "missing", ""),
        checks.ParamItem("c", "1", "2", "wrong", ""),
        checks.ParamItem("d", "1", checks.MISSING, "na", ""),
    ])
    assert len(r.applicable) == 3      # na 不参与
    assert len(r.missing) == 2         # missing + wrong 都算缺失
    assert r.score == 33
    assert checks.CmdlineReport("x86_64", None, "", []).score == 0


def test_sysctl_report_score_excludes_unknown_and_na():
    def item(key, status):
        return checks.SysctlItem(key, "1", "eq", {"x": "1"}, status, "")
    r = checks.SysctlReport(arch="x86_64", groups=[("g", [
        item("ok.1", "ok"), item("bad.1", "missing"),
        item("unk.1", "unknown"), item("na.1", "na"),
    ])])
    # unknown（权限不足无法读取）不计
    assert r.score == 50
    assert [i.key for i in r.missing] == ["bad.1"]
    assert [i.key for i in r.unknown] == ["unk.1"]
    assert checks.SysctlReport("x86_64", groups=[]).score == 0


def test_sysctl_item_actual_text():
    assert checks.SysctlItem("k", "1", "eq", {}, "unknown", "").actual_text.startswith("（无法读取")
    assert checks.SysctlItem("k", "1", "eq", {}, "missing", "").actual_text == "（内核不支持）"
    assert checks.SysctlItem("k", "1", "eq", {"k": "0"}, "missing", "").actual_text == "0"
    multi = checks.SysctlItem("k", "0", "eq",
                              {"net.ipv4.conf.all.x": "0", "net.ipv4.conf.default.x": "1"},
                              "missing", "").actual_text
    assert "all=0" in multi and "default=1" in multi


def test_habits_report_score():
    def check(status):
        return checks.HabitCheck("k", "t", status, "s", [], "")
    assert checks.HabitsReport(checks=[check("good"), check("bad")]).score == 50
    assert checks.HabitsReport(checks=[check("unknown")]).score == 60
    assert checks.HabitsReport(checks=[check("warn")]).score == 40
    assert checks.HabitsReport(checks=[]).score == 0


def _report(hsi_ok=True):
    hsi_items = ([_hsi_item(f"i{i}", i < 4) for i in range(5)]  # 4/5 → 80
                 if hsi_ok else [])
    return checks.Report(
        hsi=checks.HsiReport(ok=hsi_ok, items=hsi_items),
        cmdline=checks.CmdlineReport("x86_64", None, "",
                                     [checks.ParamItem("a", "1", "1", "ok", "")]),   # 100
        sysctl=checks.SysctlReport("x86_64", groups=[("g", [
            checks.SysctlItem("ok.1", "1", "eq", {"x": "1"}, "ok", ""),
            checks.SysctlItem("bad.1", "1", "eq", {"x": "0"}, "missing", ""),
        ])]),                                                                        # 50
        hardware=checks.HardwareReport("", "", "", "", "", "", {"rating": "good"}, ""),  # 100
        habits=checks.HabitsReport(checks=[
            checks.HabitCheck("a", "t", "good", "s", [], ""),
            checks.HabitCheck("b", "t", "bad", "s", [], "")]),                        # 50
        arch="x86_64", cpu="test", os_name="TestOS", kernel="1.0", in_flatpak=False)


def test_report_scores():
    r = _report()
    assert r.kernel_score == 75            # (100 + 50) // 2
    assert r.overall == 76                # (80 + 75 + 100 + 50) // 4


def test_report_overall_hsi_unavailable_counts_50():
    r = _report(hsi_ok=False)
    assert r.overall == 68                # (50 + 75 + 100 + 50) // 4


def test_hardware_score_uses_rating_table():
    for rating, score in data.RATING_SCORE.items():
        hw = checks.HardwareReport("", "", "", "", "", "", {"rating": rating}, "")
        assert hw.score == score


# ---------------------------------------------------------------------------
# 本机冒烟测试（只断言结构合法）
# ---------------------------------------------------------------------------

def test_get_cmdline_report_smoke():
    r = checks.get_cmdline_report()
    assert isinstance(r, checks.CmdlineReport)
    assert 0 <= r.score <= 100
    assert r.arch
    assert all(i.status in ("ok", "missing", "wrong", "na") for i in r.items)


def test_get_sysctl_report_smoke():
    r = checks.get_sysctl_report()
    assert [t for t, _ in r.groups] == [t for t, _ in data.SYSCTL_GROUPS]
    assert 0 <= r.score <= 100
    assert all(i.status in ("ok", "missing", "na", "unknown") for i in r.all_items)
