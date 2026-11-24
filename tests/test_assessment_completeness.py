from dataclasses import replace

from computesec import checks, data, kernelver


def complete_report():
    item = checks._normalize_attrs([{"AppstreamId": "org.fwupd.hsi.Iommu", "Flags": 1}])[0]
    return checks.Report(
        hsi=checks.HsiReport(ok=True, items=[item]),
        cmdline=checks.CmdlineReport("x86_64", "intel", "pti=on", [
            checks.ParamItem("pti", "on", "on", "ok", "test")]),
        sysctl=checks.SysctlReport("x86_64", [("test", [
            checks.SysctlItem("kernel.sysrq", "0", "eq", {"kernel.sysrq": "0"}, "ok", "test")])]),
        hardware=checks.HardwareReport("Framework", "Laptop", "", "", "", "",
                                       next(v for v in data.VENDORS if v["name"] == "Framework"), "DMI"),
        habits=checks.HabitsReport([checks.HabitCheck("uptime", "uptime", "good", "", [], "")]),
        arch="x86_64", cpu="Intel", os_name="Linux", kernel="6.18", in_flatpak=False,
        kernel_support=kernelver.KernelSupport(release="6.18", mainline="6.18"))


def test_complete_report_is_not_marked_partial():
    report = complete_report()
    assert not report.incomplete and report.overall == 100


def test_unknown_checks_do_not_become_a_comprehensive_success():
    report = complete_report()
    report.sysctl.groups[0][1].append(
        checks.SysctlItem("vm.mmap_rnd_bits", "32", "ge", {}, "unknown", "test"))
    assert report.overall == 100  # preserve the established score policy
    assert report.incomplete
    report = complete_report()
    report.habits.checks.append(checks.HabitCheck("usb", "usb", "unknown", "", [], ""))
    assert report.overall == 100 and report.incomplete


def test_missing_support_data_and_unknown_vendor_are_partial():
    report = complete_report()
    assert replace(report, kernel_support=None).incomplete
    assert replace(report, kernel_support=kernelver.KernelSupport(error="offline")).incomplete
    assert replace(report, kernel_support=kernelver.KernelSupport(
        release="6.18", mainline="6.18", stale=True)).incomplete
    assert replace(report, hsi=checks.HsiReport(ok=False)).incomplete
    assert replace(report, hardware=replace(report.hardware, matched_on="")).incomplete


def test_virtual_machine_assessment_is_partial():
    report = complete_report()
    vm_hw = replace(report.hardware, vendor=data.VM_VENDOR, matched_on="机箱类型: vm")
    assert replace(report, hardware=vm_hw).incomplete
