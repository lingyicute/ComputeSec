from computesec import checks, data


def test_cpu_support_describes_hsi_coverage_not_vendor_end_of_life():
    info = data.HSI_ATTRS["org.fwupd.hsi.SupportedCpu"]
    assert info["name"] == "CPU 平台检测支持"
    assert "fwupd" in info["meaning"] and "HSI" in info["meaning"]
    assert "不判断" in info["meaning"]
    assert "更换" not in info["fix"]
    item = checks._normalize_attrs([{"AppstreamId": "org.fwupd.hsi.SupportedCpu",
                                    "HsiResult": "unknown", "Flags": []}])[0]
    assert item.info is info and not item.passed
