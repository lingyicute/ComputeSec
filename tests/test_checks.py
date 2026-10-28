# -*- coding: utf-8 -*-
"""checks.py 单元测试：比对逻辑与评分规则。

只覆盖不依赖 GTK / D-Bus / 外部命令的纯逻辑，外加两个对本机 /proc 的
宽松冒烟测试（只断言结构合法，不断言具体数值）。
"""

import json
import os

import pytest

from computesec import checks, data, hostdata


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
    # fwupd 1.9.6 起的 can-fix / can-undo 两个标记位
    assert checks._flags_to_set((1 << 14) | (1 << 15)) == {"can-fix", "can-undo"}
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
    # 两段后缀匹配
    tail2 = checks._lookup_hsi_info("com.example.IntelCet.Enabled")
    assert tail2["name"] == "控制流强制技术 (CET) 支持"
    # 去掉厂商前缀的模糊匹配
    fuzzy = checks._lookup_hsi_info("com.example.Foo.SecureBoot")
    assert fuzzy["name"] == "UEFI 安全启动"
    # 通用属性尾段（如 .Enabled / .Version）不应跨类别误匹配到 Intel Boot Guard 或 ME
    assert checks._lookup_hsi_info("org.fwupd.hsi.Unknown.Enabled") == {}
    assert checks._lookup_hsi_info("org.fwupd.hsi.Bios.Version") == {}
    # “通用词 + 编号”同样按通用处理：Version20 末段唯一，但它与 TPM 2.0 无关
    assert checks._lookup_hsi_info("com.example.Version20") == {}
    assert checks._lookup_hsi_info("com.example.Enabled2") == {}
    # 两段组合仍然可以命中（厂商前缀不同但功能段一致）
    assert checks._lookup_hsi_info("com.example.Tpm.Version20")["name"] == "TPM 2.0"
    # 完全未知返回空字典（调用方用 .get 做降级）
    assert checks._lookup_hsi_info("org.example.Nope") == {}


def test_lookup_hsi_info_upstream_ids():
    """键名必须与 fwupd 的真实 Appstream ID 完全一致（libfwupd/fwupd-security-attr-private.h）。

    拼写偏差（例如把 BootserviceVars 多写成一段 Uefi.Bootservice.Vars）会让
    直接命中失败，而尾段 "Vars" 又在通用词表里、模糊匹配也救不回来——该检测项
    将丢失全部人工整理的含义/风险/修复说明。"""
    assert checks._lookup_hsi_info("org.fwupd.hsi.Uefi.BootserviceVars")["name"] == "UEFI 引导服务变量"
    assert checks._lookup_hsi_info("org.fwupd.hsi.Bios.CapsuleUpdates")["name"] == "固件胶囊更新"
    assert checks._lookup_hsi_info("org.fwupd.hsi.Bios.RollbackProtection")["name"] == "固件回滚保护"
    # Amd / Bios 两条目共享末段 RollbackProtection：两段尾缀各自唯一可命中，
    # 单段模糊无法区分归属，必须放弃（返回 {}）而不是随手挑一条。
    assert checks._lookup_hsi_info("com.example.Amd.RollbackProtection")["name"] == "AMD 固件回滚保护"
    assert checks._lookup_hsi_info("com.example.RollbackProtection") == {}
    # fwupd main 把 db 证书检测拆成 MsUefi / Production 两项；发布版仍报的 Uefi.Db 照常命中
    assert checks._lookup_hsi_info("org.fwupd.hsi.Uefi.Db")["name"] == "UEFI 签名数据库 (db)"
    assert checks._lookup_hsi_info("org.fwupd.hsi.Uefi.Db.MsUefi")["name"] == "UEFI 签名数据库 (db)"
    assert checks._lookup_hsi_info("org.fwupd.hsi.Uefi.Db.Production")["name"] == "UEFI 签名数据库只含生产证书"
    # fwupd 1.9.4 起上报的 Downfall 微码检测
    assert checks._lookup_hsi_info("org.fwupd.hsi.IntelGds")["name"] == "Intel GDS (Downfall) 微码缓解"


def test_hsi_tail_is_generic():
    assert checks._hsi_tail_is_generic("Enabled") is True
    assert checks._hsi_tail_is_generic("Version") is True
    assert checks._hsi_tail_is_generic("Version20") is True
    assert checks._hsi_tail_is_generic("Enabled_2") is True
    # 只是"以通用词开头"或"包含通用词"的专有名词不应被误伤
    assert checks._hsi_tail_is_generic("PlatformDebugEnabled") is False
    assert checks._hsi_tail_is_generic("Dbx") is False
    assert checks._hsi_tail_is_generic("SecureBoot") is False
    assert checks._hsi_tail_is_generic("ReconstructionPcr0") is False


def test_hsi_lookup_requires_unique_match(monkeypatch):
    """尾缀出现歧义时退化为 {}，而不是随手挑一条把说明安错。"""
    monkeypatch.setattr(checks.data, "HSI_ATTRS", {
        "org.fwupd.hsi.Uefi.SecureBoot": dict(name="A"),
        "org.example.hsi.Uefi.SecureBoot": dict(name="B"),
        "org.fwupd.hsi.Tpm.Version20": dict(name="TPM 2.0"),
        "org.fwupd.hsi.Tpm.Pcr0": dict(name="Pcr0"),
    })
    # 两段尾缀有两条候选 → 不猜
    assert checks._lookup_hsi_info("com.vendor.Uefi.SecureBoot") == {}
    # 单段尾缀有两条候选 → 不猜
    assert checks._lookup_hsi_info("com.vendor.SecureBoot") == {}
    # 唯一命中仍然可用
    assert checks._lookup_hsi_info("com.vendor.Tpm.Version20")["name"] == "TPM 2.0"
    assert checks._lookup_hsi_info("com.vendor.Pcr0")["name"] == "Pcr0"


def test_hsi_attr_tails_have_no_ambiguity():
    """不变量：非通用的末段必须唯一，且两段尾缀不得重复。

    一旦有人往 data.HSI_ATTRS 里加了同尾段的条目，这条测试会立刻失败，
    提醒他要么改名，要么把该尾段加进 _HSI_GENERIC_TAILS。
    """
    from collections import Counter
    tails = Counter(k.split(".")[-1] for k in data.HSI_ATTRS)
    dup_tails = {t for t, n in tails.items() if n > 1}
    assert all(checks._hsi_tail_is_generic(t) for t in dup_tails), dup_tails
    pairs = Counter(tuple(k.split(".")[-2:]) for k in data.HSI_ATTRS)
    assert [p for p, n in pairs.items() if n > 1] == []


@pytest.mark.parametrize("key,actual,expected,want", [
    ("slab_nomerge", None, None, True),
    ("slab_nomerge", checks.MISSING, None, False),
    ("efi", "disable_early_pci_dma", "disable_early_pci_dma", True),
    ("efi", "noruntime,disable_early_pci_dma", "disable_early_pci_dma", True),
    ("efi", "noruntime", "disable_early_pci_dma", False),
    ("slab_debug", "FZ", "FZ", True),
    ("slab_debug", "FZP", "FZ", True),
    ("slab_debug", "ZF", "FZ", True),
    ("slab_debug", "F", "FZ", False),
    ("slab_debug", "OFZ", "FZ", False),  # O 会关闭部分 cache 的调试
    ("slab_debug", "fz", "FZ", True),    # 内核 parse_slub_debug_flags() 用 tolower()，大小写等价
    ("slab_debug", "fZp", "FZ", True),
    ("slab_debug", "fzo", "FZ", False),  # O 仍是削弱项
    ("slab_debug", None, "FZ", True),     # 裸 token：mm/slub.c 启用 DEBUG_DEFAULT_FLAGS（FZPU）
    ("slab_debug", "", "FZ", True),       # "slab_debug=" 等号后为空，同上
    ("intel_iommu", "on,sm_on", "on", True),
    ("intel_iommu", "sm_on,on", "on", True),
    ("intel_iommu", "on,off", "on", False),          # 后者覆盖前者
    ("intel_iommu", "off,on", "on", True),
    ("intel_iommu", "on,igfx_off", "on", False),     # 集成显卡绕过 DMA 重映射
    ("intel_iommu", "on,tboot_noforce", "on", False),
    ("intel_iommu", "sm_on", "on", False),           # 没有 on
    ("amd_iommu", "on,force_isolation", "force_isolation", True),   # on 在 AMD 上是 Unknown option，不影响
    ("amd_iommu", "force_isolation,pgtbl_v2", "force_isolation", True),
    ("amd_iommu", "force_isolation,off", "force_isolation", False),
    ("amd_iommu", "fullflush", "force_isolation", False),
    ("iommu", "force,nopanic", "force", True),
    ("iommu", "force,noforce", "force", False),
    ("iommu", "force,pt", "force", False),           # 直通，绕过地址转换
    ("iommu", "nopt,force", "force", True),          # nopt 不是 pt
    ("mitigations", "auto,nosmt", "auto,nosmt", True),
    ("mitigations", "nosmt,auto", "auto,nosmt", False),  # 内核 strcmp 精确匹配，顺序颠倒会被整体忽略
    ("mitigations", "auto", "auto,nosmt", False),        # 弱于期望（未禁用 SMT）
    ("mitigations", "auto,nosmt", "auto", True),         # 强于期望，aarch64 上合法
    ("mitigations", "off", "auto", False),
    ("l1tf", "full,force", "full,force", True),
    ("l1tf", "force,full", "full,force", False),         # 内核按固定选项列表精确匹配
    ("randomize_kstack_offset", "1", "on", True),
    ("random.trust_cpu", "0", "off", True),
    ("init_on_alloc", "on", "1", True),
    ("kpti", "1", "on", True),
    ("pti", "1", "on", False),           # x86 pti= 不使用 kstrtobool
    ("pti", "yes", "on", False),
    ("rodata", "on", "full", False),
    # 裸 token（无 =）：module_param 型布尔参数被内核置为真，early_param 型无效
    ("kvm_amd.sev", None, "1", True),
    ("module.sig_enforce", None, "1", True),
    ("bdev_allow_write_mounted", None, "0", False),   # 裸 token 等价于真，与期望值 0 相悖
    ("init_on_alloc", None, "1", False),
    ("ia32_emulation", "off", "0", True),     # arch/x86/entry/common.c: kstrtobool
    ("ia32_emulation", "n", "0", True),
    ("page_alloc.shuffle", None, "1", True),  # module_param_cb + param_set_bool
])
def test_cmdline_value_ok(key, actual, expected, want):
    assert checks._cmdline_value_ok(key, actual, expected) is want


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
    assert checks._ntfs_from_lsblk_json({"blockdevices": "invalid"}) == []


def test_ntfs_from_lsblk_json_mountpoints_list():
    j = {"blockdevices": [
        {"name": "nvme0n1p3", "fstype": "ntfs", "label": "Win", "size": "100G",
         "mountpoints": [None, "/mnt/win"]},
    ]}
    found = checks._ntfs_from_lsblk_json(j)
    assert len(found) == 1
    assert "挂载: /mnt/win" in found[0]


def test_ntfs_from_lsblk_json_recognizes_bitlocker():
    """BitLocker 卷的 FSTYPE 是 bitlocker，不是 ntfs（Windows 11 默认全盘加密）。"""
    j = {"blockdevices": [
        {"name": "nvme0n1p3", "fstype": "BitLocker", "label": "OS", "size": "400G",
         "mountpoint": None},
    ]}
    found = checks._ntfs_from_lsblk_json(j)
    assert len(found) == 1
    assert "/dev/nvme0n1p3" in found[0] and "BitLocker" in found[0]


def test_ntfs_partitions_detects_bitlocker_from_udev(monkeypatch):
    monkeypatch.setattr(checks.hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))
    monkeypatch.setattr(checks.glob, "glob", lambda _pattern: ["/run/udev/data/b259:3"])

    def fake_read(path, default=""):
        if path == "/run/udev/data/b259:3":
            return "E:ID_FS_TYPE=BitLocker\nE:DEVNAME=/dev/nvme0n1p3\nE:ID_FS_LABEL=OS\n"
        if path == "/proc/mounts":
            return ""
        return default

    monkeypatch.setattr(checks, "read", fake_read)
    found, _source = checks._ntfs_partitions()
    assert len(found) == 1 and "BitLocker" in found[0]


def test_check_ntfs_bitlocker_is_reported_as_windows_partition(monkeypatch):
    parts = ["/dev/nvme0n1p3  400G  标签: OS  挂载: -  （BitLocker 加密）"]
    monkeypatch.setattr(checks, "_ntfs_partitions", lambda: (parts, "lsblk"))
    monkeypatch.setattr(checks, "_windows_installed", lambda: [])
    res = checks.check_ntfs()
    assert res.status == "bad"
    # 数字与量词之间要有空格：不能变成「1 个NTFS / BitLocker 分区」
    assert "1 个 NTFS / BitLocker 分区" in res.summary
    assert "BitLocker 加密" in res.details[0]


def test_ntfs_partitions_checks_mounts_despite_udev_data(monkeypatch):
    """udev 中有其它文件系统记录时，也不能漏掉只出现在挂载表里的 NTFS。"""
    monkeypatch.setattr(checks.hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))
    monkeypatch.setattr(checks.glob, "glob", lambda _pattern: ["/run/udev/data/b8:1"])

    def fake_read(path, default=""):
        if path == "/run/udev/data/b8:1":
            return "E:ID_FS_TYPE=ext4\nE:DEVNAME=/dev/sda1\n"
        if path == "/proc/mounts":
            return "/dev/sdb1 /mnt/windows ntfs3 rw 0 0\n"
        return default

    monkeypatch.setattr(checks, "read", fake_read)
    found, source = checks._ntfs_partitions()
    assert len(found) == 1
    assert "/dev/sdb1" in found[0] and "/mnt/windows" in found[0]
    assert source == "udev + /proc/mounts"


def _lsblk_json(*fstypes):
    return json.dumps({"blockdevices": [
        {"name": f"sd{a}", "fstype": t, "label": None, "size": "10G", "mountpoint": None}
        for a, t in zip("abcdef", fstypes, strict=False)
    ]})


def test_ntfs_native_prefers_live_lsblk_over_snapshot(monkeypatch):
    """原生环境里快照不得压过实时的 lsblk。

    快照只在同一次开机内有效，用户之后可能刚接上（或刚格式化掉）一块 Windows 磁盘。
    反过来（快照优先）会让「未发现 NTFS」这句话停留在采快照的那一刻——这正是
    sysctl 那边已经修过的同一类错误。
    """
    snapshot = hostdata.HostData({"steps": {"lsblk": {"data": {
        "blockdevices": [{"name": "sdz1", "fstype": "ntfs", "label": "旧", "size": "1G",
                          "mountpoint": None}]}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", snapshot)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks, "run", lambda *_: (0, _lsblk_json("vfat", "ext4")))

    found, source = checks._ntfs_partitions()
    assert found == []
    assert source == "lsblk"


def test_ntfs_native_sees_disk_missing_from_snapshot(monkeypatch):
    snapshot = hostdata.HostData({"steps": {"lsblk": {"data": {
        "blockdevices": [{"name": "sda1", "fstype": "ext4", "label": None, "size": "1G",
                          "mountpoint": "/"}]}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", snapshot)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks, "run", lambda *_: (0, _lsblk_json("ext4", "ntfs")))

    found, source = checks._ntfs_partitions()
    assert [f for f in found if "/dev/sdb" in f]
    assert source == "lsblk"


def test_ntfs_flatpak_uses_supplied_snapshot(monkeypatch):
    """沙箱内的 lsblk 看不到宿主机块设备，快照仍是唯一来源。"""
    snapshot = hostdata.HostData({"steps": {"lsblk": {"data": {
        "blockdevices": [{"name": "sda2", "fstype": "ntfs", "label": "Win", "size": "1G",
                          "mountpoint": None}]}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", snapshot)
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))     # 沙箱里 lsblk 不可用

    found, source = checks._ntfs_partitions()
    assert len(found) == 1 and "/dev/sda2" in found[0]
    assert source == "lsblk（用户提供）"


def test_ntfs_native_falls_back_to_snapshot_when_lsblk_unusable(monkeypatch):
    """原生环境但 lsblk 不可用（极简容器）时，快照仍要能补上。"""
    snapshot = hostdata.HostData({"steps": {"lsblk": {"data": {
        "blockdevices": [{"name": "sda2", "fstype": "ntfs", "label": None, "size": "1G",
                          "mountpoint": None}]}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", snapshot)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))

    found, source = checks._ntfs_partitions()
    assert len(found) == 1 and "/dev/sda2" in found[0]
    assert source == "lsblk（用户提供）"


def test_vendor_kw_match_word_boundary():
    assert checks._vendor_kw_match("hp", "hp elitebook") is True
    assert checks._vendor_kw_match("hp", "touchpad controller") is False
    assert checks._vendor_kw_match("msi", "msi gaming") is True
    assert checks._vendor_kw_match("lenovo", "lenovo thinkpad") is True


def test_check_usb_avoids_false_positives(monkeypatch):
    # YubiKey Nano、内置摄像头与普通有线键盘不应被误报为 2.4G 接收器
    devs = [
        {"vid": "1050", "pid": "0407", "manufacturer": "Yubico", "product": "YubiKey 5 Nano", "cls": "00"},
        {"vid": "2c97", "pid": "0001", "manufacturer": "Ledger", "product": "Nano S", "cls": "00"},
        {"vid": "0c45", "pid": "6710", "manufacturer": "Sonix", "product": "Integrated_Webcam_HD", "cls": "ef"},
        {"vid": "04d9", "pid": "a0cd", "manufacturer": "Holtek", "product": "USB Keyboard", "cls": "00"},
    ]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    res = checks.check_usb()
    assert res.status == "good"


def test_check_usb_detects_receivers(monkeypatch):
    devs = [
        {"vid": "046d", "pid": "c52b", "manufacturer": "Logitech", "product": "USB Receiver", "cls": "00"},
        {"vid": "25a7", "pid": "fa67", "manufacturer": "Compx", "product": "2.4G Receiver", "cls": "00"},
    ]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    res = checks.check_usb()
    assert res.status == "bad"
    assert len(res.details) == 2


def _usb_dev(vid, pid, mfr, product, cls="00"):
    return {"vid": vid, "pid": pid, "manufacturer": mfr, "product": product, "cls": cls}


@pytest.mark.parametrize("dev,want", [
    # 型号里写着 dongle / receiver，但明确不是键鼠接收器：直接排除
    (("0a12", "0001", "Cambridge Silicon Radio, Ltd", "Bluetooth Dongle (HCI mode)", "e0"), None),
    (("03f0", "0624", "HP, Inc", "Bluetooth Dongle", ""), None),          # lsusb 回退时没有 bDeviceClass
    (("046d", "c709", "Logitech, Inc.", "BT Mini-Receiver (HCI mode)", ""), None),
    (("046d", "0a5b", "Logitech, Inc.", "G933 Wireless Headset Dongle", ""), None),
    (("03ee", "2501", "Mitsumi", "eHome Infrared Receiver", ""), None),
    (("0413", "6025", "Leadtek Research, Inc.", "WinFast DTV Dongle", ""), None),
    (("045e", "0291", "Microsoft Corp.", "Xbox 360 Wireless Receiver for Windows", ""), None),
    (("0e50", "0002", "TDK", "Matrixlock Dongle (HID)", ""), None),       # 软件授权狗
    (("0499", "6001", "Yamaha Corp.", "CRW2200UX Lightspeed 2 External CD-RW Drive", ""), None),
    (("1a79", "6210", "Bayer Health Care LLC", "Contour Next Link 2.4 glucometer", ""), None),
    # 泛化词 + 键鼠证据 → 确认
    (("17ef", "6032", "Lenovo", "Wireless Dongle for Keyboard and Mouse", ""), "bad"),
    (("25a7", "fa61", "Areson", "USB Dongle", ""), "bad"),               # 专做 2.4G 方案的芯片厂商
    (("046d", "c52b", "Logitech, Inc.", "Unifying Receiver", ""), "bad"),
    (("1d57", "fa20", "Xenta", "2.4GHz Wireless Receiver (Mini Keyboard & Mouse)", ""), "bad"),
    # 只有泛化词：无法确认，按「疑似」处理（不扣分）
    (("1a81", "1701", "Holtek", "Wireless dongle", ""), "suspect"),
    (("256f", "c652", "3Dconnexion", "Universal Receiver", ""), "suspect"),
    # 型号里带 Receiver、但属于乐器 / 遥控 / 条码枪 / 打印机：不传键盘输入，直接排除。
    # 漏掉这几项时，强关键词 "usb receiver" 会把它们判成「已确认」并扣到 0 分。
    (("0b0e", "0001", "Line6", "Wireless Guitar USB Receiver", ""), None),
    (("0582", "0123", "Roland", "Wireless MIDI Receiver", ""), None),
    (("1234", "0002", "Acme", "USB Receiver for Wireless Drum Kit", ""), None),
    (("0bda", "0003", "Realtek", "Remote Control USB Receiver", ""), None),
    (("05e0", "1200", "Symbol", "Wireless Barcode Scanner USB Receiver", ""), None),
    (("03f0", "0004", "HP", "Wireless Printer USB Receiver", ""), None),
    # 翻页器 / 遥控笔属于带按键的输入设备，仍在检测范围内（不能被上面的排除带走）
    (("046d", "c534", "Logitech, Inc.", "Wireless Presenter USB Receiver", ""), "bad"),
    # 罗技型号串只写「Wireless Mouse」：没有 receiver / dongle 字样就无法确认，
    # 走通用疑似逻辑——罗技不能比别家少一层提示（有线「USB Keyboard」仍无关）。
    (("046d", "c53d", "Logitech, Inc.", "Wireless Mouse", ""), "suspect"),
    (("046d", "c31c", "Logitech, Inc.", "USB Keyboard", ""), None),
    # 专做 2.4G 方案的芯片厂商出的翻页器：presenter 本身就是键鼠方面的证据
    (("248a", "8266", "Maxxter", "Wireless Presenter", ""), "suspect"),
    # 其它厂商只写「Wireless Presenter」：弱关键词，按疑似处理
    (("04d9", "1234", "Holtek", "Wireless Presenter", ""), "suspect"),
])
def test_usb_receiver_kind_keywords(dev, want):
    vid, pid, mfr, product, cls = dev
    kind = checks._usb_receiver_kind(_usb_dev(vid, pid, mfr, product, cls=cls))
    assert (kind[0] if kind else None) == want


def test_check_usb_bluetooth_dongle_alone_is_good(monkeypatch):
    """只插着蓝牙适配器时，这一项不能被扣到 0 分。"""
    devs = [_usb_dev("0a12", "0001", "Cambridge Silicon Radio, Ltd", "Bluetooth Dongle (HCI mode)", cls="e0")]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    assert checks.check_usb().status == "good"


def test_check_usb_suspect_does_not_deduct_points(monkeypatch):
    """芯片厂商的通用型号串只能判“疑似”：提醒风险，但不扣分。"""
    devs = [
        # Areson/Compx 既做 2.4G 方案，也做有线外设，型号串里没有接收器字样
        _usb_dev("25a7", "fa67", "Compx", "USB Optical Mouse"),
        # 未知厂商、只写了 Wireless：可能是蓝牙
        _usb_dev("1234", "5678", "Acme", "Wireless Mouse"),
    ]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    res = checks.check_usb()
    assert res.status == "suspect"
    assert "自行确认" in res.summary
    assert len(res.details) == 3          # 2 个设备 + 1 行“不计入评分”说明
    assert checks.HabitsReport(checks=[res]).score == 100


def test_check_usb_confirmed_wins_over_suspect(monkeypatch):
    devs = [
        _usb_dev("046d", "c52b", "Logitech", "USB Receiver"),
        _usb_dev("25a7", "fa67", "Compx", "USB Optical Mouse"),
    ]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    res = checks.check_usb()
    assert res.status == "bad"
    assert "另有 1 个疑似设备" in res.summary
    assert any(d.startswith("疑似：") for d in res.details)
    assert res.advice == checks.USB_ADVICE_CONFIRMED


def test_check_usb_ignores_wired_and_video_devices(monkeypatch):
    """有线鼠标、非 2.4G 厂商与 bDeviceClass=0x0e 的视频设备都不应产生任何提示。"""
    devs = [
        _usb_dev("046d", "c31c", "Logitech", "USB Keyboard"),
        _usb_dev("04d9", "a0cd", "Holtek", "USB Keyboard"),
        _usb_dev("1234", "0001", "Acme", "USB Optical Mouse"),
        _usb_dev("0c45", "6366", "Sonix", "USB Device", cls="0e"),
    ]
    monkeypatch.setattr(checks, "_usb_devices", lambda: (devs, "sysfs"))
    res = checks.check_usb()
    assert res.status == "good"


def test_flatpak_app_dirs_cover_xdg_and_home(monkeypatch, tmp_path):
    """三个目录都要扫：系统级、XDG 用户级、以及沙箱里唯一可见的 ~/.local/share。

    Flatpak 沙箱里的 XDG_DATA_HOME 是 ~/.var/app/<id>/data，清单只授予了
    ~/.local/share/flatpak:ro，所以不能只留 XDG 那一条。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    dirs = checks._flatpak_app_dirs()
    assert "/var/lib/flatpak/app" in dirs
    assert os.path.join(os.environ["XDG_DATA_HOME"], "flatpak", "app") in dirs
    assert str(tmp_path / ".local" / "share" / "flatpak" / "app") in dirs
    assert len(dirs) == len(set(dirs))


def test_flatpak_apps_finds_home_copy_when_xdg_points_elsewhere(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    legacy = tmp_path / ".local" / "share" / "flatpak" / "app" / "org.example.Legacy"
    legacy.mkdir(parents=True)
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))
    apps, _source = checks._flatpak_apps()
    assert "org.example.Legacy" in apps


def test_flatpak_apps_respect_xdg_data_home(monkeypatch):
    """用户安装的 Flatpak 应用在 $XDG_DATA_HOME/flatpak/app，不是写死的 ~/.local/share。

    conftest.py 已经把 XDG_DATA_HOME 指到临时目录，这里在里面造一个应用目录；
    按旧实现（expanduser("~/.local/share/...")）它是扫不到的，这一项就会少算。
    """
    os.makedirs(os.path.join(os.environ["XDG_DATA_HOME"], "flatpak", "app", "org.example.Tool"))
    monkeypatch.setattr(checks, "run", lambda *_: (None, ""))   # 不真的调用 flatpak list
    apps, source = checks._flatpak_apps()
    assert "org.example.Tool" in apps
    assert source == "目录扫描"


def test_habits_suspect_counts_as_full_score():
    def check(status):
        return checks.HabitCheck("k", "t", status, "s", [], "")
    assert checks.HabitsReport(checks=[check("suspect")]).score == 100
    assert checks.HabitsReport(checks=[check("suspect"), check("good")]).score == 100
    # 但也只是不扣分，不能把明确的 bad 洗成高分
    assert checks.HabitsReport(checks=[check("suspect"), check("bad")]).score == 50


def test_cmdline_bare_token_does_not_clobber_value(monkeypatch):
    """裸 token 不得抹掉同名带值 token 的信息，但布尔参数仍按最后一次出现判定。"""
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, default="": (
        "slab_debug=FZ slab_debug efi=disable_early_pci_dma efi "
        "init_on_alloc=1 init_on_alloc module.sig_enforce=0 module.sig_enforce"
        if p == "/proc/cmdline" else default
    ))
    by_key = {i.key: i for i in checks.get_cmdline_report().items}
    assert by_key["slab_debug"].status == "ok"
    assert by_key["slab_debug"].actual == "FZ"
    assert by_key["efi"].status == "ok"
    assert by_key["init_on_alloc"].status == "ok"
    # module_param(bool)：裸 token 等价于真，覆盖前面的 =0 才与内核一致
    assert by_key["module.sig_enforce"].status == "ok"
    assert by_key["module.sig_enforce"].actual is None


def test_cmdline_comma_params_accumulate_across_tokens(monkeypatch):
    """intel_iommu 等参数出现多次时内核依次处理，后面的 token 不会抹掉前面的选项。"""
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    cmd = {"line": ""}
    monkeypatch.setattr(checks, "read", lambda p, default="": cmd["line"] if p == "/proc/cmdline" else default)

    def status(line):
        cmd["line"] = line
        return {i.key: i for i in checks.get_cmdline_report().items}["intel_iommu"].status

    assert status("intel_iommu=on intel_iommu=sm_on") == "ok"
    assert status("intel_iommu=on intel_iommu=igfx_off") == "wrong"
    assert status("intel_iommu=off intel_iommu=on") == "ok"


def test_cmdline_aliases_and_unknown_cpu(monkeypatch):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: None)
    monkeypatch.setattr(checks, "read", lambda p, default="": (
        "slub_debug=FZP efi=noruntime efi=disable_early_pci_dma randomize_kstack_offset=1"
        if p == "/proc/cmdline" else default
    ))
    rep = checks.get_cmdline_report()
    by_key = {i.key: i for i in rep.items}
    assert by_key["slab_debug"].status == "ok"
    assert by_key["efi"].status == "ok"
    assert by_key["randomize_kstack_offset"].status == "ok"
    # CPU 厂商未知且未显式传入对应参数时，专属参数应标记为 na 而非同时要求 Intel 与 AMD
    assert by_key["intel_iommu"].status == "na"
    assert by_key["amd_iommu"].status == "na"


def test_cmdline_params_are_arch_scoped(monkeypatch):
    """按 kernel-parameters.txt 的标注：spectre_v2 / spec_store_bypass_disable /
    vdso32 是 x86 专属，ssbd 是 ARM64 专属。把它们标成双架构会让另一边的用户
    去加内核根本不认识的参数。"""
    monkeypatch.setattr(checks, "cpu_vendor", lambda: None)
    monkeypatch.setattr(checks, "read", lambda p, default="": "" if p == "/proc/cmdline" else default)

    monkeypatch.setattr(checks, "arch", lambda: "aarch64")
    by_key = {i.key: i for i in checks.get_cmdline_report().items}
    for x86_only in ("spectre_v2", "spec_store_bypass_disable", "vdso32"):
        assert x86_only not in by_key, x86_only
    assert "ssbd" in by_key

    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    by_key = {i.key: i for i in checks.get_cmdline_report().items}
    assert "ssbd" not in by_key
    assert "rodata" not in by_key
    for x86_only in ("spectre_v2", "spec_store_bypass_disable", "vdso32"):
        assert x86_only in by_key, x86_only


@pytest.mark.parametrize("release, cmdline, expected, status", [
    # 6.17 及更早：on 只保护内核映像（rodata_full = false），完整保护是 full
    ("6.12.48-1-arm64", "rodata=full", "full", "ok"),
    ("6.12.48-1-arm64", "rodata=on", "full", "wrong"),
    ("6.17.9", "", "full", "missing"),
    # 6.18 起：on 即完整保护，full 不再识别（被忽略并打印警告）
    ("6.18.0-rc3", "rodata=on", "on", "ok"),
    ("6.18.2-200.fc43.aarch64", "rodata=full", "on", "wrong"),
    ("7.3.1", "rodata=on", "on", "ok"),
    # 解析不出版本时退回 full：它在任何内核上都不会降低保护
    ("", "rodata=full", "full", "ok"),
    ("weird-kernel", "rodata=on", "full", "wrong"),
])
def test_cmdline_rodata_expected_follows_running_kernel(monkeypatch, release, cmdline, expected, status):
    monkeypatch.setattr(checks, "arch", lambda: "aarch64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: None)
    monkeypatch.setattr(checks.platform, "release", lambda: release)
    monkeypatch.setattr(checks, "read", lambda p, default="": cmdline if p == "/proc/cmdline" else default)
    item = {i.key: i for i in checks.get_cmdline_report().items}["rodata"]
    assert item.expected == expected
    assert item.status == status


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
    # 无法评估时必须是 None（之前返回 0，UI 会显示成"评估过且很差"）
    assert checks.HsiReport(ok=False).score is None
    assert checks.HsiReport(ok=True, items=[]).score is None


def test_hsi_missing_data_is_undetermined_not_failed():
    """fwupd 的 missing-data 表示"无法判定"，不能算作未通过、更不能进待办。"""
    items = [
        checks.HsiItem("a", "A", "", 3, "unknown", {"missing-data"}, "", {"fix": "x", "kind": "bios"}, False, False),
        checks.HsiItem("b", "B", "", 3, "unknown", set(), "", {"fix": "y", "kind": "bios"}, False, False),
        checks.HsiItem("c", "C", "", 3, "enabled", {"success"}, "", {}, True, False),
    ]
    r = checks.HsiReport(ok=True, items=items)
    assert [i.id for i in r.undetermined] == ["a"]
    assert [i.id for i in r.failed] == ["b"]
    assert [i.id for i in r.fixable] == ["b"]        # A 不能被列成"您可以修复"
    assert [i.id for i in r.scored] == ["b", "c"]
    assert r.score == 50                              # 1/2，而不是 1/3


def test_hsi_all_undetermined_has_no_score():
    items = [checks.HsiItem("a", "A", "", 3, "unknown", {"missing-data"}, "", {}, False, False)]
    r = checks.HsiReport(ok=True, items=items)
    assert r.score is None
    assert r.failed == [] and r.fixable == []


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
    # 没有可评估项（例如 riscv64 上所有参数都是 na）→ None，而不是 0 分
    assert checks.CmdlineReport("x86_64", None, "", []).score is None
    only_na = checks.CmdlineReport("riscv64", None, "", [checks.ParamItem("a", "1", checks.MISSING, "na", "")])
    assert only_na.score is None


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
    assert checks.SysctlReport("x86_64", groups=[]).score is None
    # 全部被排除（未知/不适用/未验证）时同样没有分数
    only_excluded = checks.SysctlReport("x86_64", groups=[("g", [
        item("unk.1", "unknown"), item("na.1", "na"), item("unv.1", "unverified")])])
    assert only_excluded.score is None
    assert [i.key for i in only_excluded.scored] == []


def test_sysctl_item_actual_text():
    assert checks.SysctlItem("k", "1", "eq", {}, "unknown", "").actual_text.startswith("（无法读取")
    assert checks.SysctlItem("k", "1", "eq", {}, "missing", "").actual_text == "（内核不支持）"
    assert checks.SysctlItem("k", "1", "eq", {"k": "0"}, "missing", "").actual_text == "0"
    multi = checks.SysctlItem("k", "0", "eq",
                              {"net.ipv4.conf.all.x": "0", "net.ipv4.conf.default.x": "1"},
                              "missing", "").actual_text
    assert "all=0" in multi and "default=1" in multi
    # 混合了「读不出来」（None）时也要说人话，不能把 Python 的 None 印到界面上
    mixed = checks.SysctlItem("k", "0", "eq",
                             {"net.ipv4.conf.eth0.x": None, "net.ipv4.conf.lo.x": "1"},
                             "missing", "").actual_text
    assert "eth0=（无法读取）" in mixed and "lo=1" in mixed and "None" not in mixed
    # 只有一个值、而且是「读不出来」时，同样不能与「内核不支持」混为一谈
    one = checks.SysctlItem("k", "0", "eq", {"net.ipv6.conf.eth0.x": None}, "missing", "").actual_text
    assert one == "（无法读取）"


def test_sysctl_user_snapshot_does_not_hide_new_native_entries(monkeypatch):
    key = "net.ipv4.conf.*.accept_redirects"
    supplied = {
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
    }
    current = dict(supplied, **{"net.ipv4.conf.eth0.accept_redirects": "1"})
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": supplied}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [
        ("test", [dict(key=key, value="0", desc="test")]),
    ])
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _key: (current, False))

    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "missing"
    assert item.actual == current


def test_sysctl_flatpak_snapshot_gap_is_unverified(monkeypatch):
    """Flatpak 内快照没有覆盖的条目不能被沙箱 /proc/sys 顶替（M2）。"""
    ok_key, gap_key = "net.ipv4.tcp_syncookies", "kernel.sysrq"
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": {ok_key: "1"}}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [
        ("t", [dict(key=ok_key, value="1", desc="d"), dict(key=gap_key, value="0", desc="d")]),
    ])
    # 沙箱里读到的是 kernel.sysrq=1（未加固）。修复前它会被当成宿主机读数判为 missing。
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _k: ({ok_key: "1", gap_key: "1"}, False))

    rep = checks.get_sysctl_report()
    by_key = {i.key: i for i in rep.all_items}
    assert by_key[ok_key].status == "ok"
    assert by_key[ok_key].source == "用户提供"
    assert by_key[gap_key].status == "unverified"
    assert by_key[gap_key].actual == {}
    assert by_key[gap_key].source == "快照缺失"
    assert by_key[gap_key].actual_text == "（您提供的快照中没有这一项）"
    assert [i.key for i in rep.unverified] == [gap_key]
    assert rep.unknown == [] and rep.missing == []
    assert rep.score == 100        # unverified 不参与评分


def test_sysctl_flatpak_root_only_key_missing_from_snapshot_is_unknown(monkeypatch):
    """漏了 sudo 时 root-only 条目的报错被 2>/dev/null 吞掉，快照里就没有它们。

    沙箱里读这一项是「权限不足」，应归为 unknown，界面才会提示「可能没有加 sudo」，
    而不是笼统的「快照缺失」。"""
    ok_key, root_key = "kernel.kptr_restrict", "vm.mmap_rnd_bits"
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": {ok_key: "2"}}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: True)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [
        ("t", [dict(key=ok_key, value="2", desc="d"), dict(key=root_key, value="32", desc="d")]),
    ])
    monkeypatch.setattr(checks, "_sysctl_from_proc",
                        lambda k: ({}, True) if k == root_key else ({k: "2"}, False))
    by_key = {i.key: i for i in checks.get_sysctl_report().all_items}
    assert by_key[root_key].status == "unknown"
    assert by_key[ok_key].status == "ok"


def test_flatpak_shared_subsystems(monkeypatch):
    monkeypatch.setattr(checks, "read", lambda path, default="": (
        "[Application]\nname=x\n\n[Context]\nshared=network;ipc;\nsockets=wayland;\n"
        if path == "/.flatpak-info" else default))
    assert checks._flatpak_shared_subsystems() == {"network", "ipc"}
    assert checks._flatpak_shares_network() is True
    # 没有 network 时不能采信沙箱内的 net.*
    monkeypatch.setattr(checks, "read", lambda path, default="": (
        "[Context]\nshared=ipc;\n" if path == "/.flatpak-info" else default))
    assert checks._flatpak_shares_network() is False
    # 文件缺失 / 没有 shared 行：按“什么都没共享”处理
    monkeypatch.setattr(checks, "read", lambda path, default="": default)
    assert checks._flatpak_shared_subsystems() == set()
    assert checks._flatpak_shares_network() is False


def test_sysctl_flatpak_without_host_network_marks_net_unverified(monkeypatch):
    """Flatpak 未共享宿主网络时，net.* 的沙箱读数必须被丢弃（新 netns 的默认值与宿主相反）。"""
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: False)
    monkeypatch.setattr(checks.hostdata, "CURRENT", checks.hostdata.HostData())
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda key: (
        ({key.replace("*", "all"): "1"} if not key.startswith("net.") else {"net.x": "0"}), False))

    r = checks.get_sysctl_report()
    net = [i for i in r.all_items if i.key.startswith("net.")]
    other = [i for i in r.all_items if not i.key.startswith("net.")]
    assert net and all(i.status == "unverified" for i in net)
    assert all(i.source == "沙箱网络隔离" for i in net)
    assert not any(i.status == "unverified" for i in other)
    # 未参与评分：unverified 不算进分母，拿不到分也不会拉低分数
    assert all(i.status not in ("missing", "ok") for i in net)


def _fake_sysctl_reader(value_for_key):
    """伪造 _sysctl_from_proc：按 sysctl 表里的期望值返回"已加固"的读数。"""
    expected = {e["key"]: e["value"] for _, entries in data.SYSCTL_GROUPS for e in entries}
    return lambda key: ({key.replace("*", "all"): str(expected.get(key, value_for_key))}, False)


def test_sysctl_flatpak_with_shared_network_trusts_sandbox(monkeypatch):
    """共享了宿主网络（--share=network）时，沙箱内的 /proc/sys/net 就是宿主机视图。"""
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: True)
    monkeypatch.setattr(checks.hostdata, "CURRENT", checks.hostdata.HostData())
    monkeypatch.setattr(checks, "_sysctl_from_proc", _fake_sysctl_reader("1"))

    r = checks.get_sysctl_report()
    net = [i for i in r.all_items if i.key.startswith("net.")]
    assert net and all(i.status == "ok" for i in net)
    assert all(i.source == "proc" for i in net)


def test_sysctl_flatpak_net_uses_user_snapshot(monkeypatch):
    """用户提供的宿主机快照仍应覆盖被隔离的 net.*。"""
    hd = checks.hostdata.HostData()
    hd.payload = {"steps": {"sysctl": {"data": {"values": {
        "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.tcp_syncookies": "1"}}}}}
    monkeypatch.setattr(checks, "IN_FLATPAK", True)
    monkeypatch.setattr(checks, "_flatpak_shares_network", lambda: False)
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda key: ({"net.x": "0"}, False))

    r = checks.get_sysctl_report()
    item = next(i for i in r.all_items if i.key == "net.ipv4.tcp_syncookies")
    assert item.status == "ok"
    assert item.source == "用户提供"
    # 快照里没有的 net.* 依然标 unverified，不会退回沙箱读数
    other = next(i for i in r.all_items if i.key == "net.core.bpf_jit_harden")
    assert other.status == "unverified"


def test_sysctl_native_prefers_live_values(monkeypatch):
    """原生环境下 /proc 才是此刻的真实状态，快照不得覆盖同名键。

    反过来（快照优先）会错两次：用户加固后（快照是加固前采的）被判成未加固；
    用户把 sysctl 撤销后（快照里还是加固后的值）却被判成"已加固"——后者正是
    本程序最不该犯的错。快照的存活期是整次开机，本程序本身又在提醒用户
    "长时间不重启"，两者叠在一起时快照可能已经很旧了。
    """
    key = "net.ipv4.conf.*.accept_redirects"
    hd = hostdata.HostData({"steps": {"sysctl": {"data": {"values": {
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
    }}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [("t", [dict(key=key, value="0", desc="d")])])
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _k: ({
        "net.ipv4.conf.all.accept_redirects": "1",
        "net.ipv4.conf.default.accept_redirects": "1",
        "net.ipv4.conf.eth0.accept_redirects": "1",
    }, False))

    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "missing"
    assert item.actual["net.ipv4.conf.all.accept_redirects"] == "1"      # 实时值，不是快照里的 0
    assert item.actual["net.ipv4.conf.eth0.accept_redirects"] == "1"     # 快照里没有的接口照常保留
    assert item.source == "proc"                                        # 没有用到快照


def test_sysctl_native_snapshot_fills_unreadable_keys(monkeypatch):
    """读不到（EACCES）的键仍要用快照补上，并标注这份快照有多旧。"""
    key = "vm.mmap_rnd_bits"
    hd = hostdata.HostData({"collected_at": 1, "steps": {"sysctl": {"data": {"values": {key: "32"}}}}})
    monkeypatch.setattr(checks.hostdata, "CURRENT", hd)
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks.data, "SYSCTL_GROUPS", [("t", [dict(key=key, value="32", desc="d")])])
    monkeypatch.setattr(checks, "_sysctl_from_proc", lambda _k: ({}, True))

    item = checks.get_sysctl_report().all_items[0]
    assert item.status == "ok"
    assert item.actual == {key: "32"}
    assert item.source.startswith("用户提供")


def test_habits_report_score():
    def check(status):
        return checks.HabitCheck("k", "t", status, "s", [], "")
    assert checks.HabitsReport(checks=[check("good"), check("bad")]).score == 50
    assert checks.HabitsReport(checks=[check("warn")]).score == 40
    assert checks.HabitsReport(checks=[]).score is None


def test_habits_unknown_is_not_scored():
    """读不到（unknown）不计分：用户没法通过任何操作改善它，扣分等于凭空扣。

    其它三个板块遇到"无法评估"都是不计分并显示「—」，这里跟随同一口径。
    """
    def check(status):
        return checks.HabitCheck("k", "t", status, "s", [], "")
    # 只有 unknown：没有可评估项 → None（界面显示「—」），而不是 60 分
    assert checks.HabitsReport(checks=[check("unknown")]).score is None
    # unknown 被跳过，剩下的按原口径平均
    assert checks.HabitsReport(checks=[check("unknown"), check("good")]).score == 100
    assert checks.HabitsReport(checks=[check("unknown"), check("good"), check("bad")]).score == 50
    # suspect（疑似）仍然满分：疑似不是证据
    assert checks.HabitsReport(checks=[check("suspect"), check("bad")]).score == 50


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


@pytest.mark.parametrize("values,want", [
    ([80, 79], 80),                 # 79.5 向上，而不是截断成 79
    ([81, 80], 81),                 # 80.5 向上（round() 的银行家舍入会给出 80）
    ([100, 99, 100, 98], 99),       # 99.25
    ([0, 1], 1),                    # 0.5 向上
    ([100], 100),
    ([None, 90], 90),
    ([None, None], None),
    ([], None),
])
def test_mean_rounds_half_up(values, want):
    assert checks.Report._mean(values) == want


def test_report_overall_skips_unavailable_hsi():
    # HSI 拿不到时不再用 50 分顶替，而是把 HSI 从分母里去掉重新归一
    r = _report(hsi_ok=False)
    assert r.overall == 75                # (75 + 100 + 50) // 3
    assert r.hsi.score is None


def test_report_overall_none_when_everything_unavailable():
    r = checks.Report(
        hsi=checks.HsiReport(ok=False),
        cmdline=checks.CmdlineReport("riscv64", None, "", []),
        sysctl=checks.SysctlReport("riscv64", groups=[("g", [
            checks.SysctlItem("na.1", "1", "eq", {}, "na", "")])]),
        hardware=checks.HardwareReport("", "", "", "", "", "", {"rating": "good"}, ""),
        habits=checks.HabitsReport(checks=[]),
        arch="riscv64", cpu="test", os_name="TestOS", kernel="1.0", in_flatpak=False)
    assert r.kernel_score is None
    assert r.overall == 100               # 只剩硬件品牌可评估


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
    assert r.score is None or 0 <= r.score <= 100
    assert r.arch
    assert all(i.status in ("ok", "missing", "wrong", "na") for i in r.items)


def test_get_sysctl_report_smoke():
    r = checks.get_sysctl_report()
    assert [t for t, _ in r.groups] == [t for t, _ in data.SYSCTL_GROUPS]
    assert r.score is None or 0 <= r.score <= 100
    assert all(i.status in ("ok", "missing", "na", "unknown", "unverified") for i in r.all_items)
