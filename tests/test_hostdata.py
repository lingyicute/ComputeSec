# -*- coding: utf-8 -*-
"""hostdata.py 单元测试：剪贴板解析器与缓存逻辑。"""

import json
import time

import pytest

from computesec import hostdata


def _sysctl_text(extra_lines=(), anchors=True):
    """构造一份“看起来像 sudo sysctl -a 输出”的文本。"""
    lines = []
    if anchors:
        lines += [
            "kernel.ostype = Linux",
            "kernel.osrelease = 6.9.1-test",
            "kernel.version = #1 SMP Test",
            "kernel.hostname = testbox",
            "fs.file-max = 9223372036854775807",
            "net.ipv4.ip_forward = 0",
            "vm.max_map_count = 1048576",
        ]
    for i in range(30):
        lines.append(f"kernel.test_param_{i} = {i}")
    lines.extend(extra_lines)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# parse_sysctl
# ---------------------------------------------------------------------------

def test_parse_sysctl_ok():
    parsed, err = hostdata.parse_sysctl(_sysctl_text())
    assert err == ""
    assert parsed["values"]["kernel.ostype"] == "Linux"
    assert parsed["values"]["vm.max_map_count"] == "1048576"
    assert len(parsed["values"]) >= 30
    assert parsed["meta"] == {}


def test_parse_sysctl_collapses_whitespace():
    parsed, _ = hostdata.parse_sysctl(_sysctl_text(["kernel.spaces = a   b\tc"]))
    assert parsed["values"]["kernel.spaces"] == "a b c"


def test_parse_sysctl_counts_permission_denied():
    text = _sysctl_text([
        "sysctl: permission denied on key 'vm.mmap_rnd_bits'",
        "sysctl: permission denied on key 'vm.mmap_rnd_compat_bits'",
    ])
    parsed, err = hostdata.parse_sysctl(text)
    assert err == ""
    assert parsed["meta"]["denied"] == 2


@pytest.mark.parametrize("text", ["", "   ", "\n\n"])
def test_parse_sysctl_empty_clipboard(text):
    parsed, err = hostdata.parse_sysctl(text)
    assert parsed is None
    assert "空" in err


def test_parse_sysctl_garbage():
    parsed, err = hostdata.parse_sysctl("hello world\njust some random text\n")
    assert parsed is None
    assert "sysctl" in err


def test_parse_sysctl_too_few_entries():
    parsed, err = hostdata.parse_sysctl("kernel.ostype = Linux\nkernel.hostname = x\n")
    assert parsed is None
    assert "条目" in err


def test_parse_sysctl_without_anchors_rejected():
    parsed, err = hostdata.parse_sysctl(_sysctl_text(anchors=False))
    assert parsed is None
    assert "sysctl" in err


def test_parse_sysctl_skips_shell_prompt_contamination():
    parsed, err = hostdata.parse_sysctl(_sysctl_text([
        "[user@testbox ~]$ sudo sysctl -a 2>/dev/null",
        "user@testbox$  kernel.evil   =   1",
        "impossible key with spaces = 1",
        "notakey = 1",
    ]))
    assert err == ""
    assert "kernel.evil" not in parsed["values"]
    assert "notakey" not in parsed["values"]


# ---------------------------------------------------------------------------
# parse_lsblk
# ---------------------------------------------------------------------------

def _lsblk_obj():
    return {"blockdevices": [
        {"name": "sda", "fstype": None, "label": None, "size": "500G",
         "mountpoint": None, "children": [
             {"name": "sda1", "fstype": "vfat", "label": "EFI",
              "size": "512M", "mountpoint": "/boot/efi"},
             {"name": "sda2", "fstype": "btrfs", "label": "fedora",
              "size": "499G", "mountpoint": "/"},
         ]},
    ]}


def test_parse_lsblk_ok():
    parsed, err = hostdata.parse_lsblk(json.dumps(_lsblk_obj()))
    assert err == ""
    assert parsed["blockdevices"][0]["name"] == "sda"


def test_parse_lsblk_ignores_prompt_noise_around_json():
    text = "[user@testbox ~]$ lsblk -J\n" + json.dumps(_lsblk_obj()) + "\n[user@testbox ~]$ \n"
    parsed, err = hostdata.parse_lsblk(text)
    assert err == ""
    assert "blockdevices" in parsed


@pytest.mark.parametrize("text", ["", "   "])
def test_parse_lsblk_empty(text):
    parsed, err = hostdata.parse_lsblk(text)
    assert parsed is None
    assert "空" in err


def test_parse_lsblk_invalid_json():
    parsed, err = hostdata.parse_lsblk("{this is not json]")
    assert parsed is None
    assert "JSON" in err


def test_parse_lsblk_wrong_json():
    parsed, err = hostdata.parse_lsblk(json.dumps({"foo": [1, 2, 3]}))
    assert parsed is None
    assert "blockdevices" in err


# ---------------------------------------------------------------------------
# HostData 存取
# ---------------------------------------------------------------------------

def test_set_has_get():
    hd = hostdata.HostData()
    assert not hd.has("sysctl")
    assert not hd.any_data
    hd.set("sysctl", {"values": {"a.b": "1"}, "meta": {}})
    assert hd.has("sysctl")
    assert hd.any_data
    assert hd.sysctl_values == {"a.b": "1"}
    assert hd.lsblk is None


def test_sysctl_lookup_exact_and_wildcard():
    hd = hostdata.HostData()
    hd.set("sysctl", {"values": {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "kernel.yama.ptrace_scope": "1",
    }, "meta": {}})
    assert hd.sysctl_lookup("kernel.yama.ptrace_scope") == {"kernel.yama.ptrace_scope": "1"}
    assert hd.sysctl_lookup("kernel.missing") == {}
    assert hd.sysctl_lookup("net.ipv4.conf.*.rp_filter") == {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
    }


def test_sysctl_lookup_without_data():
    assert hostdata.HostData().sysctl_lookup("kernel.*") == {}


def test_fresh_requires_same_boot_id(monkeypatch):
    monkeypatch.setattr(hostdata, "boot_id", lambda: "boot-1")
    assert hostdata.HostData().fresh is False
    assert hostdata.HostData({"boot_id": "boot-1"}).fresh is True
    assert hostdata.HostData({"boot_id": "boot-2"}).fresh is False


@pytest.mark.parametrize("ago,expected", [
    (0, "刚刚"),
    (30, "刚刚"),
    (300, "5 分钟前"),
    (7200, "2 小时前"),
    (90000, "1 天前"),
])
def test_age_text(ago, expected):
    hd = hostdata.HostData({"collected_at": int(time.time()) - ago})
    assert hd.age_text == expected


def test_age_text_empty():
    assert hostdata.HostData().age_text == ""


def test_mark_done_records_boot_id(monkeypatch):
    monkeypatch.setattr(hostdata, "boot_id", lambda: "boot-9")
    hd = hostdata.HostData()
    hd.mark_done()
    assert hd.collected_boot_id == "boot-9"
    assert hd.collected_at > 0
    assert hd.skipped is False


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(hostdata, "boot_id", lambda: "boot-1")
    hd = hostdata.HostData()
    hd.set("sysctl", {"values": {"a.b": "1"}, "meta": {}})
    hd.mark_done()
    hd.save()

    loaded = hostdata.HostData.load()
    assert loaded.has("sysctl")
    assert loaded.sysctl_values == {"a.b": "1"}
    assert loaded.fresh is True


def test_load_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert hostdata.HostData.load().payload == {}


def test_load_corrupt_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    d = tmp_path / "computesec"
    d.mkdir()
    (d / hostdata.CACHE_NAME).write_text("{corrupt json")
    assert hostdata.HostData.load().payload == {}
