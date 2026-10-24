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


def test_parse_sysctl_eio_lines_are_not_denied():
    # procps 3.3.12 及更早在 stable_secret 未配置时，sudo sysctl -a 也会打印读错行
    # （fgets 失败分支用 xwarnx，不带错误原因）；这不是权限问题，
    # 不应触发「请用 sudo 重新执行」的提示。zh_CN 的两代译文都要认。
    parsed, err = hostdata.parse_sysctl(_sysctl_text([
        'sysctl: reading key "net.ipv6.conf.all.stable_secret"',
        'sysctl: reading key "net.ipv6.conf.default.stable_secret"',
        "sysctl: 读取net.ipv6.conf.enp0s3.stable_secret 时出错",     # procps ≤ 4.0.4 的 zh_CN
        'sysctl: 读取键 "net.ipv6.conf.enp0s3.stable_secret"',      # procps ≥ 4.0.5 的 zh_CN
    ]))
    assert err == ""
    assert parsed["meta"] == {}


def test_parse_sysctl_counts_only_permission_denied():
    # 读错行与权限拒绝行混在一起时只计后者；zh_CN 的权限拒绝消息同样要计入
    # （旧解析按 sysctl: 前缀识别，修读错行时不能让中文提示退化丢失）。
    parsed, err = hostdata.parse_sysctl(_sysctl_text([
        'sysctl: reading key "net.ipv6.conf.all.stable_secret"',
        "sysctl: permission denied on key 'vm.mmap_rnd_bits'",
        'sysctl: 对键 "vm.mmap_rnd_compat_bits" 的权限不够',              # procps ≥ 4.0.5 的 zh_CN
        "sysctl: 无法格式化设备 net.ipv4.tcp_fastopen_key，权限被拒绝。",  # procps ≤ 4.0.4 的 zh_CN（原译如此）
    ]))
    assert err == ""
    assert parsed["meta"]["denied"] == 3


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


def test_parse_lsblk_handles_braces_in_shell_prompt():
    text = "{user@testbox ~} $ lsblk -J\n" + json.dumps(_lsblk_obj()) + "\n{0} [user@testbox ~]$\n"
    parsed, err = hostdata.parse_lsblk(text)
    assert err == ""
    assert parsed["blockdevices"][0]["name"] == "sda"


@pytest.mark.parametrize("prefix", [
    '{"foo": 1}',
    '{"blockdevices": "not-a-list"}',
])
def test_parse_lsblk_skips_other_json_objects(prefix):
    text = prefix + " $ lsblk -J\n" + json.dumps(_lsblk_obj())
    parsed, err = hostdata.parse_lsblk(text)
    assert err == ""
    assert parsed["blockdevices"][0]["name"] == "sda"


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
    parsed2, err2 = hostdata.parse_lsblk(json.dumps({"blockdevices": "not-a-list"}))
    assert parsed2 is None
    assert "blockdevices" in err2


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


def _write_cache(tmp_path, payload):
    d = tmp_path / "computesec"
    d.mkdir(exist_ok=True)
    (d / hostdata.CACHE_NAME).write_text(payload)
    return d


def test_load_rejects_wrong_structure(tmp_path, monkeypatch):
    """结构不对的缓存必须当作不存在，而不是让访问器抛 AttributeError。"""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    for payload in ('{"steps": ["oops"]}',            # steps 是列表
                    '{"steps": {"sysctl": "oops"}}',   # 单个 step 不是字典
                    '["oops"]'):                       # 顶层都不是字典
        _write_cache(tmp_path, payload)
        hd = hostdata.HostData.load()
        assert hd.payload == {}
        assert hd.any_data is False
        assert hd.sysctl_values == {}
        assert hd.get("sysctl") is None


def test_get_is_defensive_against_bad_payload():
    """即便 payload 是手工构造的坏结构，访问器也只能返回空值，不能抛异常。"""
    for bad in ({"steps": ["oops"]}, {"steps": None}, {"steps": {"sysctl": ["oops"]}}, {}):
        hd = hostdata.HostData(bad)
        assert hd.get("sysctl") is None
        assert hd.sysctl_values == {}
        assert hd.any_data is False


@pytest.mark.parametrize("payload", [
    {"steps": {"sysctl": {"data": ["oops"]}}},                    # data 不是字典
    {"steps": {"sysctl": {"data": {"values": ["a"]}}}},           # values 不是字典
    {"steps": {"sysctl": {"data": {"values": {"k": 1}}}}},        # 值不是字符串
    {"steps": {"lsblk": {"data": ["x"]}}},                        # lsblk 不是字典
    {"steps": {"lsblk": {"data": {"blockdevices": "x"}}}},        # blockdevices 不是列表
    {"collected_at": "bad", "steps": {}},                         # 时间戳不是数字
    {"collected_at": True, "steps": {}},
    {"boot_id": 42, "steps": {}},
])
def test_load_rejects_bad_nested_structure(tmp_path, monkeypatch, payload):
    """深一层的坏结构同样当作没有缓存：此前会让 sysctl 板块整块消失，或让内核页渲染失败。"""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _write_cache(tmp_path, json.dumps(payload))
    hd = hostdata.HostData.load()
    assert hd.payload == {}


def test_accessors_survive_bad_nested_payload():
    hd = hostdata.HostData({"collected_at": "bad", "boot_id": 42,
                            "steps": {"sysctl": {"data": ["oops"]}, "lsblk": {"data": ["x"]}}})
    assert hd.sysctl_values == {}
    assert hd.sysctl_lookup("kernel.kptr_restrict") == {}
    assert hd.lsblk is None
    assert hd.age_text == ""
    assert hd.collected_boot_id == ""


def test_load_keeps_valid_payload_with_both_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    good = {"collected_at": 1000, "boot_id": "b", "skipped": False, "steps": {
        "sysctl": {"data": {"values": {"kernel.ostype": "Linux"}, "meta": {}}, "at": 1000},
        "lsblk": {"data": {"blockdevices": []}, "at": 1000}}}
    _write_cache(tmp_path, json.dumps(good))
    assert hostdata.HostData.load().payload == good


def test_cache_file_and_dir_permissions(tmp_path, monkeypatch):
    """缓存里是整份 sudo sysctl -a 输出，只能由当前用户读写。"""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    hd = hostdata.HostData()
    hd.set("sysctl", {"values": {"kernel.ostype": "Linux"}})
    hd.save()
    cache = tmp_path / "computesec" / hostdata.CACHE_NAME
    assert cache.exists()
    assert (cache.stat().st_mode & 0o777) == 0o600
    assert ((tmp_path / "computesec").stat().st_mode & 0o777) == 0o700


def test_data_dir_tightens_existing_permissions(tmp_path, monkeypatch):
    d = tmp_path / "xdg" / "computesec"
    d.mkdir(parents=True)
    d.chmod(0o755)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert hostdata._data_dir() == str(d)
    assert (d.stat().st_mode & 0o777) == 0o700


def test_valid_step_index():
    n = len(hostdata.STEPS)
    assert hostdata.valid_step_index(0) is True
    assert hostdata.valid_step_index(n - 1) is True
    for bad in (-1, n, n + 1, 10 ** 6, None, "0", 1.0):
        assert hostdata.valid_step_index(bad) is False


def test_data_dir_ignores_relative_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", "relative/dir")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert hostdata._data_dir() == str(tmp_path / ".local" / "share" / "computesec")


def test_display_dir_shortens_home(monkeypatch, tmp_path):
    """界面提示要用真实的数据目录，不能写死 ~/.local/share。"""
    from computesec import xdg

    # 默认位置：家目录缩成 ~，读起来和写死的文案一样，但它是算出来的
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert xdg.display_dir() == "~/.local/share/computesec"
    assert not (tmp_path / ".local").exists()          # 只算路径，不建目录

    # 自定义 XDG_DATA_HOME：提示必须跟着走（仍在家目录下，照样缩写）
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert xdg.display_dir() == "~/xdg/computesec"

    # 不在家目录下时原样返回，不做无意义的前缀替换
    monkeypatch.setenv("XDG_DATA_HOME", "/opt/data")
    assert xdg.display_dir() == "/opt/data/computesec"


def test_data_dir_respects_absolute_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert hostdata._data_dir() == str(tmp_path / "xdg" / "computesec")


def test_readonly_paths_do_not_create_data_dir(tmp_path, monkeypatch):
    """只读查询与清理不应在磁盘上留下空目录。"""
    from computesec import kernelver
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    hostdata.HostData.load()
    hostdata.HostData.clear()
    kernelver.load_cache()
    assert not (tmp_path / "xdg" / "computesec").exists()


def test_save_tightens_leftover_tmp_file(tmp_path, monkeypatch):
    """上次写到一半留下的 .tmp 若是 0644，写入时也要收紧成 0600。"""
    import os
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    d = tmp_path / "computesec"
    d.mkdir(mode=0o700)
    leftover = d / (hostdata.CACHE_NAME + ".tmp")
    leftover.write_text("{}")
    os.chmod(leftover, 0o644)
    hd = hostdata.HostData()
    hd.set("sysctl", {"values": {"kernel.ostype": "Linux"}})
    hd.save()
    assert (os.stat(d / hostdata.CACHE_NAME).st_mode & 0o777) == 0o600
