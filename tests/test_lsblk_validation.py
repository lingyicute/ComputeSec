"""Reject disk data that cannot establish filesystem types."""

import json

import pytest

from computesec import checks, hostdata

VALID = {"blockdevices": [{"name": "sda1", "fstype": "ntfs"}]}
INVALID = [
    {"blockdevices": [None]},
    {"blockdevices": [{}]},
    {"blockdevices": [{"name": "sda1"}]},
    {"blockdevices": [{"name": 42, "fstype": "ntfs"}]},
    {"blockdevices": [{"name": "sda1", "fstype": 42}]},
    {"blockdevices": [{"name": "sda1", "fstype": None, "children": "bad"}]},
    {"blockdevices": [{"name": "sda1", "fstype": None, "children": [False]}]},
    {"blockdevices": [{"name": "sda1", "fstype": "ntfs", "mountpoints": 42}]},
]


@pytest.mark.parametrize("payload", INVALID)
def test_parser_rejects_incomplete_or_malformed_nodes(payload):
    parsed, error = hostdata.parse_lsblk(json.dumps(payload))
    assert parsed is None
    assert error


@pytest.mark.parametrize("payload", INVALID)
def test_cache_rejects_malformed_disk_data(payload, tmp_path, monkeypatch):
    monkeypatch.setattr(hostdata, "_data_dir", lambda create=True: str(tmp_path))
    (tmp_path / hostdata.CACHE_NAME).write_text(json.dumps({
        "steps": {"lsblk": {"data": payload}},
    }))
    assert hostdata.HostData.load().payload == {}


def test_parser_can_skip_malformed_prefix_object():
    text = json.dumps(INVALID[1]) + "\n" + json.dumps(VALID)
    parsed, error = hostdata.parse_lsblk(text)
    assert parsed == VALID
    assert not error


@pytest.mark.parametrize("rc,payload", [(0, {}), (0, INVALID[4]), (1, {"blockdevices": []})])
def test_invalid_live_output_does_not_displace_snapshot(monkeypatch, rc, payload):
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData({
        "steps": {"lsblk": {"data": VALID}},
    }))
    monkeypatch.setattr(checks, "run", lambda *_: (rc, json.dumps(payload)))
    found, source = checks._ntfs_partitions()
    assert len(found) == 1
    assert "sda1" in found[0]
    assert source == "lsblk（用户提供）"


def test_mount_table_alone_cannot_prove_absence_of_windows(monkeypatch):
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "_ntfs_partitions", lambda: ([], "/proc/mounts"))
    monkeypatch.setattr(checks, "_windows_installed", lambda: [])
    result = checks.check_ntfs()
    assert result.status == "unknown"
    assert checks.HabitsReport([result]).score is None


def test_valid_empty_and_null_children_are_allowed():
    for payload in ({"blockdevices": []}, {"blockdevices": [
        {"name": "sda", "fstype": None, "children": None},
    ]}):
        parsed, error = hostdata.parse_lsblk(json.dumps(payload))
        assert parsed == payload
        assert not error
