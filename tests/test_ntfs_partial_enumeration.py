import pytest
from computesec import checks, hostdata

@pytest.mark.parametrize("source", ["udev", "udev + /proc/mounts", "/proc/mounts", ""])
def test_partial_enumeration_cannot_prove_absence(monkeypatch, source):
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(hostdata, "CURRENT", hostdata.HostData())
    monkeypatch.setattr(checks, "_ntfs_partitions", lambda: ([], source))
    monkeypatch.setattr(checks, "_windows_installed", lambda: [])
    result = checks.check_ntfs()
    assert result.status == "unknown"
    assert checks.HabitsReport([result]).score is None

@pytest.mark.parametrize("source", ["lsblk", "lsblk（用户提供）"])
def test_complete_enumeration_can_establish_absence(monkeypatch, source):
    monkeypatch.setattr(checks, "IN_FLATPAK", False)
    monkeypatch.setattr(checks, "_ntfs_partitions", lambda: ([], source))
    monkeypatch.setattr(checks, "_windows_installed", lambda: [])
    assert checks.check_ntfs().status == "good"


def test_positive_udev_evidence_is_not_discarded(monkeypatch):
    monkeypatch.setattr(checks, "_ntfs_partitions", lambda: (["/dev/sda1 NTFS"], "udev"))
    monkeypatch.setattr(checks, "_windows_installed", lambda: [])
    assert checks.check_ntfs().status == "bad"
