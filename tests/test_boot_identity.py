import pytest
from computesec import hostdata

@pytest.mark.parametrize("saved", ["", "previous-boot"])
def test_unreadable_boot_id_does_not_validate_cache(monkeypatch, saved):
    monkeypatch.setattr(hostdata, "boot_id", lambda: "")
    assert not hostdata.HostData({"boot_id": saved, "skipped": True}).fresh


def test_current_boot_still_accepts_skip_marker(monkeypatch):
    monkeypatch.setattr(hostdata, "boot_id", lambda: "current-boot")
    assert hostdata.HostData({"boot_id": "current-boot", "skipped": True}).fresh
