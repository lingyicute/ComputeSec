"""Malformed numeric cache metadata must not crash startup or rendering."""

import json

import pytest

from computesec import hostdata, kernelver


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), True, False])
def test_host_cache_rejects_invalid_timestamps(value, tmp_path, monkeypatch):
    monkeypatch.setattr(hostdata, "_data_dir", lambda create=True: str(tmp_path))
    (tmp_path / hostdata.CACHE_NAME).write_text(json.dumps({"collected_at": value}))
    assert hostdata.HostData.load().payload == {}
    assert hostdata.HostData({"collected_at": value}).collected_at == 0
    assert hostdata.HostData({"collected_at": value}).age_text == ""


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), True, False])
def test_kernel_cache_rejects_invalid_timestamps(value, tmp_path):
    payload = {"mainline": "7.3", "stable": "7.2.12", "checked_at": value}
    cache = tmp_path / "kernelver.json"
    cache.write_text(json.dumps(payload))
    assert kernelver.KernelSupport.from_dict(payload) is None
    assert kernelver.load_cache(str(cache)) is None


def test_kernelver_age_text_rejects_fractional_future_timestamp():
    st = kernelver.KernelSupport(checked_at=1000.9)
    assert st.age_text(now=1000.1) == ""
    assert st.age_text(now=1001.0) == "刚刚"
