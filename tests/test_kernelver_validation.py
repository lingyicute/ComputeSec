"""Only usable upstream versions may satisfy the release check."""

import json

import pytest

from computesec import kernelver as kv


@pytest.mark.parametrize("releases", [42, True, "bad", {"mainline": "7.3"}, None])
def test_release_collection_must_be_a_list(releases):
    assert kv.parse_releases_json(json.dumps({"releases": releases})) == ("", "")


@pytest.mark.parametrize("version", ["garbage", " ", "7.3garbage", "7.3.1.2", "7.3-local", "9" * 5000 + ".1"])
def test_invalid_upstream_version_does_not_become_known(version):
    text = json.dumps({"releases": [{"moniker": "mainline", "version": version}]})
    assert kv.parse_releases_json(text) == ("", "")
    assert not kv.KernelSupport(release="7.2", mainline=version).known
    with pytest.raises(ValueError):
        kv.fetch_versions(fetcher=lambda *_: text)


def test_invalid_first_version_does_not_hide_valid_later_entry():
    text = json.dumps({"releases": [
        {"moniker": "mainline", "version": "garbage"},
        {"moniker": "mainline", "version": "7.3-rc1"},
        {"moniker": "stable", "version": "7.2.12"},
    ]})
    assert kv.parse_releases_json(text) == ("7.3-rc1", "7.2.12")


def test_unusable_cache_does_not_suppress_fetch(tmp_path):
    cache = tmp_path / "kernelver.json"
    cache.write_text(json.dumps({"mainline": "garbage", "checked_at": 1000}))
    calls = []

    def fetch(*_args):
        calls.append(1)
        return json.dumps({"releases": [{"moniker": "mainline", "version": "7.3"}]})

    status = kv.get_status("7.2", now=1001, fetcher=fetch, cache_path=str(cache))
    assert calls == [1]
    assert status.known
    assert status.mainline == "7.3"
