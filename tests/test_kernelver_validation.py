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

    status = kv.get_status("7.3", now=1001, fetcher=fetch, cache_path=str(cache))
    assert calls == [1]
    assert status.known
    assert status.mainline == "7.3"


def test_kernel_support_clears_invalid_upstream_version_strings():
    st = kv.KernelSupport(release="6.12.1", mainline="not-a-version", stable="7.2.12")
    assert st.mainline == ""
    assert st.stable == "7.2.12"
    assert st.tier == "older"


def test_from_dict_recomputes_tier_instead_of_trusting_cached_label():
    st = kv.KernelSupport.from_dict({
        "release": "6.1.158",
        "mainline": "7.3",
        "stable": "7.2.12",
        "tier": "mainline",
        "checked_at": 1000,
    })
    assert st is not None
    assert st.tier == "older"
    assert not st.supported
    st_no_stable = kv.KernelSupport.from_dict({
        "release": "6.1.158",
        "mainline": "7.3",
        "stable": "",
        "tier": "stable",
        "checked_at": 1000,
    })
    assert st_no_stable is not None
    assert st_no_stable.tier == "unknown"
    assert not st_no_stable.known


def test_age_text_handles_huge_integer_timestamps():
    huge = 10 ** 400
    st = kv.KernelSupport.from_dict({
        "release": "6.18.1",
        "mainline": "6.18.1",
        "checked_at": huge,
    })
    assert st is not None
    assert st.age_text() == ""
    assert st.age_text(now=1000) == ""
    assert st.age_text(now=huge + 10) == "刚刚"


def test_default_fetcher_rejects_overflowing_timeout():
    with pytest.raises(ValueError):
        kv._default_fetcher(kv.RELEASES_URL, 10 ** 400)
