# -*- coding: utf-8 -*-
"""kernelver.py 单元测试：版本解析、版本线判定、缓存与离线降级。

全部用例都不访问网络：需要"上游版本号"的地方一律传入假的 fetcher。
"""

import json

import pytest

from computesec import kernelver as kv

# 与 https://www.kernel.org/releases.json 的真实结构一致（节选）
RELEASES_JSON = json.dumps({
    "latest_stable": {"version": "7.3"},
    "releases": [
        {"moniker": "mainline", "version": "7.3"},
        {"moniker": "stable", "version": "7.2.12"},
        {"moniker": "longterm", "version": "6.18.58"},
        {"moniker": "longterm", "version": "6.12.114"},
        {"moniker": "longterm", "version": "6.1.190"},
        {"moniker": "linux-next", "version": "next-20261023"},
    ],
}, indent=2)


def _fetcher_returning(text):
    def fetch(url, timeout):
        assert url == kv.RELEASES_URL
        assert timeout > 0
        return text
    return fetch


def _fetcher_failing(exc=None):
    def fetch(url, timeout):
        raise exc or OSError("network is unreachable")
    return fetch


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("text,want", [
    ("6.1.158+", (6, 1, 158)),
    ("7.3", (7, 3, 0)),
    ("7.2.12-200.fc44.x86_64", (7, 2, 12)),
    ("6.12.0-13-generic", (6, 12, 0)),
    ("6.18.0-rc3", (6, 18, 0)),
    ("  7.3.1  ", (7, 3, 1)),
])
def test_parse_release(text, want):
    assert kv.parse_release(text) == want


@pytest.mark.parametrize("text", ["", "abc", None, 42, "next-20261023", "v7.3"])
def test_parse_release_rejects_garbage(text):
    assert kv.parse_release(text) is None


def test_parse_releases_json():
    assert kv.parse_releases_json(RELEASES_JSON) == ("7.3", "7.2.12")


@pytest.mark.parametrize("text", ["", "not json", "[]", "null", '{"releases": "oops"}',
                                  '{"releases": [{"moniker": "stable"}]}', "{}"])
def test_parse_releases_json_tolerates_garbage(text):
    assert kv.parse_releases_json(text) == ("", "")


# ---------------------------------------------------------------------------
# classify：只有 mainline / stable 两条线算"受支持"
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("release,want", [
    ("7.3.0", "mainline"),
    ("7.3", "mainline"),
    ("7.4.0-rc1", "mainline"),       # 比主线还新（-rc / linux-next）
    ("7.2.12", "stable"),
    ("7.2.11", "stable"),            # 同一条线上落后一个点版本仍算 stable
    ("6.18.58", "older"),            # LTS
    ("6.12.114", "older"),
    ("6.1.158+", "older"),
    ("garbage", "unknown"),
])
def test_classify(release, want):
    assert kv.classify(release, "7.3", "7.2.12") == want


def test_classify_without_upstream_data():
    assert kv.classify("6.1.158", "", "") == "unknown"
    # 只拿到 stable 也能判断
    assert kv.classify("6.1.158", "", "7.2.12") == "older"
    assert kv.classify("7.2.12", "", "7.2.12") == "stable"


# ---------------------------------------------------------------------------
# fetch / 缓存 / 离线降级
# ---------------------------------------------------------------------------
def test_fetch_versions():
    assert kv.fetch_versions(fetcher=_fetcher_returning(RELEASES_JSON)) == ("7.3", "7.2.12")


def test_fetch_versions_raises_on_empty_payload():
    with pytest.raises(ValueError):
        kv.fetch_versions(fetcher=_fetcher_returning("{}"))


def test_get_status_online_then_cached(tmp_path):
    cache = tmp_path / "kv.json"
    calls = []

    def fetch(url, timeout):
        calls.append(1)
        return RELEASES_JSON

    st = kv.get_status(release="6.1.158+", now=1000, fetcher=fetch, cache_path=str(cache))
    assert st.known and not st.supported
    assert (st.mainline, st.stable, st.tier) == ("7.3", "7.2.12", "older")
    assert st.major_minor == "6.1"
    assert cache.exists()

    # 第二次：命中缓存，不再联网
    st2 = kv.get_status(release="6.1.158+", now=2000, fetcher=_fetcher_failing(), cache_path=str(cache))
    assert (st2.mainline, st2.stable) == ("7.3", "7.2.12")
    assert len(calls) == 1


def test_get_status_offline_without_cache(tmp_path):
    st = kv.get_status(release="7.2.12", now=1000, fetcher=_fetcher_failing(), cache_path=str(tmp_path / "none.json"))
    assert st.known is False
    assert st.tier == "unknown"
    assert st.error                     # 有错误原因，便于排查
    assert st.supported is False


def test_get_status_uses_stale_cache_when_offline(tmp_path):
    cache = tmp_path / "kv.json"
    kv.get_status(release="7.2.12", now=1000, fetcher=_fetcher_returning(RELEASES_JSON), cache_path=str(cache))
    # TTL 过后仍离线：宁可给出"上次的结果"，也不要完全没有结论
    st = kv.get_status(release="7.2.12", now=1000 + kv.CACHE_TTL + 10,
                       fetcher=_fetcher_failing(), cache_path=str(cache))
    assert st.known is True
    assert st.supported is True
    assert st.tier == "stable"


def test_cache_is_not_world_readable(tmp_path):
    import os
    cache = tmp_path / "kv.json"
    kv.get_status(release="6.1.158", now=1000, fetcher=_fetcher_returning(RELEASES_JSON), cache_path=str(cache))
    assert (os.stat(cache).st_mode & 0o777) == 0o600


def test_load_cache_rejects_garbage(tmp_path):
    cache = tmp_path / "kv.json"
    cache.write_text('{"release": 42}')
    assert kv.load_cache(str(cache)) is None
    cache.write_text("not json")
    assert kv.load_cache(str(cache)) is None
    cache.write_text('[1, 2]')
    assert kv.load_cache(str(cache)) is None


# ---------------------------------------------------------------------------
# 文案
# ---------------------------------------------------------------------------
def _status(tier, release="6.1.158+", mainline="7.3", stable="7.2.12"):
    return kv.KernelSupport(release=release, mainline=mainline, stable=stable, tier=tier)


def test_warning_text_mentions_versions_and_reason():
    text = kv.warning_text(_status("older"))
    assert "6.1.158+" in text
    assert "7.3" in text and "7.2.12" in text
    for kw in ("LTS", "sysctl", "启动参数", "mainline", "stable"):
        assert kw in text
    # 必须说明"参数会被内核忽略、而程序会误判"这一关键风险
    assert "静默忽略" in text


def test_banner_text_is_short():
    text = kv.banner_text(_status("older"))
    assert "6.1.158+" in text and "mainline" in text and "stable" in text
    assert len(text) < len(kv.warning_text(_status("older")))


def test_tier_text_covers_all_tiers():
    for tier in ("mainline", "stable", "older", "unknown"):
        assert kv.TIER_ZH[tier]
