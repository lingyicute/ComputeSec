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


def test_fresh_cache_keeps_its_own_timestamp(tmp_path):
    """命中仍在 TTL 内的缓存时，checked_at 应当还是当初取到版本号的时刻。"""
    cache = tmp_path / "kv.json"
    kv.get_status(release="6.1.158+", now=1000, fetcher=_fetcher_returning(RELEASES_JSON), cache_path=str(cache))
    st = kv.get_status(release="6.1.158+", now=2000, fetcher=_fetcher_failing("应当走缓存"), cache_path=str(cache))
    assert st.stale is False
    assert st.checked_at == 1000


def test_stale_cache_is_flagged(tmp_path):
    """过期缓存 + 断网：结论可以给，但必须标明它来自旧数据、且带上失败原因。"""
    cache = tmp_path / "kv.json"
    kv.get_status(release="6.1.158+", now=1000, fetcher=_fetcher_returning(RELEASES_JSON), cache_path=str(cache))
    now = 1000 + kv.CACHE_TTL + 86400
    st = kv.get_status(release="6.1.158+", now=now, fetcher=_fetcher_failing(), cache_path=str(cache))
    assert st.known is True and st.supported is False
    assert st.stale is True
    assert st.checked_at == 1000            # 不能被改写成 now
    assert st.error                         # 失败原因要留下来给 tooltip
    assert st.age_text(now) == "2 天前"      # TTL(1 天) + 额外 1 天


def test_online_result_is_not_stale(tmp_path):
    st = kv.get_status(release="7.2.12", now=1000, fetcher=_fetcher_returning(RELEASES_JSON),
                       cache_path=str(tmp_path / "kv.json"))
    assert st.stale is False
    assert st.error == ""


def _counting(text):
    calls = []

    def fetch(url, timeout):
        calls.append(url)
        return text
    return fetch, calls


def test_force_bypasses_fresh_cache_and_rewrites_it(tmp_path):
    """手动重查：缓存还在 TTL 内也要真正联网，且新结果照常写回缓存。"""
    cache = str(tmp_path / "kv.json")
    kv.save_cache(kv.KernelSupport(release="7.2.1", mainline="7.2", stable="7.1.9",
                                   tier="stable", checked_at=1000), cache)
    fetch, calls = _counting(RELEASES_JSON)
    st = kv.get_status(release="7.2.1", now=1000 + 3600, fetcher=fetch, cache_path=cache, force=True)
    assert len(calls) == 1
    assert (st.mainline, st.stable, st.checked_at) == ("7.3", "7.2.12", 1000 + 3600)
    assert kv.load_cache(cache).mainline == "7.3"


def test_force_failure_keeps_fresh_cache_without_marking_stale(tmp_path):
    cache = str(tmp_path / "kv.json")
    kv.get_status(release="7.2.12", now=1000, fetcher=_fetcher_returning(RELEASES_JSON), cache_path=cache)
    st = kv.get_status(release="7.2.12", now=2000, fetcher=_fetcher_failing(), cache_path=cache, force=True)
    assert st.known and st.supported
    assert st.stale is False                # 仍在 TTL 内，不算过期
    assert st.error                         # 但这次确实没刷新成
    assert st.checked_at == 1000


@pytest.mark.parametrize("checked_at", [0, 1000 + 30 * 86400])
def test_cache_without_or_with_future_timestamp_is_not_fresh(tmp_path, checked_at):
    """时间戳为 0 或在未来（时钟回拨）时，缓存不能永不过期。"""
    cache = tmp_path / "kv.json"
    cache.write_text(json.dumps(dict(release="7.2.1", mainline="7.2", stable="7.1.9", tier="stable",
                                     checked_at=checked_at, error="")))
    fetch, calls = _counting(RELEASES_JSON)
    st = kv.get_status(release="7.2.1", now=1000, fetcher=fetch, cache_path=str(cache))
    assert len(calls) == 1 and st.mainline == "7.3"


def test_cache_without_versions_is_ignored(tmp_path):
    cache = tmp_path / "kv.json"
    cache.write_text(json.dumps(dict(release="7.2.1", mainline="", stable="", tier="unknown",
                                     checked_at=990, error="")))
    fetch, calls = _counting(RELEASES_JSON)
    st = kv.get_status(release="7.2.1", now=1000, fetcher=fetch, cache_path=str(cache))
    assert len(calls) == 1 and st.known


@pytest.mark.parametrize("secs,want", [
    (0, "刚刚"), (59, "刚刚"), (60, "1 分钟前"), (3599, "59 分钟前"),
    (3600, "1 小时前"), (86400, "1 天前"), (3 * 86400, "3 天前"),
])
def test_age_text(secs, want):
    st = kv.KernelSupport(release="6.1.158+", checked_at=1_000_000)
    assert st.age_text(1_000_000 + secs) == want


def test_age_text_without_timestamp():
    assert kv.KernelSupport(release="6.1.158+").age_text() == ""


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
# 联网请求本身
# ---------------------------------------------------------------------------
class _FakeResponse:
    """够 _default_fetcher 用的最小替身。"""

    def __init__(self, body=b"{}", url=None):
        self._body = body
        self._url = url

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def geturl(self):
        return self._url

    def read(self, n=-1):
        self.seen_limit = n
        return self._body


def _patch_urlopen(monkeypatch, resp):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["resp"] = resp
        return resp

    monkeypatch.setattr(kv, "_urlopen", fake_urlopen)
    return seen


def test_default_fetcher_caps_response_size(monkeypatch):
    resp = _FakeResponse(b'{"releases": []}', url=kv.RELEASES_URL)
    _patch_urlopen(monkeypatch, resp)
    assert kv._default_fetcher(kv.RELEASES_URL, 5) == '{"releases": []}'
    assert resp.seen_limit == kv.MAX_RESPONSE_BYTES + 1


def test_default_fetcher_reports_oversized_response(monkeypatch):
    """超限要明确报错，而不是截断后让 JSON 解析失败、误报「没有版本号」。"""
    _patch_urlopen(monkeypatch, _FakeResponse(b"x" * (kv.MAX_RESPONSE_BYTES + 1), url=kv.RELEASES_URL))
    with pytest.raises(ValueError, match="超过"):
        kv._default_fetcher(kv.RELEASES_URL, 5)


class _FakeFp:
    closed = False

    def close(self):
        self.closed = True


@pytest.mark.parametrize("newurl", ["http://www.kernel.org/releases.json", "ftp://mirror.example/x"])
def test_redirect_handler_rejects_each_non_https_hop(newurl):
    """https → http → https 的链里，中间那一跳在发出前就必须被拦下。"""
    import urllib.error
    import urllib.request
    h = kv._HttpsOnlyRedirectHandler()
    fp = _FakeFp()
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(urllib.request.Request(kv.RELEASES_URL), fp, 302, "Found", {}, newurl)
    assert fp.closed


def test_redirect_handler_follows_https_hop():
    import urllib.request
    h = kv._HttpsOnlyRedirectHandler()
    new = h.redirect_request(urllib.request.Request(kv.RELEASES_URL), _FakeFp(), 302, "Found", {},
                             "https://mirrors.example/releases.json")
    assert new.full_url == "https://mirrors.example/releases.json"


def test_default_fetcher_rejects_downgrade_redirect(monkeypatch):
    """被重定向到 http:// 时 TLS 只保护了第一跳，此时不能相信响应内容。"""
    _patch_urlopen(monkeypatch, _FakeResponse(url="http://mirror.example/releases.json"))
    with pytest.raises(ValueError):
        kv._default_fetcher(kv.RELEASES_URL, 5)


def test_default_fetcher_accepts_https_redirect(monkeypatch):
    resp = _FakeResponse(b"ok", url="https://mirrors.example/releases.json")
    _patch_urlopen(monkeypatch, resp)
    assert kv._default_fetcher(kv.RELEASES_URL, 5) == "ok"


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
