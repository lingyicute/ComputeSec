"""Cache writes must be private, atomic and isolated between writers."""

import json
import os

import pytest

from computesec import hostdata, kernelver, xdg


@pytest.fixture(params=["hostdata", "kernelver"])
def writer(request, tmp_path, monkeypatch):
    if request.param == "hostdata":
        monkeypatch.setattr(hostdata, "_data_dir", lambda create=True: str(tmp_path))
        path = tmp_path / hostdata.CACHE_NAME

        def save(value):
            hostdata.HostData({"marker": value}).save()
    else:
        path = tmp_path / kernelver.CACHE_NAME

        def save(value):
            kernelver.save_cache(kernelver.KernelSupport(error=value), str(path))

    return path, save


def test_preexisting_temporary_symlink_is_not_followed(writer, tmp_path):
    path, save = writer
    victim = tmp_path / "unrelated.txt"
    victim.write_text("do not overwrite")
    victim.chmod(0o644)
    (tmp_path / (path.name + ".tmp")).symlink_to(victim)
    save("new")
    assert victim.read_text() == "do not overwrite"
    assert victim.stat().st_mode & 0o777 == 0o644
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())


def test_interleaved_writers_use_different_temporary_paths(writer, monkeypatch):
    path, save = writer
    replace = os.replace
    entered = False
    sources = []

    def interleave(source, target):
        nonlocal entered
        sources.append(os.fspath(source))
        if not entered:
            entered = True
            save("inner")
        return replace(source, target)

    monkeypatch.setattr(xdg.os, "replace", interleave)
    save("outer")
    assert len(set(sources)) == 2
    payload = json.loads(path.read_text())
    assert payload.get("marker", payload.get("error")) == "outer"


def test_replace_failure_preserves_old_cache_and_cleans_temp(writer, monkeypatch):
    path, save = writer
    save("old")
    before = path.read_bytes()

    def fail_replace(*_args):
        raise OSError("read-only destination")

    monkeypatch.setattr(xdg.os, "replace", fail_replace)
    save("new")
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]
