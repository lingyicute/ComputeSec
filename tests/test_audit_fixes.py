# -*- coding: utf-8 -*-
import pytest

from computesec import checks, cli, data, hostdata


@pytest.mark.parametrize("cmdline,want", [
    ("hash_pointers=always no_hash_pointers=0", "wrong"),
    ("hash_pointers=always no_hash_pointers=1", "wrong"),
    ("no_hash_pointers=1 hash_pointers=always", "ok"),
])
def test_no_hash_pointers_with_value_disables_hashing(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["hash_pointers"]
    assert item.status == want


@pytest.mark.parametrize("cmdline,want", [
    ("slab_nomerge slab_merge=1", "missing"),
    ("slub_nomerge slub_merge=0", "missing"),
    ("slab_merge=1 slab_nomerge", "ok"),
])
def test_slab_merge_with_value_overrides_earlier_nomerge(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["slab_nomerge"]
    assert item.status == want
