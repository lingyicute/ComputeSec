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


@pytest.mark.parametrize("cmdline,want,actual", [
    ("quiet loglevel=0", "ok", "0"),
    ("debug loglevel=0", "ok", "0"),
    ("loglevel=0 quiet", "wrong", "quiet"),
    ("loglevel=0 debug", "wrong", "debug"),
    ("loglevel=0 quiet=1", "wrong", "quiet"),
    ("loglevel=0 quiet loglevel=0", "ok", "0"),
])
def test_later_quiet_or_debug_overrides_loglevel_zero(monkeypatch, cmdline, want, actual):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["loglevel"]
    assert item.status == want
    assert item.actual == actual


@pytest.mark.parametrize("cmdline,want", [
    ("ignore_loglevel loglevel=0", "wrong"),
    ("loglevel=0 ignore_loglevel", "wrong"),
    ("loglevel=0 printk.ignore_loglevel", "wrong"),
    ("loglevel=0 printk.ignore_loglevel=1", "wrong"),
    ("ignore_loglevel loglevel=0 printk.ignore_loglevel=0", "ok"),
    ("printk.ignore_loglevel=0 ignore_loglevel loglevel=0", "ok"),
])
def test_ignore_loglevel_bypasses_loglevel_zero(monkeypatch, cmdline, want):
    monkeypatch.setattr(checks, "arch", lambda: "x86_64")
    monkeypatch.setattr(checks, "cpu_vendor", lambda: "intel")
    monkeypatch.setattr(checks, "read", lambda p, d="": cmdline if p == "/proc/cmdline" else d)
    item = {i.key: i for i in checks.get_cmdline_report().items}["loglevel"]
    assert item.status == want
