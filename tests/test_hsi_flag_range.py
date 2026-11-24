import pytest
from computesec import checks

@pytest.mark.parametrize("flags", [-1, -3, -(1 << 63), (1 << 64) | 1])
def test_invalid_unsigned_flags_cannot_pass_or_hide_hsi(flags):
    assert checks._flags_to_set(flags) == set()
    item = checks._normalize_attrs([{"AppstreamId": "org.fwupd.hsi.Iommu", "Flags": flags}])[0]
    assert not item.passed and not item.obsoleted


def test_unknown_valid_unsigned_bits_are_ignored():
    assert checks._flags_to_set((1 << 63) | 1) == {"success"}
