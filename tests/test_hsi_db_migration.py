import pytest
from computesec import checks, data

@pytest.mark.parametrize("aid", ["org.fwupd.hsi.Uefi.Db", "org.fwupd.hsi.Uefi.Db.MsUefi"])
def test_db_check_is_certificate_migration_not_dbx_revocation(aid):
    info = checks._lookup_hsi_info(aid)
    assert info is data.HSI_ATTRS["org.fwupd.hsi.Uefi.Db"]
    assert "Microsoft UEFI CA 2023" in info["meaning"]
    assert "不是 dbx" in info["meaning"]
    assert "先更新 KEK，再更新 db" in info["fix"]
    item = checks._normalize_attrs([{"AppstreamId": aid, "HsiResult": "not-found",
                                    "Flags": ["success"]}])[0]
    assert item.passed  # custom-key systems without Microsoft's CA can pass
