from computesec import data


def test_plugin_guidance_addresses_filtering_not_unrelated_platform_plugins():
    info = data.HSI_ATTRS["org.fwupd.hsi.Fwupd.Plugins"]
    assert "过滤" in info["meaning"] and "并非" in info["meaning"]
    assert "fwupdtool --plugins" in info["fix"]
    assert "仅重装软件不会" in info["fix"]
