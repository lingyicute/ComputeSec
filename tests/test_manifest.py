# -*- coding: utf-8 -*-
"""Flatpak 清单与打包元数据的一致性。

2026-10-24 起不再准备上架 Flathub：Flathub 专用的 `uk._92li.lingyicute.ComputeSec.yml`
已删除，仓库里只剩 CI / Release 使用的 `.json`，也就不存在"两份清单权限不一致"
的问题了。这里改为守住三条仍会漂移、且都真的把人坑过的约束：

1. 清单必须保留 `--share=network`。1.2.0 加版本线检查时只改了一份清单、漏了另
   一份（当时就是 .yml 漏了），用漏掉的那份构建出来的包，版本线恒为「未能核对」，
   `net.*` 下的 sysctl 也全部变成「未验证」；
2. 清单必须继续开放它真正读取的宿主机数据（fwupd / hostname1 / udev / 引导分区），
   少一条就是一类检测静默失效；
3. metainfo 里最新的 `<release version>` 必须等于 `data.VERSION`。版本号只在
   data.py 维护一处，而发布日志是手写的，最容易漏。
"""

import json
import re
from pathlib import Path

from computesec import data

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "uk._92li.lingyicute.ComputeSec"


def _manifest():
    return json.loads((ROOT / f"{APP_ID}.json").read_text(encoding="utf-8"))


def test_no_flathub_manifest_left_behind():
    """不再上架 Flathub：那份 .yml 清单不该再出现，否则会有人照着它构建。"""
    assert not (ROOT / f"{APP_ID}.yml").exists()


def test_manifest_grants_network():
    """版本线检查要联网；缺这一条时 net.* 的读数还会来自沙箱自己的 netns。"""
    assert "--share=network" in _manifest()["finish-args"]


def test_manifest_opens_the_host_data_it_reads():
    finish = _manifest()["finish-args"]
    for perm in ("--system-talk-name=org.freedesktop.fwupd",
                 "--system-talk-name=org.freedesktop.hostname1",
                 "--filesystem=/var/lib/flatpak:ro",
                 "--filesystem=~/.local/share/flatpak:ro",
                 "--filesystem=/run/udev:ro",
                 "--filesystem=/boot:ro",
                 "--filesystem=/efi:ro"):
        assert perm in finish, perm


def test_manifest_targets_this_app():
    m = _manifest()
    assert m["id"] == APP_ID == data.APP_ID
    assert m["command"] == "computesec"


def test_newest_metainfo_release_matches_version():
    xml = (ROOT / "data" / f"{APP_ID}.metainfo.xml").read_text(encoding="utf-8")
    versions = re.findall(r'<release version="([^"]+)"', xml)
    assert versions, "metainfo 里没有任何 <release>"
    assert versions[0] == data.VERSION
