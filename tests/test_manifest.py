# -*- coding: utf-8 -*-
"""两份 Flatpak 清单（.json 给 CI / 本地构建，.yml 给 Flathub）的权限必须一致。

1.2.0 加 --share=network 时只改了 .json，.yml 漏掉了：用 .yml 构建出的包
版本线检查恒为「未能核对」，net.* sysctl 也全部变成「未验证」。
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "uk._92li.lingyicute.ComputeSec"


def _yml_finish_args(text):
    # 不引入 PyYAML：finish-args 是顶层的一个纯字符串列表，按行取即可。
    m = re.search(r"^finish-args:\n((?:[ \t]+.*\n|\n)+)", text, re.M)
    assert m, "yml 清单里没有 finish-args"
    return [x.strip() for x in re.findall(r"^[ \t]+-[ \t]+(\S+)", m.group(1), re.M)]


def test_manifests_grant_the_same_permissions():
    j = json.loads((ROOT / f"{APP_ID}.json").read_text(encoding="utf-8"))
    y = _yml_finish_args((ROOT / f"{APP_ID}.yml").read_text(encoding="utf-8"))
    assert sorted(j["finish-args"]) == sorted(y)
