# -*- coding: utf-8 -*-
"""Tests for scripts/subset_font.py string extraction."""

from scripts import subset_font


def test_script_ui_chars_keeps_url_strings_and_templates():
    html = r"""<script>
    // 注释中的独字：巭
    /* 块注释：孬 */
    const url = 'https://example.invalid/路径';
    const msg = `模板提示：${url}`;
    const esc = '转义\'引号';
    </script>"""
    chars = subset_font.script_ui_chars(html)
    assert {"路", "径", "模", "板", "提", "示", "转", "义", "引", "号"}.issubset(chars)
    assert "巭" not in chars
    assert "孬" not in chars


def test_subset_font_cache_is_current():
    assert subset_font.main(["--check"]) == 0
