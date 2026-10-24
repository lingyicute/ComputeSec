#!/usr/bin/env python3
"""
Subset the design font into a separately cacheable WOFF2 file.

Optional maintenance/CI tool, not a runtime build requirement.
Run: pip install fonttools brotli && python scripts/subset_font.py
Use --force to refresh the upstream font, or NEBULOVE_FONT=/path/to/font.ttf offline.
"""
import hashlib
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
# 上游字体固定在某个提交上，不用 main 分支：否则上游一改，同一份代码就会得到不同
# 的构建产物，CI 与本地也就无法复现。升级字体时同时更新 COMMIT 与 SHA256。
FONT_REPO = "lingyicute/Nebulove"
FONT_COMMIT = "df0d98ed69435d0ff1f3705c084aca057f4ca9a5"
FONT_SHA256 = "c40a831c4577807aaf7e264fad8dadb6dd2b8fe329bd39abdf74e3ef72770ae4"
FONT_URL = f"https://raw.githubusercontent.com/{FONT_REPO}/{FONT_COMMIT}/Nebulove.ttf"
HTML_PATH = ROOT / "web" / "index.html"
CACHE_PATH = ROOT / "scripts" / ".font-subset-cache.json"
OUTPUTS = {
    "Nebulove": ROOT / "web" / "fonts" / "nebulove-subset.woff2",
}


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignored = 0
        self.chars = set()

    def handle_starttag(self, tag, attrs):
        if tag in {"head", "script", "style"}:
            self.ignored += 1
        if not self.ignored:
            for name, value in attrs:
                if name in {"alt", "title", "aria-label", "placeholder"} and value:
                    self.chars.update(value)

    def handle_endtag(self, tag):
        if tag in {"head", "script", "style"}:
            self.ignored = max(0, self.ignored - 1)

    def handle_data(self, text):
        if not self.ignored:
            self.chars.update(text)


def css_content_values(html):
    values = set()
    for style in re.findall(r"<style[^>]*>(.*?)</style>", html, flags=re.S):
        css = re.sub(r"/\*.*?\*/", "", style, flags=re.S)
        values.update(v for v in re.findall(r"content:\s*['\"]([^'\"]*)['\"]", css) if v)
    return values


def collect_chars():
    html = HTML_PATH.read_text(encoding="utf-8")
    parser = VisibleText()
    parser.feed(html)
    chars = parser.chars
    # Avoid subsetting CSS comments as visible text; only real content: glyphs matter.
    chars.update(css_content_values(html))
    chars.update(chr(c) for c in range(32, 127))  # Includes dynamic counts / English UI.
    chars.update("：，。！？；“”‘’（）【】—…·《》×＝÷＋－")
    return chars


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(chars=None, local_font=None):
    """决定"这份 WOFF2 是否还能用"的指纹：上游字体 + 本脚本 + 页面用到的字符集。"""
    chars = collect_chars() if chars is None else chars
    source_key = digest(Path(local_font)) if local_font else FONT_URL
    return hashlib.sha256((
        source_key + digest(Path(__file__))
        + json.dumps(sorted(ord(c) for c in chars))
    ).encode()).hexdigest()


def subset(font, chars):
    from fontTools.subset import Options, Subsetter

    subsetter = Subsetter(options=Options())
    subsetter.populate(unicodes=sorted(ord(c) for c in chars))
    subsetter.subset(font)
    font.flavor = "woff2"
    font.recalcTimestamp = False
    output = io.BytesIO()
    font.save(output)
    return output.getvalue()


def replace_face(css, family, filename):
    for match in re.finditer(r"@font-face\s*\{[^}]*\}", css):
        if re.search(r'font-family:\s*["\']' + re.escape(family) + r'["\']\s*;', match[0]):
            face = (
                "@font-face{\n"
                f'    font-family:"{family}";\n'
                f"    src: url('fonts/{filename}') format('woff2');\n"
                "    font-display:swap;\n"
                "  }"
            )
            return css[:match.start()] + face + css[match.end():]
    raise ValueError(f"Missing font-face: {family}")


def is_current():
    """当前 web/index.html 与已提交的 WOFF2 子集是否一致（不访问网络）。"""
    try:
        cached = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "缺少或无法解析 scripts/.font-subset-cache.json"
    css = HTML_PATH.read_text(encoding="utf-8")
    if cached.get("fingerprint") != fingerprint():
        return False, "字体子集已过期：web/index.html 或本脚本有改动"
    for path in OUTPUTS.values():
        if not path.exists():
            return False, f"缺少 {path.relative_to(ROOT)}"
        if path.name not in css:
            return False, f"web/index.html 没有引用 {path.name}"
        if cached.get("outputs", {}).get(path.name) != digest(path):
            return False, f"{path.relative_to(ROOT)} 与缓存记录的哈希不一致"
    return True, "WOFF2 子集与页面一致"


def main():
    if "--check" in sys.argv:
        ok, reason = is_current()
        print(("OK: " if ok else "STALE: ") + reason)
        if not ok:
            print("请执行：pip install fonttools brotli && python scripts/subset_font.py")
            return 1
        return 0
    from fontTools.ttLib import TTFont

    chars = collect_chars()
    local_font = os.environ.get("NEBULOVE_FONT")
    fp = fingerprint(chars, local_font)
    css = HTML_PATH.read_text(encoding="utf-8")
    if "--force" not in sys.argv and CACHE_PATH.exists():
        cached = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        if cached.get("fingerprint") == fp and all(
            path.exists() and path.name in css
            and cached.get("outputs", {}).get(path.name) == digest(path)
            for path in OUTPUTS.values()
        ):
            print("Visible charset unchanged; WOFF2 subset is current.")
            return

    if local_font:
        nebulove = TTFont(local_font)
    else:
        print(f"Downloading Nebulove source font @ {FONT_COMMIT[:7]}...")
        with urllib.request.urlopen(FONT_URL, timeout=90) as response:
            blob = response.read()
        got = hashlib.sha256(blob).hexdigest()
        if got != FONT_SHA256:
            print(f"字体哈希不一致，已中止：\n  期望 {FONT_SHA256}\n  实际 {got}\n"
                  "如果你确实要升级字体，请同时更新脚本里的 FONT_COMMIT 与 FONT_SHA256。")
            return 1
        nebulove = TTFont(io.BytesIO(blob))
    fonts = {"Nebulove": subset(nebulove, chars)}

    new_css = css
    for family, path in OUTPUTS.items():
        new_css = replace_face(new_css, family, path.name)
    assert new_css.count("@font-face") == css.count("@font-face")
    for family, path in OUTPUTS.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fonts[family])
        print(f"{path.name}: {len(fonts[family]):,} bytes")
    HTML_PATH.write_text(new_css, encoding="utf-8")
    CACHE_PATH.write_text(json.dumps({
        "fingerprint": fp,
        "source": FONT_URL,
        "charset_count": len(chars),
        "outputs": {p.name: digest(p) for p in OUTPUTS.values()},
    }, indent=2) + "\n", encoding="utf-8")
    print("Updated external subset; no font data embedded in render-blocking CSS.")


if __name__ == "__main__":
    sys.exit(main())
