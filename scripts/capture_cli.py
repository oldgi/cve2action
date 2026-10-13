"""把命令列的實際輸出截成圖，給文章當結果圖用。

```bash
uv run --extra dashboard --with playwright python scripts/capture_cli.py
```

**程式跑出來的結果，就用程式跑出來的畫面。** 這支腳本用與文章、測試、CI 相同的
一組輸入呼叫 `cve2action`，把 stdout 原封不動排進一個終端機樣式的頁面再截圖。
圖上第一行印出實際下的指令，讀者可以照著重跑。

Day 26、27 原本的結果圖是 ChatGPT 依提示詞畫的資訊圖，數字是人抄進提示詞的——
讀者看不到真的輸出，產圖時也可能把數字畫錯。換成這裡的截圖之後，圖上的每個數字
都由程式產生。

字型用細明體（MingLiU）：中文字恰好是英數字的兩倍寬，命令列輸出的對齊就是照這個
假設排的。
"""

from __future__ import annotations

import contextlib
import html
import io
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import data  # noqa: E402  與儀表板、測試同一組輸入

from cve2action.cli import main as cli_main  # noqa: E402

# 檔名 → 子命令。只換子命令，輸入一律是 data.argv() 那一組。
SHOTS = {
    "day-26-result": "candidates",
    "day-27-result": "roi",
}

PAGE = """<!doctype html><meta charset="utf-8">
<style>
  body {{ margin: 0; background: #1a1a19; }}
  .term {{ display: inline-block; padding: 28px 32px; background: #1a1a19; color: #e8e6df;
          font: 17px/1.5 "MingLiU", monospace; white-space: pre; }}
  .cmd {{ color: #3987e5; }}
  .cmd b {{ color: #898781; font-weight: normal; }}
</style>
<div class="term"><span class="cmd"><b>$</b> uv run cve2action {command} $ARGS</span>
<b></b>
{output}</div>"""


def run(command: str) -> str:
    args = data.argv()
    args[0] = command
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli_main(args)
    if code != 0:
        raise SystemExit(f"cve2action {command} exit {code}")
    return buffer.getvalue().rstrip("\n")


def main() -> int:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge")
        page = browser.new_page(viewport={"width": 1600, "height": 900}, device_scale_factor=1)
        for name, command in SHOTS.items():
            output = run(command)
            page.set_content(PAGE.format(command=command, output=html.escape(output)))
            target = ROOT / "docs" / "images" / f"{name}.png"
            page.locator(".term").screenshot(path=str(target))
            print(f"{target.relative_to(ROOT)}  {target.stat().st_size // 1024} KB")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
