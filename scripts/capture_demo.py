"""照藍圖 §14 的展示腳本走一遍儀表板，每一步截一張圖，最後組成 Demo GIF。

```bash
uv run --extra dashboard streamlit run app/dashboard.py      # 另一個終端機
uv run --extra dashboard --with playwright python scripts/capture_demo.py
```

產出 `docs/images/demo/step-N-*.png` 與 `docs/images/demo/demo.gif`。

用系統已安裝的 Edge（`channel="msedge"`），不另外下載瀏覽器；沒有 Edge 的環境
傳 `--channel chrome` 或 `--channel chromium`（後者要先 `playwright install chromium`）。

**截圖是展示素材，不是驗證。** 數字對不對由 `tests/test_dashboard.py` 負責；
這支腳本只負責「真的畫得出來、走得完八步」。
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images" / "demo"

# (檔名, 要點的分頁, 往下捲幾格, 說明——寫進 GIF 之外的 README 對照表)
STEPS = [
    ("step-1-upload", None, 0, "上傳弱掃 CSV"),
    ("step-2-ranking", "① 排名對照", 0, "CVSS 排名 vs 本專案排名"),
    ("step-3-slope", "① 排名對照", 6, "同一筆弱點，兩種排法"),
    ("step-4-factors", "① 排名對照", 22, "分數從哪裡來"),
    ("step-5-explain", "② 單筆說明", 0, "公式、來源、路徑"),
    ("step-6-measure", "③ 措施模擬", 0, "選措施：前後分數、路徑、工時"),
    ("step-7-graph", "④ 攻擊路徑", 3, "通往 Crown Jewel 的路徑"),
    ("step-8-export", "⑤ 匯出", 0, "匯出修補優先清單"),
]


def capture(url: str, channel: str, theme: str) -> list[Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    shots: list[Path] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=channel)
        page = browser.new_page(viewport={"width": 1440, "height": 900},
                                color_scheme=theme, device_scale_factor=1)
        page.goto(url)
        page.get_by_text("同一筆弱點，兩種排法").wait_for(timeout=180_000)

        # 第 1 步：真的上傳一份弱掃檔（用 Northstar 自己那份，結果與預設相同）
        page.locator("input[type=file]").set_input_files(
            str(ROOT / "data/synthetic/northstar/scanner.csv"))
        page.get_by_text("scanner.csv").first.wait_for(timeout=60_000)
        page.get_by_text("同一筆弱點，兩種排法").wait_for(timeout=180_000)

        for name, tab, scroll, _caption in STEPS:
            if tab:
                page.get_by_role("tab", name=tab).click()
                page.wait_for_timeout(1500)
            page.mouse.move(900, 500)
            page.mouse.wheel(0, -20_000)
            if scroll:
                page.mouse.wheel(0, scroll * 120)
            page.wait_for_timeout(1200)
            path = OUT / f"{name}.png"
            page.screenshot(path=str(path))
            shots.append(path)
        browser.close()
    return shots


def gif(shots: list[Path], width: int = 1200, ms: int = 2600) -> Path:
    frames = []
    for path in shots:
        image = Image.open(path).convert("RGB")
        height = round(image.height * width / image.width)
        frames.append(image.resize((width, height), Image.LANCZOS)
                      .convert("P", palette=Image.ADAPTIVE, colors=128))
    target = OUT / "demo.gif"
    frames[0].save(target, save_all=True, append_images=frames[1:], duration=ms, loop=0,
                   optimize=True)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--url", default="http://localhost:8501")
    parser.add_argument("--channel", default="msedge")
    parser.add_argument("--theme", default="light", choices=["light", "dark"])
    args = parser.parse_args()
    shots = capture(args.url, args.channel, args.theme)
    target = gif(shots)
    for path in shots + [target]:
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
