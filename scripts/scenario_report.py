"""產出 Day 29 的測試報告：四個必測情境、對照人工排序、CVSS 與本專案的差異逐筆說明。

```bash
uv run python scripts/scenario_report.py      # 寫入 docs/releases/day-29-scenario-report.md
```

報告是**產出物**，不是手寫的：重跑必須得到同一份。數字與 `tests/test_scenarios.py`、
儀表板的「情境驗證」分頁同一段程式算的。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import data  # noqa: E402
import scenarios  # noqa: E402

TARGET = ROOT / "docs" / "releases" / "day-29-scenario-report.md"
BADGE = {scenarios.PASS: "✅ PASS", scenarios.PARTIAL: "⚠️ PARTIAL",
         scenarios.FAIL: "❌ FAIL", scenarios.NO_CASE: "— NO_CASE"}


def main() -> int:
    p = data.run()
    results = scenarios.run_all(p)
    vs = scenarios.versus_expert(p, ROOT / "data/calibration/day-17-expert-ranking.yaml")
    out = ["# Day 29 測試報告：四個必測情境", "",
           f"- 證據基準日：{data.AS_OF}（NVD／EPSS／KEV 固定快照）",
           f"- 資料集：Northstar（虛構），{len(p.ranked)} 筆 finding，{len(p.scored)} 筆有分數",
           "- 產生方式：`uv run python scripts/scenario_report.py`（產出物，不手改）", "",
           "## 總表", "", "| 情境 | 判定 | 量到 |", "|---|---|---|"]
    for s in results:
        out.append(f"| {s.number}．{s.title} | {BADGE[s.verdict]} | {s.finding} |")
    out += ["", "規則先於結果：每個情境是一條逐字對應藍圖 §8.4 的查詢規則，資料裡符合的",
            "每一筆都評。`NO_CASE`（資料裡沒有這種情況）不算通過。", ""]
    for s in results:
        out += [f"## 情境{'一二三四'[s.number - 1]}：{s.title}（{BADGE[s.verdict]}）", "",
                f"- 規則：{s.rule}", f"- 判準：{s.criterion}", f"- 量到：{s.finding}",
                f"- 限制：{s.caveat}", ""]
        if s.cases:
            keys = [k for k, v in s.cases[0].items() if not isinstance(v, (list, dict))]
            out.append("| " + " | ".join(keys) + " |")
            out.append("|" + "---|" * len(keys))
            for c in s.cases:
                out.append("| " + " | ".join(str(c[k]) for k in keys) + " |")
            out.append("")
    m, c = vs["model"], vs["cvss"]
    out += ["## 對照人工排序（Day 17 基準）", "",
            "| 排序 | Kendall τ-b | 一致 | 分歧 | 平手 |", "|---|---:|---:|---:|---:|",
            f"| 本專案 | {m[0]} | {m[1]} | {m[2]} | {m[3]} |",
            f"| 只看 CVSS | {c[0]} | {c[1]} | {c[2]} | {c[3]} |", "",
            f"**效度威脅**：只有 {vs['n']} 筆，排序者是「{vs['ranked_by']}」。",
            "這是自我一致性檢查，不是獨立驗證；差 0.07 在 5 筆上就是一組比較的差別。", "",
            "## CVSS 排名與本專案排名：差異逐筆說明（成功標準 #5）", "",
            "主因＝方向與移動一致、偏離全體中位數最多的那一項（S 以外）。算出來的，不是寫上去的。",
            "", "| 本專案 | CVSS（並列） | 移動 | 資產 | CVE | CVSS | 分數 | 主因 |",
            "|---:|---:|---:|---|---|---:|---:|---|"]
    for r in scenarios.why_moved(p):
        out.append(f"| {r['rank']} | {r['cvss_rank']} | {r['move']:+d} | {r['asset']} | "
                   f"{r['cve']} | {r['cvss']} | {r['score']} | {r['reason']} |")
    TARGET.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print(TARGET.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
