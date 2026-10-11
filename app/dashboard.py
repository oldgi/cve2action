#!/usr/bin/env python
"""儀表板（藍圖 §12 的 `app/dashboard.py`，Day 28）。

**這是 Day 28 的骨架，還沒實作。** 目的在於讓結構先存在、並寫下那天要守的條件，
而不是留一個空檔案假裝有東西。

那一天的驗收（藍圖 §10 Day 28）：

> 排序、說明、路徑可操作；**同一畫面並陳 CVSS 排名與本專案排名兩欄**（成功標準 #5）

資料層已經備好在 `app/data.py`，四個視圖的查詢都跑得起來，2026-10-11 驗證過
可以畫得出來：

| 視圖 | 驗證結果 |
|---|---|
| `graph` | 通往 Crown Jewel 的 30 條路徑收斂成 12 台、18 條邊 |
| `ranking` | 前十名的五項因子攤成堆疊長條 |
| `cvss` | 六筆 CVSS 10.0 在本專案排序裡跨 28 個名次 |
| `treatment` | 適用性 1/9/30、層級覆寫前後 |

## 動手前要記得的兩件事

**一、`ranking` 視圖會揭穿一件事。** 前十名裡 `business` 的貢獻全是 2.0、
`threat` 全是 1.2——兩個因子在頂端完全沒有鑑別力。儀表板如果照五個因子等寬畫，
會把這件事藏起來。`app/data.py` 的 `distinct_contributions_in_top10` 就是為了
讓它藏不住。

**二、P0 的筆數在這份資料上不具參考價值。** Day 25 量到覆寫後 25/40 是 P0，
根因是 40 筆裡 32 筆的 CVE 都在 KEV（輸入飽和，不是規則失效，見 ADR-day-25）。
儀表板拿 P0 計數當頭條數字會誤導讀者。
"""

from __future__ import annotations

import sys


def main() -> int:
    print("Day 28 尚未實作。資料層已就緒：uv run python app/data.py --help",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
