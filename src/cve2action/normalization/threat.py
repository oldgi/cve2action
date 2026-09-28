"""把 EPSS 與 KEV 正規化成單一威脅輸入 T（0–1）。

兩個來源回答不同問題（Day 9、Day 10）：EPSS 預測未來 30 天遭利用的**廣度**，
KEV 記錄過去已確認的**事實**。所以**取最大值，不平均**——針對性攻擊推不高 EPSS，
但它已經發生過；把 KEV 的 1.0 跟 EPSS 的 0.02 平均掉，等於用「很少人掃」沖淡「已經被打過」。

EPSS 原始機率極度偏斜（絕大多數 CVE 貼著零），直接當 0–1 用會讓中低分全部擠在一起。
採藍圖 §9.1 的對數轉換把低端拉開：

    T_epss = ln(1 + 99p) / ln(100)

**沒有威脅資料時不補零。** 零代表「確定沒有威脅」，那是我們不知道的事。此時整個威脅項
從公式中移除、其餘權重重新正規化，並在輸出標明——不知道，不該比「確定沒什麼威脅」更低分。
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .exposure import Derived

KEV_LISTED = "LISTED"


@dataclass(frozen=True)
class ThreatRules:
    """risk_rules.yaml 的 threat 區塊。"""

    epss_log_base: float = 99.0   # ln(1 + base·p) / ln(1 + base)
    kev_listed_value: float = 1.0


def epss_to_score(probability: float, rules: ThreatRules) -> float:
    """對數轉換，把偏斜的 EPSS 機率拉成比較可比的 0–1。"""
    if not 0.0 <= probability <= 1.0:
        raise ValueError(f"EPSS probability must be within 0-1, got {probability}")
    base = rules.epss_log_base
    return math.log1p(base * probability) / math.log1p(base)


def derive_threat(epss_record, kev_entry, kev_catalog_available: bool,
                  rules: ThreatRules) -> Derived | None:
    """回傳威脅輸入與其來源；兩個來源都沒有時回 None（呼叫端據此移除威脅項）。

    `kev_entry` 為 None 且 `kev_catalog_available` 為真，代表目錄在手上但沒收錄它——
    那是明確事實（NOT_LISTED），威脅貢獻 0；目錄根本沒抓到才是不知道。
    """
    candidates: list[tuple[float, str]] = []

    if epss_record is not None and epss_record.has_score:
        score = epss_to_score(epss_record.epss, rules)
        stamp = epss_record.model_date or "?"
        candidates.append((score, f"epss:{epss_record.epss:.4f}@{stamp}"))

    if kev_catalog_available:
        if kev_entry is not None:
            candidates.append((rules.kev_listed_value, f"kev:{KEV_LISTED}@{kev_entry.date_added}"))
        else:
            candidates.append((0.0, "kev:NOT_LISTED"))

    if not candidates:
        return None

    value, source = max(candidates, key=lambda item: item[0])
    # 同時有兩個來源時，把落選的也記下來——排序理由要看得出另一邊說了什麼
    if len(candidates) > 1:
        others = "; ".join(s for v, s in candidates if s != source)
        source = f"{source} (over {others})"
    return Derived(f"{value:.4f}", source)
