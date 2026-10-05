"""適用性閘門（Day 25，藍圖 §9.0 閘門 2、成功標準 #3）。

**最便宜的處置是證明它根本不必修。** 這個模組就是那句話的實作——但它更常回答
「證不出來」，而那不是失敗，是今天的主要發現。

## 三態

| 判定 | 意思 | 後果 |
|---|---|---|
| `APPLICABLE` | 裝的版本確實落在受影響範圍內 | 照常評分、照常排隊 |
| `NOT_APPLICABLE` | **證明**它不受影響 | 離開佇列，而且要說得出憑什麼 |
| `UNDECIDABLE` | 證不出來 | **照常評分**，但標記 `REVIEW_REQUIRED` |

`UNDECIDABLE` 照常評分，是 Day 15 控制適用性、Day 21 身分前提、Day 22 查無路徑
一路下來的同一條紀律：**不能證明它不適用，就得當它適用。**

## 只有一種方式掙得 `NOT_APPLICABLE`

**產品不在受影響清單裡，而且那份清單不是空的。**

聽起來很窄，是故意的。版本比對在真實資料上會以兩種方式騙人，兩種我們都遇到了：

1. **編號體系對不上。** Exchange 裝的是 `15.2.792`，而 CPE 用 `2013`／`2016`／
   `2019` 加 CU 編號。兩邊都是數字，比得出大小，**而答案毫無意義**——
   `15.2.792` 既不等於也不大於 `2019`，純數字比對會得出「不受影響」。
   那會是一筆**假的**免修，代價是漏掉一台對外的 Exchange。
2. **空清單不是證據。** `CVE-2024-6242` 的 `configurations` 整個是空的。
   「不在清單裡」在這裡只代表清單沒東西，不代表它安全。

所以這裡**從不**用「你已經修到更新的版本了」來放行：我們的證據沒有廠商宣告的
修補版本，而從 CPE 的上界反推修補版本，跨編號體系就會出事。這條限制記在
ADR-day-25，不是沒想到，是刻意不做。

## 證據本身也要過關

- `banner` 永遠定不了案。發行版回溯修補（backport）之後，服務自報的版本不會變：
  看起來中招，其實早就修了；反過來也一樣。
- 過期的證據不得用來放行——與控制證據（Day 12）、評分門檻的豁免（Day 23）同一條。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

APPLICABLE = "APPLICABLE"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNDECIDABLE = "UNDECIDABLE"

# 查得到安裝紀錄的來源才能定案；banner 是服務自報的，manual 看日期
SETTLEABLE_SOURCES = frozenset({"package_manager", "agent_inventory",
                                "vendor_portal", "manual"})
# 與控制證據同一個天數（risk_rules.yaml 的 exposure.control_evidence_max_age_days）
DEFAULT_MAX_AGE_DAYS = 90
# CPE 裡代表「不限版本」的兩個寫法
ANY_VERSION = frozenset({"*", "-"})


@dataclass(frozen=True)
class Verdict:
    """一筆 finding 的適用性判定，連同它憑什麼。"""

    state: str
    reason: str
    evidence: dict[str, Any] | None = None

    @property
    def settled(self) -> bool:
        return self.state != UNDECIDABLE

    @property
    def leaves_queue(self) -> bool:
        return self.state == NOT_APPLICABLE


def vulnerable_cpes(cve: str, snapshot_dir: str | Path) -> list[dict[str, Any]]:
    """快照裡所有標為 vulnerable 的 CPE 比對項。查無快照回空 list。"""
    path = Path(snapshot_dir) / f"{cve.upper()}.json"
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8")).get("raw", {})
    record = raw.get("vulnerabilities", [{}])[0].get("cve", raw.get("cve", raw))
    found: list[dict[str, Any]] = []
    for config in record.get("configurations") or []:
        for node in config.get("nodes", []):
            found.extend(m for m in node.get("cpeMatch", []) if m.get("vulnerable"))
    return found


def _numeric(version: str | None) -> tuple[int, ...] | None:
    """只接受純數字的點分版本。帶字母的一律回 None——`7.4p1` 與 `17.6.6a`
    排得出直覺的順序，但那是直覺不是規則，而這裡猜錯會把該修的放掉。"""
    if not version:
        return None
    parts = version.split(".")
    if parts and all(part.isdigit() for part in parts):
        return tuple(int(part) for part in parts)
    return None


def _pad(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[tuple, tuple]:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def _within(installed: tuple[int, ...], match: dict[str, Any]) -> bool | None:
    """裝的版本在不在這一條 CPE 的範圍內。比不了回 None。"""
    declared = match["criteria"].split(":")[5]
    bounds = {
        "ge": match.get("versionStartIncluding"),
        "gt": match.get("versionStartExcluding"),
        "le": match.get("versionEndIncluding"),
        "lt": match.get("versionEndExcluding"),
    }
    if not any(bounds.values()):
        # 沒有範圍：CPE 自己那一格就是版本。`*`／`-` 代表不限版本。
        if declared in ANY_VERSION:
            return True
        exact = _numeric(declared)
        if exact is None:
            return None
        a, b = _pad(installed, exact)
        return a == b

    for key, raw_bound in bounds.items():
        if raw_bound is None:
            continue
        bound = _numeric(raw_bound)
        if bound is None:
            return None  # 邊界帶字母，比不了
        a, b = _pad(installed, bound)
        if key == "ge" and a < b:
            return False
        if key == "gt" and a <= b:
            return False
        if key == "le" and a > b:
            return False
        if key == "lt" and a >= b:
            return False
    return True


def decide(evidence: dict[str, Any] | None, matches: list[dict[str, Any]],
           as_of: date, max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> Verdict:
    """對一筆 finding 下適用性判定。

    `evidence` 是 `version_evidence.csv` 裡對應 (asset, cve) 的那一列，可為 None。
    `matches` 是該 CVE 在快照裡的 vulnerable CPE 清單。
    """
    if evidence is None:
        return Verdict(UNDECIDABLE, "沒有版本證據——不知道裝的是哪一版")

    source = str(evidence.get("source", ""))
    if source not in SETTLEABLE_SOURCES:
        return Verdict(UNDECIDABLE,
                       f"證據來源是 {source}，定不了案"
                       "（服務自報的版本在回溯修補後不會變）", evidence)

    verified = str(evidence.get("verified_at", ""))
    try:
        age = (as_of - date.fromisoformat(verified)).days
    except ValueError:
        return Verdict(UNDECIDABLE, f"證據日期讀不出來：{verified!r}", evidence)
    if age > max_age_days:
        return Verdict(UNDECIDABLE,
                       f"證據已過期（{verified}，{age} 天前）——過期的證據不得用來放行",
                       evidence)

    if not matches:
        return Verdict(UNDECIDABLE,
                       "NVD 沒有列任何受影響版本——空清單不是證據，"
                       "「不在清單裡」在這裡只代表清單沒東西", evidence)

    product = str(evidence.get("cpe_product", ""))
    listed = {m["criteria"].split(":")[4] for m in matches}
    if product not in listed:
        return Verdict(NOT_APPLICABLE,
                       f"受影響產品有 {len(listed)} 個，裝的 {product} 不在其中",
                       evidence)

    installed = _numeric(str(evidence.get("version", "")))
    if installed is None:
        return Verdict(UNDECIDABLE,
                       f"版本 {evidence.get('version')!r} 帶非數字片段，比不了",
                       evidence)

    relevant = [m for m in matches if m["criteria"].split(":")[4] == product]
    unreadable = 0
    for match in relevant:
        verdict = _within(installed, match)
        if verdict is None:
            unreadable += 1
        elif verdict:
            return Verdict(APPLICABLE,
                           f"{product} {evidence.get('version')} 落在受影響範圍內",
                           evidence)
    if unreadable:
        return Verdict(UNDECIDABLE,
                       f"{product} 有 {unreadable}/{len(relevant)} 條範圍帶非數字邊界，"
                       "比不了", evidence)
    # 全部比完都沒命中。**仍然不放行**——見模組開頭：
    # 編號體系對不上時，純數字比對會得出一個有大小、沒意義的答案。
    return Verdict(UNDECIDABLE,
                   f"{product} 的 {len(relevant)} 條範圍都沒命中 "
                   f"{evidence.get('version')}，但沒命中不等於不受影響"
                   "（編號體系可能根本不同）", evidence)
