"""§9.6 規則覆寫（Day 25）。

藍圖 §9.6 原文三條：

> - KEV＋Internet 可達＋存在有效攻擊路徑：至少 P0。
> - 可無需既有權限通往 Crown Jewel：至少 P1。
> - 關鍵輸入缺失：標記 `REVIEW_REQUIRED`，不得僅依數字自動降級。
>
> 分數不取代人工決策。任何 P0/P1 降級都必須留下原因、核准人與有效期限。

這三條從 Day 23 起輸入就齊了，但到 Day 24 為止一條都沒實作，而且 §10 原本沒有
任何一天負責前兩條——Day 24 的一致性盤點才查出來（藍圖 §9.6 註記）。

## 只能往上，不能往下

`apply()` 永遠只把層級**推向 P0**，從不往回。這是 `UNKNOWN 不得降低風險` 的
直接延伸：覆寫規則存在的理由是「分數算漏了某件事」，而算漏只會算得太低。
一條會降級的覆寫規則，實質上是一個沒有核准人的例外。

降級只能走 `risk_acceptances.csv`——一列有原因、有具名核准人、有有效期限的紀錄。
過期的接受不是接受（與 Day 23 的豁免到期同一條紀律）。

## 「可無需既有權限」怎麼認定

**整條路徑都是網路跳，沒有任何身分邊。** 這是最窄、也是唯一證得出來的讀法：
身分邊按定義需要先持有一個帳號，不管那個帳號好不好拿。

刻意不把 Day 21 的 `SATISFIED`（權限可由服務身分取得）算進來。那種路徑確實危險，
但它危險的理由是「權限拿得到」，不是「不需要權限」——混在一起會讓這條規則說不清
自己在講什麼。那條路徑的風險已經由 Day 23 的 `A_Privilege` 項計入分數。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

# 層級由嚴重到輕；`apply()` 只往左邊推
TIER_ORDER = ("P0", "P1", "P2", "P3")

KEV_REACHABLE_PATH = "kev_reachable_path"
UNAUTHENTICATED_TO_CROWN_JEWEL = "unauthenticated_to_crown_jewel"
MISSING_CRITICAL_INPUT = "missing_critical_input"

REVIEW_REQUIRED = "REVIEW_REQUIRED"


@dataclass(frozen=True)
class Fired:
    """一次覆寫：哪一條規則、憑哪些事實、把層級從哪推到哪。"""

    rule: str
    facts: tuple[str, ...]
    was: str = ""
    now: str = ""

    @property
    def raised(self) -> bool:
        return bool(self.was) and self.was != self.now


@dataclass
class Outcome:
    tier: str
    review_required: bool = False
    fired: tuple[Fired, ...] = ()
    accepted_by: dict[str, Any] | None = None

    @property
    def rules(self) -> tuple[str, ...]:
        return tuple(f.rule for f in self.fired)


def _raise_to(current: str, floor: str) -> str:
    """把層級推到至少 `floor`。已經更嚴重就不動。"""
    if current not in TIER_ORDER:
        return floor
    return floor if TIER_ORDER.index(floor) < TIER_ORDER.index(current) else current


def effective_acceptance(rows: list[dict[str, Any]], asset: str, cve: str,
                         as_of: date) -> dict[str, Any] | None:
    """這筆 finding 現在有沒有一份算數的風險接受。

    `APPROVED` 且 `valid_until` 未過期才算。狀態欄寫 APPROVED 不等於現在有效——
    一份寫了期限卻沒有人比對的紀錄，就是一張永久赦免。
    """
    for row in rows:
        if row.get("asset") != asset or row.get("cve") != cve:
            continue
        if row.get("status") != "APPROVED":
            continue
        try:
            if date.fromisoformat(str(row.get("valid_until", ""))) >= as_of:
                return row
        except ValueError:
            continue
    return None


def apply(tier: str, *, kev_listed: bool = False, reachable: bool = False,
          has_path: bool = False, unauthenticated_jewel_path: bool = False,
          undecidable_applicability: bool = False,
          missing_inputs: tuple[str, ...] = (),
          acceptance: dict[str, Any] | None = None) -> Outcome:
    """套用 §9.6 的三條規則。只升不降。

    `acceptance` 是一份**已經確認有效**的風險接受（見 `effective_acceptance`）。
    它不會把層級降下來——降級是人的決定，這裡只負責把它記下來讓人看見，
    並且**仍然標記需要複核**：§9.6 寫的是「不得僅依數字自動降級」，
    而一份簽過的紙也不是數字可以自動執行的授權。
    """
    fired: list[Fired] = []
    result = tier

    if kev_listed and reachable and has_path:
        before = result
        result = _raise_to(result, "P0")
        fired.append(Fired(KEV_REACHABLE_PATH,
                           ("KEV 收錄", "Internet 可達", "存在有效攻擊路徑"),
                           was=before, now=result))

    if unauthenticated_jewel_path:
        before = result
        result = _raise_to(result, "P1")
        fired.append(Fired(UNAUTHENTICATED_TO_CROWN_JEWEL,
                           ("存在整條都是網路跳、通往 Crown Jewel 的路徑",),
                           was=before, now=result))

    review = False
    if undecidable_applicability or missing_inputs:
        facts = list(missing_inputs)
        if undecidable_applicability:
            facts.append("適用性證不出來")
        fired.append(Fired(MISSING_CRITICAL_INPUT, tuple(facts),
                           was=result, now=result))
        review = True

    if acceptance is not None:
        review = True

    return Outcome(tier=result, review_required=review, fired=tuple(fired),
                   accepted_by=acceptance)


def render(outcome: Outcome, tier_before: str) -> str:
    """一句話說明這筆被覆寫成什麼、憑什麼。沒有覆寫就回空字串。"""
    parts = []
    for item in outcome.fired:
        if item.rule == MISSING_CRITICAL_INPUT:
            parts.append(f"{REVIEW_REQUIRED}（{'；'.join(item.facts)}）")
        elif item.raised:
            parts.append(f"{item.was}→{item.now} 依 §9.6「{item.rule}」"
                         f"（{'、'.join(item.facts)}）")
        else:
            parts.append(f"§9.6「{item.rule}」成立，但 {tier_before} 已經更嚴重，不動")
    if outcome.accepted_by is not None:
        row = outcome.accepted_by
        parts.append(f"已接受風險 {row.get('acceptance_id')}："
                     f"{row.get('approver')} 核准至 {row.get('valid_until')}"
                     f"（{row.get('ref')}）——仍須複核，分數不取代人工決策")
    return "；".join(parts)
