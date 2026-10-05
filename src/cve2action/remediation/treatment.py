"""處置結果（Day 25）：把適用性、§9.6 覆寫與可用措施合成一筆結論。

## 為什麼不是改 `rank`

`ranked_result.csv` 的欄位是 Day 6 以來的契約，而 Day 11–24 每一篇文章引用的數字
都從它來。把 `NOT_APPLICABLE` 塞進 `decision` 欄，等於讓已發表的分布數字全部改口。

所以處置是**另一個投影**：同一份 `Explanation`，換一個問題去問它。
Day 16 立的規矩是「理由是計分的投影」，這裡只是多一個投影，不是多一套計算。

## 一筆處置結論長什麼樣

| 欄位 | 答什麼 |
|---|---|
| `applicability` | 要不要修（`APPLICABLE`／`NOT_APPLICABLE`／`UNDECIDABLE`） |
| `tier` | 多急（§9.6 覆寫**之後**的層級） |
| `review_required` | 能不能照數字自動走 |
| `options` | 有哪些做法（patch、補償控制、隔離、關服務） |

四個問題是獨立的。一筆可以同時是「證不出來適用不適用」「被覆寫成 P0」
「有兩個處置選項」——那不矛盾，那是現實。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from . import overrides
from .applicability import NOT_APPLICABLE, UNDECIDABLE, Verdict, decide, vulnerable_cpes

# 處置動作，由便宜到貴。「證明不必修」不在這裡——它根本不是一種動作。
ACTION_ORDER = ("config_change", "compensating_control", "disable_service",
                "isolate", "patch")


@dataclass
class Treatment:
    asset: str
    cve: str
    applicability: str
    applicability_reason: str
    tier: str
    tier_before: str
    review_required: bool
    override_note: str = ""
    options: tuple[str, ...] = ()
    fired: tuple[str, ...] = ()
    accepted_by: str = ""

    @property
    def leaves_queue(self) -> bool:
        return self.applicability == NOT_APPLICABLE

    @property
    def actionable(self) -> bool:
        """要做事，而且知道可以做什麼。"""
        return not self.leaves_queue and bool(self.options)

    @property
    def stuck(self) -> bool:
        """要做事，但清冊裡一個做法都沒有。"""
        return not self.leaves_queue and not self.options


@dataclass
class Facts:
    """算一筆處置需要、但不屬於 Explanation 的外部事實。"""

    kev: frozenset[str] = frozenset()
    reachable: frozenset[str] = frozenset()
    has_path: frozenset[str] = frozenset()
    unauthenticated_jewel: frozenset[str] = frozenset()
    evidence: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    acceptances: list[dict[str, Any]] = field(default_factory=list)
    remediations: list[dict[str, Any]] = field(default_factory=list)


def _options(facts: Facts, asset: str, cve: str) -> tuple[str, ...]:
    actions = {r["action"] for r in facts.remediations
               if r.get("asset") == asset and r.get("cve") == cve}
    return tuple(a for a in ACTION_ORDER if a in actions)


def treat(explanation, facts: Facts, snapshot_dir: str, as_of: date) -> Treatment:
    """對一筆 finding 產出處置結論。"""
    asset, cve = explanation.asset, explanation.cve
    verdict: Verdict = decide(facts.evidence.get((asset, cve)),
                              vulnerable_cpes(cve, snapshot_dir), as_of)

    tier_before = explanation.tier or ""

    if verdict.state == NOT_APPLICABLE:
        # 已經證明不必修的，不進覆寫。§9.6 的規則是在排「該做的事」的先後，
        # 而一件不必做的事沒有先後可言——把它推成 P0 是把閘門的結論丟掉。
        return Treatment(
            asset=asset, cve=cve, applicability=verdict.state,
            applicability_reason=verdict.reason, tier="", tier_before=tier_before,
            review_required=False,
            override_note="已證明不適用，不進 §9.6 覆寫",
            options=(), fired=(), accepted_by="")

    missing: list[str] = []
    if not explanation.scored:
        missing.append("缺資產脈絡，無法評分")
    if explanation.degraded:
        missing.append("沒有威脅資料")

    accepted = overrides.effective_acceptance(facts.acceptances, asset, cve, as_of)
    outcome = overrides.apply(
        tier_before,
        kev_listed=cve.upper() in facts.kev,
        reachable=asset in facts.reachable,
        has_path=asset in facts.has_path,
        unauthenticated_jewel_path=asset in facts.unauthenticated_jewel,
        undecidable_applicability=verdict.state == UNDECIDABLE,
        missing_inputs=tuple(missing),
        acceptance=accepted,
    )

    return Treatment(
        asset=asset, cve=cve,
        applicability=verdict.state, applicability_reason=verdict.reason,
        tier=outcome.tier, tier_before=tier_before,
        review_required=outcome.review_required,
        override_note=overrides.render(outcome, tier_before),
        options=_options(facts, asset, cve),
        fired=outcome.rules,
        accepted_by=str(accepted.get("acceptance_id")) if accepted else "",
    )


def report(treatments: list[Treatment]) -> str:
    """處置視圖。先講能省下多少工，再講省不下來的為什麼省不下來。"""
    total = len(treatments)
    dropped = [t for t in treatments if t.leaves_queue]
    undecided = [t for t in treatments if t.applicability == UNDECIDABLE]
    stuck = [t for t in treatments if t.stuck]
    review = [t for t in treatments if t.review_required]

    lines = [f"處置結果（{total} 筆）", ""]
    lines.append(f"  證明不必修　{len(dropped):>3} 筆　——唯一真正省下來的工")
    lines.append(f"  適用，要修　{total - len(dropped) - len(undecided):>3} 筆")
    lines.append(f"  證不出來　　{len(undecided):>3} 筆　——照常評分，標記待複核")
    lines.append("")
    for item in dropped:
        lines.append(f"  [NOT_APPLICABLE] {item.asset} {item.cve}")
        lines.append(f"      {item.applicability_reason}")

    if undecided:
        reasons: dict[str, int] = {}
        for item in undecided:
            head = item.applicability_reason.split("——")[0].split("（")[0]
            reasons[head] = reasons.get(head, 0) + 1
        lines.append("")
        lines.append("  證不出來的理由：")
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            lines.append(f"      {count:>3} 筆　{reason}")

    fired: dict[str, int] = {}
    raised = 0
    for item in treatments:
        for rule in item.fired:
            fired[rule] = fired.get(rule, 0) + 1
        if item.tier != item.tier_before and item.tier_before:
            raised += 1
    lines.append("")
    lines.append(f"  §9.6 覆寫：{raised} 筆層級被推上去；待複核 {len(review)} 筆")
    for rule, count in sorted(fired.items(), key=lambda kv: -kv[1]):
        lines.append(f"      {count:>3} 筆　{rule}")

    accepted = [t for t in treatments if t.accepted_by]
    if accepted:
        lines.append("")
        lines.append(f"  有效的風險接受 {len(accepted)} 筆（仍須複核，分數不取代人工決策）：")
        for item in accepted:
            lines.append(f"      {item.asset} {item.cve} ← {item.accepted_by}")

    lines.append("")
    lines.append(f"  清冊裡一個做法都沒有的：{len(stuck)} 筆")
    lines.append("  「修漏洞不是唯一選項」的前提是**選項要存在**；"
                 "沒有登記任何處置方案，不等於只能修，是我們還沒想過。")
    return "\n".join(lines)
