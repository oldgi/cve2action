"""候選措施引擎（Day 26）：Patch、隔離、關閉服務，哪一個先做？

## 「哪一個先做」其實是兩個問題

| 問題 | 答案要的是 |
|---|---|
| **先做**哪一個？ | 最快把風險壓下來、而且不用等人簽核的那一個 |
| 哪一個能**結案**？ | 做完之後弱掃不再報、finding 可以關掉的那一個 |

兩者常常不是同一個。關掉 WebUI 一小時、零停機，但漏洞還在；patch 要排窗口，
但做完才算數。藍圖 §20.1 早就寫了：**完成緩解不等於已完成修補。**
把兩件事壓成一個「建議措施」，緩解做完那天 finding 就會被當成結案。

## 每項措施都有成本與限制（當日驗收）

- **成本**：工時與停機分鐘，讀自 `remediations.csv`。讀不到就是 `None`——
  **不是 0**。§20.3 Day 18：不能因不知道修補成本就填成零。
- **限制**：`compatibility` 不是 `none` 的，都要有人簽核才能動。
  停機 0 分鐘不代表沒有代價：MOVEit 的隔離不停機，但會斷掉合作夥伴的上傳。
- **做完之後**：三態，沿用整個系列的紀律——

  | 結果 | 動作 | 為什麼 |
  |---|---|---|
  | `CLOSES` | patch | 版本變了，弱掃不再報 |
  | `RESCAN_REQUIRED` | config_change | 版本沒變；停 RC4 會消失、開 NLA 不會。**重掃前不算結案** |
  | `STAYS_OPEN` | isolate／disable_service／compensating_control | 漏洞還在，只是走不到或被攔著 |

## 補償控制要先過番外篇二的那道閘

補償控制只有在「這類控制攔得到這類弱點」時才是選項。判斷直接沿用
`normalization.control.applicability`——兩條軸線（AV/PR 與 CWE）、同一套三態：

- `NOT_APPLICABLE` → **憑證據否決**，這個候選不提供。
- `UNDECIDABLE` → **沉默不否決**，照樣列出，但標記效果待證、不優先選它。
- `APPLICABLE` → 可以選。即使可以，它在驗證之前也降不了分——那是 Day 12 的規則，
  分數只認有 `verified_at` 的控制。

控制類型取自 `controls.csv` 裡同一台資產登記的控制。資產上一個控制都沒登記，
就無從得知「補償控制」指的是哪一種——那是 `UNDECIDABLE`，不是 `APPLICABLE`。
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from ..normalization.control import (
    APPLICABLE,
    NOT_APPLICABLE,
    UNDECIDABLE,
    applicability,
    parse_attack,
)
from .treatment import ACTION_ORDER, Treatment

CLOSES = "CLOSES"
RESCAN_REQUIRED = "RESCAN_REQUIRED"
STAYS_OPEN = "STAYS_OPEN"

CLOSURE = {
    "patch": CLOSES,
    "config_change": RESCAN_REQUIRED,
    "isolate": STAYS_OPEN,
    "disable_service": STAYS_OPEN,
    "compensating_control": STAYS_OPEN,
}

# 一筆 finding 的規劃狀態
PLANNED = "PLANNED"
NO_CANDIDATE = "NO_CANDIDATE"
MOOT = "MOOT"  # 已證明不必修，登記的做法用不到


class CandidateError(ValueError):
    """處置方案清冊的內容無法解讀。"""


def _number(raw: Any) -> float | None:
    """空白或讀不懂的成本回 None。None 的意思是「不知道」，不是「免費」。"""
    text = str(raw if raw is not None else "").strip()
    if not text:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if value >= 0 else None


@dataclass(frozen=True)
class Candidate:
    remediation_id: str
    asset: str
    cve: str
    action: str
    effort_hours: float | None
    downtime_minutes: float | None
    constraint: str
    closure: str
    effect: str = APPLICABLE
    effect_reason: str = ""
    notes: str = ""

    @property
    def cost_known(self) -> bool:
        return self.effort_hours is not None and self.downtime_minutes is not None

    @property
    def needs_signoff(self) -> bool:
        return bool(self.constraint)

    @property
    def rejected(self) -> bool:
        """憑證據否決：這類控制攔不到這類弱點。"""
        return self.effect == NOT_APPLICABLE

    def sort_key(self) -> tuple:
        """先做的順序：不用簽核 > 效果有據 > 成本已知 > 停機少 > 工時少。

        成本不明的排最後，而不是排最前——把不知道當成零，它就會永遠第一個被選。
        """
        return (
            self.needs_signoff,
            self.effect == UNDECIDABLE,
            not self.cost_known,
            self.downtime_minutes if self.downtime_minutes is not None else math.inf,
            self.effort_hours if self.effort_hours is not None else math.inf,
            ACTION_ORDER.index(self.action),
        )

    def label(self) -> str:
        hours = "?" if self.effort_hours is None else f"{self.effort_hours:g}h"
        down = "?" if self.downtime_minutes is None else f"{self.downtime_minutes:g}m"
        extra = f"，{self.constraint}" if self.constraint else ""
        return f"{self.action}（{hours}／停機 {down}{extra}）"


@dataclass(frozen=True)
class Plan:
    asset: str
    cve: str
    tier: str
    status: str
    candidates: tuple[Candidate, ...] = ()
    first: Candidate | None = None
    close: Candidate | None = None

    @property
    def offered(self) -> tuple[Candidate, ...]:
        return tuple(c for c in self.candidates if not c.rejected)

    @property
    def first_is_not_close(self) -> bool:
        """有能結案的做法，但先做的不是它——緩解先上、修補排窗口。"""
        return self.first is not None and self.close is not None and self.first is not self.close

    @property
    def closure(self) -> str:
        """這筆 finding 走完所有候選之後，最好能到哪裡。"""
        if self.close is not None:
            return CLOSES
        if any(c.closure == RESCAN_REQUIRED for c in self.offered):
            return RESCAN_REQUIRED
        return STAYS_OPEN


@dataclass(frozen=True)
class Weakness:
    """判斷補償控制適用性需要的弱點特徵（讀自 NVD 快照）。"""

    vector: str | None = None
    cwes: tuple[str, ...] = ()


def _control_effect(asset: str, weakness: Weakness, controls: list[dict],
                    control_rules) -> tuple[str, str]:
    kinds = sorted({str(c.get("control_type", "")).strip().lower()
                    for c in controls if c.get("asset_id") == asset} - {""})
    if not kinds:
        return UNDECIDABLE, "資產上沒有登記任何控制，無從判斷補償的是哪一種"
    attack = parse_attack(weakness.vector)
    verdicts = [(kind, *applicability(kind, attack, control_rules, weakness.cwes))
                for kind in kinds]
    for kind, state, why in verdicts:
        if state == APPLICABLE:
            return APPLICABLE, f"{kind}: {why}"
    if all(state == NOT_APPLICABLE for _kind, state, _why in verdicts):
        return NOT_APPLICABLE, "; ".join(f"{k}: {w}" for k, _s, w in verdicts)
    return UNDECIDABLE, "; ".join(f"{k}: {w}" for k, _s, w in verdicts)


def build_candidates(remediations: list[dict], weaknesses: dict[str, Weakness],
                     controls: list[dict], control_rules) -> list[Candidate]:
    """把清冊的每一列變成一個候選措施。看不懂的動作要出聲，不要安靜地略過。"""
    out: list[Candidate] = []
    for row in remediations:
        action = str(row.get("action", "")).strip()
        if action not in CLOSURE:
            raise CandidateError(
                f"{row.get('remediation_id')}: unknown action {action!r}; "
                f"allowed {sorted(CLOSURE)}")
        asset, cve = str(row.get("asset", "")), str(row.get("cve", "")).upper()
        constraint = str(row.get("compatibility", "")).strip()
        effect, why = APPLICABLE, ""
        if action == "compensating_control":
            effect, why = _control_effect(asset, weaknesses.get(cve, Weakness()),
                                          controls, control_rules)
        out.append(Candidate(
            remediation_id=str(row.get("remediation_id", "")), asset=asset, cve=cve,
            action=action,
            effort_hours=_number(row.get("effort_hours")),
            downtime_minutes=_number(row.get("downtime_minutes")),
            constraint="" if constraint.lower() in ("", "none") else constraint,
            closure=CLOSURE[action], effect=effect, effect_reason=why,
            notes=str(row.get("notes", "")),
        ))
    return out


def plan(treatment: Treatment, candidates: list[Candidate]) -> Plan:
    mine = tuple(sorted((c for c in candidates
                         if c.asset == treatment.asset and c.cve == treatment.cve.upper()),
                        key=Candidate.sort_key))
    if treatment.leaves_queue:
        return Plan(treatment.asset, treatment.cve, "", MOOT, mine)
    offered = [c for c in mine if not c.rejected]
    if not offered:
        return Plan(treatment.asset, treatment.cve, treatment.tier, NO_CANDIDATE, mine)
    closers = [c for c in offered if c.closure == CLOSES]
    return Plan(treatment.asset, treatment.cve, treatment.tier, PLANNED, mine,
                first=offered[0], close=closers[0] if closers else None)


def plan_all(treatments: list[Treatment], candidates: list[Candidate]) -> list[Plan]:
    from .overrides import TIER_ORDER

    rank = {tier: i for i, tier in enumerate(TIER_ORDER)}
    plans = [plan(t, candidates) for t in treatments]
    return sorted(plans, key=lambda p: (rank.get(p.tier, len(rank)), p.asset, p.cve))


def _sum(values: list[float | None]) -> str:
    known = [v for v in values if v is not None]
    total = f"{sum(known):g}"
    return total if len(known) == len(values) else f"{total}＋未知 {len(values) - len(known)} 項"


def report(plans: list[Plan]) -> str:
    planned = [p for p in plans if p.status == PLANNED]
    empty = [p for p in plans if p.status == NO_CANDIDATE]
    moot = [p for p in plans if p.status == MOOT and p.candidates]
    every = [c for p in plans for c in p.candidates]

    lines = [f"候選措施（{len(every)} 項，對應 {sum(1 for p in plans if p.candidates)} 筆 finding；"
             f"共 {len(plans)} 筆）", ""]
    lines.append(f"  {'層級':<4}{'資產':<22}{'CVE':<16}先做 → 結案")
    for item in planned:
        first = item.first.label() if item.first else "—"
        if item.close is None:
            close = "（待重掃）" if item.closure == RESCAN_REQUIRED else "（沒有能結案的做法）"
        elif item.close is item.first:
            close = "同一項"
        else:
            close = item.close.label()
        lines.append(f"  {item.tier:<6}{item.asset:<22}{item.cve:<16}{first} → {close}")
        for cand in item.candidates:
            if cand.effect != APPLICABLE:
                lines.append(f"  {'':<44}└ {cand.remediation_id} 補償控制 "
                             f"{cand.effect}：{cand.effect_reason}")

    comp = [c for c in every if c.action == "compensating_control"]
    lines.append("")
    lines.append(f"  先做與結案不是同一項　{sum(p.first_is_not_close for p in planned):>3} 筆")
    signoff = sum(bool(p.first and p.first.needs_signoff) for p in planned)
    lines.append(f"  先做的那一項要人簽核　{signoff:>3} 筆")
    lines.append(f"  做完仍無法結案　　　　{sum(p.closure == STAYS_OPEN for p in planned):>3} 筆"
                 f"　＋待重掃 {sum(p.closure == RESCAN_REQUIRED for p in planned)} 筆")
    lines.append(f"  補償控制　適用 {sum(c.effect == APPLICABLE for c in comp)}"
                 f"／否決 {sum(c.effect == NOT_APPLICABLE for c in comp)}"
                 f"／無從判斷 {sum(c.effect == UNDECIDABLE for c in comp)}")
    firsts = [p.first for p in planned if p.first]
    lines.append(f"  只做「先做」：工時 {_sum([c.effort_hours for c in firsts])} h，"
                 f"停機 {_sum([c.downtime_minutes for c in firsts])} 分鐘")
    lines.append("")
    for item in moot:
        for cand in item.candidates:
            lines.append(f"  已證明不必修、卻登記了做法：{item.asset} {item.cve} "
                         f"{cand.remediation_id} {cand.label()}")
    lines.append(f"  一個候選都沒有的：{len(empty)} 筆——成本是「不知道」，不是 0；"
                 "不進任何成本比較")
    return "\n".join(lines)
