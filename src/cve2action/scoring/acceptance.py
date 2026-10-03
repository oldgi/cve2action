"""評分門檻：把「可用」變成量得出來的條件。

門檻分兩種，混在一起就會誤判：

- **structural**：公式本身的性質，用合成探針驗證，與任何資料集無關。
  「四個分級都構造得出來嗎」是這一類。
- **empirical**：在某個資料集上量出來的。「這份掃描結果裡 High 佔幾成」是這一類，
  換一份資料就會變。

這個區分不是潔癖。從 Day 11 到 Day 17，我一直把「Northstar 產不出 Low」寫成
「v0.1 公式產不出 Low」——前者是資料集的事實，後者是對公式的指控，而後者是錯的。
合成探針花十行就能拆穿這個誤會，我拖了七天。

沒過不一定要修。沒過而且沒有 waiver，exit 1；沒過但有 waiver，要寫清楚根因與
重新量測的日子。**選擇不修是決定，不是忽略。**
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..models import DECISION_SCORED

STRUCTURAL = "structural"
EMPIRICAL = "empirical"
AT_MOST = "at_most"


class AcceptanceError(ValueError):
    """門檻設定檔不符合規格。"""


@dataclass(frozen=True)
class Check:
    id: str
    kind: str
    description: str
    passed: bool
    measured: Any
    threshold: Any
    detail: str = ""
    waiver: dict[str, Any] | None = None

    @property
    def waived(self) -> bool:
        return not self.passed and self.waiver is not None

    @property
    def blocking(self) -> bool:
        return not self.passed and self.waiver is None

    @property
    def status(self) -> str:
        if self.passed:
            return "PASS"
        return "WAIVED" if self.waived else "FAIL"


@dataclass(frozen=True)
class Acceptance:
    checks: tuple[Check, ...]
    rules_version: str

    @property
    def blocking(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.blocking)

    @property
    def waived(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if c.waived)

    @property
    def accepted(self) -> bool:
        return not self.blocking


def load_criteria(path: str | Path) -> dict[str, Any]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("criteria"), list):
        raise AcceptanceError(f"{path}: missing 'criteria' list")
    seen = set()
    for entry in raw["criteria"]:
        for field in ("id", "kind", "description", "threshold"):
            if field not in entry:
                raise AcceptanceError(f"{path}: criterion missing '{field}': {entry}")
        if entry["kind"] not in (STRUCTURAL, EMPIRICAL):
            raise AcceptanceError(f"{path}: unknown kind {entry['kind']!r}")
        if entry["id"] in seen:
            raise AcceptanceError(f"{path}: duplicate criterion id {entry['id']!r}")
        seen.add(entry["id"])
    for waiver in raw.get("waivers") or []:
        if waiver.get("id") not in seen:
            raise AcceptanceError(f"{path}: waiver for unknown criterion {waiver.get('id')!r}")
        for field in ("reason", "revisit_on"):
            if not str(waiver.get(field, "")).strip():
                raise AcceptanceError(
                    f"{path}: waiver {waiver.get('id')!r} needs a '{field}'——"
                    "不修可以，不寫為什麼不行"
                )
    return raw


# --- structural 探針 ---------------------------------------------------------

def _probe(rules, cvss: float, reach: str, control: str, business: str) -> dict:
    from .engine import score_finding

    return score_finding(
        {"asset": "PROBE", "cve": "CVE-0000-0001", "cvss": cvss},
        {"environment": "NON_PROD", "reachability": reach,
         "control_effectiveness": control, "business_criticality": business},
        rules,
    )


def _check_bands_reachable(rules) -> tuple[bool, Any, str]:
    """每個分級都要構造得出來。用合成探針掃值域四個角落與中間的 CVSS。"""
    found: dict[str, str] = {}
    cvss_steps = [round(x * 0.5, 1) for x in range(0, 21)]
    for reach in rules.reachability:
        for control in rules.control_effectiveness:
            for business in rules.business_criticality:
                for cvss in cvss_steps:
                    row = _probe(rules, cvss, reach, control, business)
                    found.setdefault(row["priority"],
                                     f"CVSS {cvss} / {reach} / {control} / {business}")
    labels = {band.label for band in rules.priority_bands}
    missing = sorted(labels - set(found))
    detail = "; ".join(f"{band}←{example}" for band, example in sorted(found.items()))
    return not missing, sorted(found), (f"構造不出 {missing}" if missing else detail)


def _check_degradation_safe(rules) -> tuple[bool, Any, str]:
    """UNKNOWN 不得比 NONE 安全；缺威脅資料不得讓分數低於有資料的下界。"""
    problems = []
    for reach in rules.reachability:
        for business in rules.business_criticality:
            unknown = _probe(rules, 9.8, reach, "UNKNOWN", business)["priority_score"]
            none = _probe(rules, 9.8, reach, "NONE", business)["priority_score"]
            if unknown < none:
                problems.append(f"UNKNOWN<{none} at {reach}/{business}")
    # 無威脅資料時權重退回 severity，分數不得低於威脅為 0 時的假想值
    degraded = _probe(rules, 9.8, "INTERNET", "NONE", "CRITICAL")["priority_score"]
    pretend_zero = round(10 * (rules.weights["severity"] * 0.98
                               + rules.weights["exposure"] * 1.0
                               + rules.weights["business"] * 1.0), 2)
    if degraded < pretend_zero:
        problems.append(f"缺威脅資料 {degraded} < 補零 {pretend_zero}")
    return not problems, len(problems), "; ".join(problems) or "缺資料從不換來較低的分數"


def _check_monotonic(rules) -> tuple[bool, Any, str]:
    """任一因子單獨變大，分數不得下降。"""
    problems = []
    order_reach = sorted(rules.reachability, key=lambda k: rules.reachability[k])
    order_business = sorted(rules.business_criticality,
                            key=lambda k: rules.business_criticality[k])
    for lower, higher in zip(order_reach, order_reach[1:], strict=False):
        a = _probe(rules, 7.0, lower, "NONE", "NORMAL")["priority_score"]
        b = _probe(rules, 7.0, higher, "NONE", "NORMAL")["priority_score"]
        if b < a:
            problems.append(f"reachability {lower}→{higher} 分數下降")
    for lower, higher in zip(order_business, order_business[1:], strict=False):
        a = _probe(rules, 7.0, "INTERNAL", "NONE", lower)["priority_score"]
        b = _probe(rules, 7.0, "INTERNAL", "NONE", higher)["priority_score"]
        if b < a:
            problems.append(f"business {lower}→{higher} 分數下降")
    for low, high in ((3.0, 4.0), (7.0, 8.0), (9.0, 9.8)):
        a = _probe(rules, low, "INTERNAL", "NONE", "NORMAL")["priority_score"]
        b = _probe(rules, high, "INTERNAL", "NONE", "NORMAL")["priority_score"]
        if b < a:
            problems.append(f"cvss {low}→{high} 分數下降")
    return not problems, len(problems), "; ".join(problems) or "四個因子都單調不遞減"


# --- empirical 量測 ----------------------------------------------------------

def _scored(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("decision") == DECISION_SCORED]


def _measure(rows: list[dict], explanations) -> dict[str, tuple[float, str]]:
    scored = _scored(rows)
    total = len(scored)
    if not total:
        return {}
    scores = [float(r["priority_score"]) for r in scored]
    distinct = len(set(scores))
    bands: dict[str, int] = {}
    for row in scored:
        bands[row["priority"]] = bands.get(row["priority"], 0) + 1
    biggest = max(bands.items(), key=lambda kv: kv[1])
    span = max(scores) - min(scores)
    ceiling = sum(1 for s in scores if s >= 10.0)

    complete = sum(
        1 for e in explanations
        if e.decision == DECISION_SCORED and len(e.factors) >= 3
        and all(f.source for f in e.factors)
    )
    return {
        "explainable": (round(complete / total, 4), f"{complete}/{total} 筆有完整分解與來源"),
        "discrimination": (round(distinct / total, 4), f"{distinct} 個相異分數 / {total} 筆"),
        "band_balance": (round(biggest[1] / total, 4),
                         f"最大分級 {biggest[0]} {biggest[1]}/{total}"),
        "range_coverage": (round(span / 10.0, 4),
                           f"{min(scores):g}–{max(scores):g}，跨距 {span:.2f}"),
        "ceiling_saturation": (round(ceiling / total, 4), f"{ceiling}/{total} 撞到 10.0"),
    }


STRUCTURAL_CHECKS = {
    "bands_reachable": _check_bands_reachable,
    "degradation_safe": _check_degradation_safe,
    "monotonic": _check_monotonic,
}


def evaluate(criteria: dict[str, Any], rules, rows: list[dict], explanations) -> Acceptance:
    waivers = {w["id"]: w for w in (criteria.get("waivers") or [])}
    measured = _measure(rows, explanations)
    checks: list[Check] = []

    for entry in criteria["criteria"]:
        cid, kind = entry["id"], entry["kind"]
        if kind == STRUCTURAL:
            probe = STRUCTURAL_CHECKS.get(cid)
            if probe is None:
                raise AcceptanceError(f"structural criterion {cid!r} has no probe implemented")
            passed, value, detail = probe(rules)
        else:
            if cid not in measured:
                raise AcceptanceError(f"empirical criterion {cid!r} has no measurement")
            value, detail = measured[cid]
            threshold = float(entry["threshold"])
            passed = (value <= threshold if entry.get("direction") == AT_MOST
                      else value >= threshold)
        checks.append(Check(
            id=cid, kind=kind, description=entry["description"], passed=passed,
            measured=value, threshold=entry["threshold"], detail=detail,
            waiver=None if passed else waivers.get(cid),
        ))
    return Acceptance(tuple(checks), str(criteria.get("applies_to_rules_version", "")))


def report(acceptance: Acceptance) -> str:
    lines = [f"評分門檻（rules {acceptance.rules_version}）", ""]
    for check in acceptance.checks:
        measured = (f"{check.measured:g}" if isinstance(check.measured, float)
                    else str(check.measured))
        lines.append(f"  [{check.status:<6}] {check.id:<20} {measured:>8}  "
                     f"(門檻 {check.threshold})")
        lines.append(f"            {check.description}")
        if check.detail:
            lines.append(f"            實測：{check.detail}")
        if check.waived:
            lines.append(f"            豁免至 {check.waiver['revisit_on']}："
                         f"{' '.join(check.waiver['reason'].split())[:80]}…")
        lines.append("")
    passed = sum(1 for c in acceptance.checks if c.passed)
    lines.append(f"通過 {passed}/{len(acceptance.checks)}；"
                 f"豁免 {len(acceptance.waived)}；阻擋 {len(acceptance.blocking)}")
    if acceptance.accepted:
        lines.append("v0.1 評分門檻：**通過**（含上述豁免，根因與重新量測日期已記錄）")
    else:
        lines.append("v0.1 評分門檻：**未通過** —— 下列條件沒過也沒有 waiver：")
        for check in acceptance.blocking:
            lines.append(f"  - {check.id}")
    return "\n".join(lines)
