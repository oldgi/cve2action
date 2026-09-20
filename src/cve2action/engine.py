"""Decision Engine v0.1：確定性評分，逐筆附理由。

S = CVSS / 10
E = Reachability × Control Effectiveness（Effective Exposure）
B = Business Impact
Priority Score = 10 × (wS×S + wE×E + wB×B)

缺少必要 context 或值不在值域 → decision = NEEDS_CONTEXT，不評分、不猜預設值。
"""

from __future__ import annotations

from typing import Any

from .models import DECISION_NEEDS_CONTEXT, DECISION_SCORED, RiskRules


def _missing(value: Any) -> bool:
    return value is None or str(value).strip() == ""


def _gap(field: str, value: Any, allowed: dict[str, float] | None = None) -> str:
    if _missing(value):
        return f"missing {field}"
    if allowed is not None:
        return f"{field}='{value}' not in {sorted(allowed)}"
    return f"invalid {field}='{value}'"


def score_finding(
    finding: dict[str, Any],
    context: dict[str, Any] | None,
    rules: RiskRules,
) -> dict[str, Any]:
    """對單筆 finding 評分；回傳 ranked_result 的一列（dict）。"""
    row: dict[str, Any] = {
        "asset": finding.get("asset"),
        "cve": finding.get("cve"),
        "cvss": finding.get("cvss"),
        "environment": "",
        "effective_exposure": "",
        "business_criticality": "",
        "priority_score": "",
        "priority": "",
    }
    gaps: list[str] = []

    cvss: float | None = None
    if _missing(finding.get("cvss")):
        gaps.append("missing cvss")
    else:
        try:
            cvss = float(finding["cvss"])
        except (TypeError, ValueError):
            cvss = None
        if cvss is None or not 0.0 <= cvss <= 10.0:
            gaps.append(f"cvss='{finding['cvss']}' not a number within 0–10")
            cvss = None

    if context is None:
        gaps.append("asset not found in asset_context")
        reach_value = control_value = business_value = None
    else:
        row["environment"] = context.get("environment") or ""
        reach = context.get("reachability")
        control = context.get("control_effectiveness")
        business = context.get("business_criticality")

        reach_value = rules.reachability.get(str(reach)) if not _missing(reach) else None
        if reach_value is None:
            gaps.append(_gap("reachability", reach, rules.reachability))

        control_value = (
            rules.control_effectiveness.get(str(control)) if not _missing(control) else None
        )
        if control_value is None:
            gaps.append(_gap("control_effectiveness", control, rules.control_effectiveness))

        business_value = (
            rules.business_criticality.get(str(business)) if not _missing(business) else None
        )
        if business_value is None:
            gaps.append(_gap("business_criticality", business, rules.business_criticality))
        else:
            row["business_criticality"] = str(business)

    if gaps:
        row["decision"] = DECISION_NEEDS_CONTEXT
        row["reason"] = "needs context: " + "; ".join(gaps)
        return row

    assert cvss is not None and reach_value is not None
    assert control_value is not None and business_value is not None
    severity = cvss / 10.0
    exposure = round(reach_value * control_value, 4)
    weights = rules.weights
    score = round(
        10.0
        * (
            weights["severity"] * severity
            + weights["exposure"] * exposure
            + weights["business"] * business_value
        ),
        2,
    )

    row["effective_exposure"] = exposure
    row["priority_score"] = score
    row["priority"] = rules.band_for(score)
    row["decision"] = DECISION_SCORED
    row["reason"] = (
        f"CVSS {cvss:g} (S={severity:g}); "
        f"{context['reachability']} x {context['control_effectiveness']} -> E={exposure:g}; "
        f"{context['business_criticality']} -> B={business_value:g}; "
        f"score=10x({weights['severity']:g}xS+{weights['exposure']:g}xE"
        f"+{weights['business']:g}xB)={score:g} [{row['priority']}]"
    )
    return row


def rank(
    findings: list[dict[str, Any]],
    contexts: dict[str, dict[str, Any]],
    rules: RiskRules,
) -> list[dict[str, Any]]:
    """全部評分後排序：SCORED 依分數降冪在前，NEEDS_CONTEXT 保留在最後。"""
    rows = [score_finding(f, contexts.get(str(f.get("asset"))), rules) for f in findings]
    scored = [r for r in rows if r["decision"] == DECISION_SCORED]
    needs_context = [r for r in rows if r["decision"] == DECISION_NEEDS_CONTEXT]
    scored.sort(key=lambda r: r["priority_score"], reverse=True)
    return scored + needs_context
