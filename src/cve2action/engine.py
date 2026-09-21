"""Decision Engine v0.1：確定性評分，逐筆附理由。

S = CVSS / 10
E = Reachability × Control Effectiveness（Effective Exposure）
B = Business Impact
Priority Score = 10 × (wS×S + wE×E + wB×B)

缺少必要 context 或值不在值域 → decision = NEEDS_CONTEXT，不評分、不猜預設值。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import DECISION_NEEDS_CONTEXT, DECISION_SCORED, RiskRules

if TYPE_CHECKING:
    from .collectors.nvd import CveRecord


def _missing(value: Any) -> bool:
    return value is None or str(value).strip() == ""


def _gap(field: str, value: Any, allowed: dict[str, float] | None = None) -> str:
    if _missing(value):
        return f"missing {field}"
    if allowed is not None:
        return f"{field}='{value}' not in {sorted(allowed)}"
    return f"invalid {field}='{value}'"


def _scanner_cvss(finding: dict[str, Any]) -> tuple[float | None, str | None]:
    """掃描器手填的 CVSS → (值, 錯誤說明)。空白不算錯誤，回 (None, None)。"""
    raw = finding.get("cvss")
    if _missing(raw):
        return None, None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None, f"cvss='{raw}' not a number within 0–10"
    if not 0.0 <= value <= 10.0:
        return None, f"cvss='{raw}' not a number within 0–10"
    return value, None


def _resolve_cvss(
    finding: dict[str, Any], snapshot: CveRecord | None, rules: RiskRules
) -> tuple[float | None, str, str, str | None, str]:
    """決定這一列用哪個 CVSS：有來源的快照分數優先於掃描器手填值。

    回傳 (score, version, source, gap, note)。gap 非 None 代表 NEEDS_CONTEXT；
    note 是給 reason 的補充，例如掃描器與 NVD 不一致。
    """
    scanner_value, scanner_error = _scanner_cvss(finding)
    if snapshot is not None:
        chosen = snapshot.cvss.preferred(rules.cvss_version_preference)
        if chosen is not None:
            note = ""
            if scanner_value is not None and scanner_value != chosen.base_score:
                note = f"scanner said {scanner_value:g}"
            source = f"nvd/{chosen.scorer_type.lower() or 'unknown'}"
            return chosen.base_score, chosen.version, source, None, note
        # 快照存在但沒有任何分數：NVD 尚未評分，退回掃描器值，仍不得補零
        if scanner_value is not None:
            return scanner_value, "", "scanner", None, "nvd unscored"
        return None, "", "", "missing cvss (scanner blank, nvd unscored)", ""
    if scanner_error:
        return None, "", "", scanner_error, ""
    if scanner_value is None:
        return None, "", "", "missing cvss", ""
    return scanner_value, "", "scanner", None, ""


def score_finding(
    finding: dict[str, Any],
    context: dict[str, Any] | None,
    rules: RiskRules,
    snapshot: CveRecord | None = None,
) -> dict[str, Any]:
    """對單筆 finding 評分；回傳 ranked_result 的一列（dict）。"""
    row: dict[str, Any] = {
        "asset": finding.get("asset"),
        "cve": finding.get("cve"),
        "cvss": finding.get("cvss"),
        "cvss_version": "",
        "cvss_source": "",
        "environment": "",
        "effective_exposure": "",
        "business_criticality": "",
        "priority_score": "",
        "priority": "",
    }
    gaps: list[str] = []

    cvss, cvss_version, cvss_source, cvss_gap, cvss_note = _resolve_cvss(finding, snapshot, rules)
    if cvss_gap:
        gaps.append(cvss_gap)
    else:
        row["cvss"] = cvss
        row["cvss_version"] = cvss_version
        row["cvss_source"] = cvss_source

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
    cvss_label = f"v{cvss_version} {cvss_source}" if cvss_version else cvss_source
    if cvss_note:
        cvss_label += f", {cvss_note}"
    row["reason"] = (
        f"CVSS {cvss:g} [{cvss_label}] (S={severity:g}); "
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
    snapshots: dict[str, CveRecord] | None = None,
) -> list[dict[str, Any]]:
    """全部評分後排序：SCORED 依分數降冪在前，NEEDS_CONTEXT 保留在最後。

    `snapshots` 以 CVE 編號（大寫）為鍵；給了就用有來源的分數取代掃描器手填值。
    """
    snapshots = snapshots or {}
    rows = [
        score_finding(
            f,
            contexts.get(str(f.get("asset"))),
            rules,
            snapshots.get(str(f.get("cve", "")).strip().upper()),
        )
        for f in findings
    ]
    scored = [r for r in rows if r["decision"] == DECISION_SCORED]
    needs_context = [r for r in rows if r["decision"] == DECISION_NEEDS_CONTEXT]
    scored.sort(key=lambda r: r["priority_score"], reverse=True)
    return scored + needs_context
