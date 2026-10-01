"""Decision Engine：確定性評分。

S = CVSS / 10
T = max(EPSS 對數轉換, KEV)
E = Reachability × Control Effectiveness（Effective Exposure）
B = Business Impact
Priority Score = 10 × (wS×S + wT×T + wE×E + wB×B)

缺少必要 context 或值不在值域 → decision = NEEDS_CONTEXT，不評分、不猜預設值。

Day 16 起，計分的第一級產物是 `Explanation`（見 explain.py）：輸出的 CSV 列與
`reason` 字串都由它投影出來，不再各自拼湊，字串因此不可能與數字對不上。
"""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING, Any

from ..models import DECISION_NEEDS_CONTEXT, DECISION_SCORED, OUTPUT_COLUMNS, RiskRules
from ..normalization.control import parse_attack
from ..normalization.exposure import derive_control_effectiveness
from ..normalization.threat import derive_threat
from .explain import Explanation, Factor

if TYPE_CHECKING:
    from ..collectors.epss import EpssRecord
    from ..collectors.kev import KevCatalog
    from ..collectors.nvd import CveRecord


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


def _chosen_vector(snapshot: CveRecord | None, rules: RiskRules) -> str | None:
    """本列實際採用的那一版 CVSS 的 vector，Day 15 用來讀 AV/PR。"""
    if snapshot is None:
        return None
    chosen = snapshot.cvss.preferred(rules.cvss_version_preference)
    return chosen.vector if chosen is not None else None


def explain_finding(
    finding: dict[str, Any],
    context: dict[str, Any] | None,
    rules: RiskRules,
    snapshot: CveRecord | None = None,
    epss: EpssRecord | None = None,
    kev: KevCatalog | None = None,
    controls: list[dict[str, Any]] | None = None,
    as_of: date | None = None,
) -> Explanation:
    """對單筆 finding 評分，回傳結構化的 Explanation。

    沒有任何威脅資料時，威脅項整個移除、權重退回 severity——不補零，
    因為零代表「確定沒有威脅」，那是我們不知道的事。
    """
    fields: dict[str, Any] = {
        "asset": finding.get("asset"),
        "cve": finding.get("cve"),
        "cvss": finding.get("cvss"),
        "cvss_version": "",
        "cvss_source": "",
        "threat": "",
        "threat_source": "",
        "environment": "",
        "control_effectiveness": "",
        "control_source": "",
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
        fields["cvss"] = cvss
        fields["cvss_version"] = cvss_version
        fields["cvss_source"] = cvss_source

    if context is None:
        gaps.append("asset not found in asset_context")
        reach_value = control_value = business_value = None
    else:
        fields["environment"] = context.get("environment") or ""
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
            fields["business_criticality"] = str(business)

    if gaps:
        fields["decision"] = DECISION_NEEDS_CONTEXT
        return Explanation(
            asset=str(finding.get("asset", "")), cve=str(finding.get("cve", "")),
            decision=DECISION_NEEDS_CONTEXT, gaps=tuple(gaps), extras=fields,
        )

    assert cvss is not None and reach_value is not None
    assert control_value is not None and business_value is not None

    control_label = str(context["control_effectiveness"])
    control_source = str(context.get("control_source", "asset_context"))
    control_note = ""
    if controls is not None:
        # Day 15：控制的折減資格逐筆重算——攔截點不在這條攻擊路徑上就不算數
        derived = derive_control_effectiveness(
            str(finding.get("asset")), controls, rules, as_of or date.today(),
            parse_attack(_chosen_vector(snapshot, rules)), check_applicability=True,
        )
        control_label, control_source = derived.value, derived.source
        control_value = rules.control_effectiveness[derived.value]
        control_note = f" [{control_source}]"
    fields["control_effectiveness"] = control_label
    fields["control_source"] = control_source

    severity = cvss / 10.0
    exposure = round(reach_value * control_value, 4)
    weights = rules.weights

    cve_id = str(finding.get("cve", "")).strip().upper()
    threat = derive_threat(epss, kev.get(cve_id) if kev else None,
                           kev is not None, rules.threat) if rules.threat else None
    cvss_label = f"v{cvss_version} {cvss_source}" if cvss_version else cvss_source
    if cvss_note:
        cvss_label += f", {cvss_note}"

    severity_weight = weights["severity"]
    if threat is None:
        # 威脅項缺席時，它的權重退回 severity——不是按比例分給所有人。
        # CVSS 的可利用性指標本來就兼著回答「會不會被利用」；沒有 EPSS/KEV 時它繼續兼，
        # 於是公式退回 Day 5 的 50/25/25，先前建立的基準不受影響。
        severity_weight += weights["threat"]

    factors: list[Factor] = [Factor(
        key="severity", value=severity, weight=severity_weight,
        inputs={"cvss": cvss, "version": cvss_version},
        source=cvss_source or "scanner", detail=cvss_label,
    )]
    if threat is not None:
        factors.append(Factor(
            key="threat", value=float(threat.value), weight=weights["threat"],
            inputs={"epss": epss.epss if epss is not None else None,
                    "kev_listed": bool(kev.get(cve_id)) if kev is not None else None},
            source=threat.source, detail=threat.source,
        ))
        fields["threat"] = float(threat.value)
        fields["threat_source"] = threat.source
    factors.append(Factor(
        key="exposure", value=exposure, weight=weights["exposure"],
        inputs={"reachability": context["reachability"], "control": control_label,
                "reachability_value": reach_value, "control_value": control_value},
        source=control_source, detail=f"{context['reachability']} x {control_label}",
    ))
    factors.append(Factor(
        key="business", value=business_value, weight=weights["business"],
        inputs={"criticality": context["business_criticality"]},
        source=str(context.get("business_source", "asset_context")),
        detail=str(context["business_criticality"]),
    ))

    score = round(10.0 * sum(f.weight * f.value for f in factors), 2)
    fields["effective_exposure"] = exposure
    fields["priority_score"] = score
    fields["priority"] = rules.band_for(score)
    fields["decision"] = DECISION_SCORED
    fields["control_note"] = control_note

    return Explanation(
        asset=str(finding.get("asset", "")), cve=str(finding.get("cve", "")),
        decision=DECISION_SCORED, factors=tuple(factors), score=score,
        band=fields["priority"], degraded=threat is None, extras=fields,
    )


def row_from(explanation: Explanation) -> dict[str, Any]:
    """把 Explanation 投影成 ranked_result 的一列。reason 同樣由它產生。"""
    row = {column: explanation.extras.get(column, "") for column in OUTPUT_COLUMNS}
    row["reason"] = explanation.to_reason()
    return row


def score_finding(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """對單筆 finding 評分；回傳 ranked_result 的一列（dict）。"""
    return row_from(explain_finding(*args, **kwargs))


def rank_explained(
    findings: list[dict[str, Any]],
    contexts: dict[str, dict[str, Any]],
    rules: RiskRules,
    snapshots: dict[str, CveRecord] | None = None,
    epss: dict[str, EpssRecord] | None = None,
    kev: KevCatalog | None = None,
    controls: list[dict[str, Any]] | None = None,
    as_of: date | None = None,
) -> list[Explanation]:
    """全部評分後排序，回傳 Explanation：SCORED 依分數降冪在前，NEEDS_CONTEXT 在最後。

    排序只實作在這裡一次；`rank` 是它的投影，兩者不可能排出不同順序。
    """
    snapshots, epss = snapshots or {}, epss or {}
    explanations = [
        explain_finding(
            f,
            contexts.get(str(f.get("asset"))),
            rules,
            snapshots.get(str(f.get("cve", "")).strip().upper()),
            epss.get(str(f.get("cve", "")).strip().upper()),
            kev,
            controls,
            as_of,
        )
        for f in findings
    ]
    scored = [e for e in explanations if e.decision == DECISION_SCORED]
    needs_context = [e for e in explanations if e.decision == DECISION_NEEDS_CONTEXT]
    scored.sort(key=lambda e: e.score, reverse=True)
    return scored + needs_context


def rank(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """`rank_explained` 的列投影；欄位與順序同 ranked_result.csv。

    `snapshots` 以 CVE 編號（大寫）為鍵；給了就用有來源的分數取代掃描器手填值。
    """
    return [row_from(e) for e in rank_explained(*args, **kwargs)]
