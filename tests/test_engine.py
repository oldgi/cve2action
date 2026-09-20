"""Decision Engine v0.1 回歸測試：Day 5 Case A/B 的數值是驗收基準。"""

from pathlib import Path

import pytest

from cve2action.engine import rank, score_finding
from cve2action.models import DECISION_NEEDS_CONTEXT, DECISION_SCORED
from cve2action.rules import load_rules

RULES = load_rules(Path(__file__).resolve().parents[1] / "config" / "risk_rules.yaml")


def ctx(reachability, control, business, environment="PROD"):
    return {
        "asset": "TEST",
        "environment": environment,
        "reachability": reachability,
        "control_effectiveness": control,
        "business_criticality": business,
    }


def test_case_a_isolated_high_cvss_drops_to_medium():
    row = score_finding(
        {"asset": "A", "cve": "CVE-2022-26134", "cvss": "9.8"},
        ctx("ISOLATED", "PARTIAL", "NORMAL", environment="NON_PROD"),
        RULES,
    )
    assert row["decision"] == DECISION_SCORED
    assert row["effective_exposure"] == pytest.approx(0.14)
    assert row["priority_score"] == 6.25
    assert row["priority"] == "Medium"


def test_case_b_internet_crown_jewel_outranks_case_a():
    row = score_finding(
        {"asset": "B", "cve": "CVE-2022-41082", "cvss": "8.8"},
        ctx("INTERNET", "STRONG", "CRITICAL"),
        RULES,
    )
    assert row["priority_score"] == 7.90
    assert row["priority"] == "High"


def test_case_b_without_control_becomes_critical():
    row = score_finding(
        {"asset": "B", "cve": "CVE-2022-41082", "cvss": "8.8"},
        ctx("INTERNET", "NONE", "CRITICAL"),
        RULES,
    )
    assert row["priority_score"] == 9.40
    assert row["priority"] == "Critical"


def test_ranking_flips_case_b_above_case_a():
    findings = [
        {"asset": "A", "cve": "CVE-2022-26134", "cvss": "9.8"},
        {"asset": "B", "cve": "CVE-2022-41082", "cvss": "8.8"},
    ]
    contexts = {
        "A": ctx("ISOLATED", "PARTIAL", "NORMAL"),
        "B": ctx("INTERNET", "STRONG", "CRITICAL"),
    }
    ranked = rank(findings, contexts, RULES)
    assert [r["asset"] for r in ranked] == ["B", "A"]


def test_unknown_control_does_not_lower_exposure():
    unknown = score_finding(
        {"asset": "U", "cve": "CVE-2021-44228", "cvss": "10.0"},
        ctx("INTERNAL", "UNKNOWN", "IMPORTANT"),
        RULES,
    )
    none = score_finding(
        {"asset": "N", "cve": "CVE-2021-44228", "cvss": "10.0"},
        ctx("INTERNAL", "NONE", "IMPORTANT"),
        RULES,
    )
    assert unknown["effective_exposure"] == none["effective_exposure"]
    assert unknown["priority_score"] == none["priority_score"] == 8.25


def test_missing_context_row_yields_needs_context():
    row = score_finding({"asset": "GHOST", "cve": "CVE-2021-36260", "cvss": "9.8"}, None, RULES)
    assert row["decision"] == DECISION_NEEDS_CONTEXT
    assert row["priority_score"] == ""
    assert "asset not found in asset_context" in row["reason"]


def test_out_of_domain_context_value_yields_needs_context():
    row = score_finding(
        {"asset": "X", "cve": "CVE-0000-0000", "cvss": "5.0"},
        ctx("DMZ", "PARTIAL", "NORMAL"),
        RULES,
    )
    assert row["decision"] == DECISION_NEEDS_CONTEXT
    assert "reachability='DMZ'" in row["reason"]


def test_blank_context_field_yields_needs_context():
    row = score_finding(
        {"asset": "X", "cve": "CVE-0000-0000", "cvss": "5.0"},
        ctx("INTERNAL", "", "NORMAL"),
        RULES,
    )
    assert row["decision"] == DECISION_NEEDS_CONTEXT
    assert "missing control_effectiveness" in row["reason"]


@pytest.mark.parametrize("bad_cvss", ["", "abc", "-1", "10.1"])
def test_invalid_cvss_yields_needs_context(bad_cvss):
    row = score_finding(
        {"asset": "X", "cve": "CVE-0000-0000", "cvss": bad_cvss},
        ctx("INTERNAL", "PARTIAL", "NORMAL"),
        RULES,
    )
    assert row["decision"] == DECISION_NEEDS_CONTEXT


def test_needs_context_rows_stay_at_bottom():
    findings = [
        {"asset": "GHOST", "cve": "CVE-1", "cvss": "9.9"},
        {"asset": "B", "cve": "CVE-2", "cvss": "8.8"},
    ]
    ranked = rank(findings, {"B": ctx("INTERNET", "NONE", "CRITICAL")}, RULES)
    assert ranked[-1]["asset"] == "GHOST"
    assert ranked[-1]["decision"] == DECISION_NEEDS_CONTEXT


def test_reason_explains_every_factor():
    row = score_finding(
        {"asset": "A", "cve": "CVE-2022-26134", "cvss": "9.8"},
        ctx("ISOLATED", "PARTIAL", "NORMAL"),
        RULES,
    )
    for fragment in ["CVSS 9.8", "S=0.98", "ISOLATED", "PARTIAL", "E=0.14", "NORMAL", "B=0.4"]:
        assert fragment in row["reason"]
