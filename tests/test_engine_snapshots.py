"""引擎從 NVD 快照取 CVSS：有來源的分數優先於手填值，缺分數不補零。"""

from dataclasses import replace
from pathlib import Path

from cve2action.collectors.nvd import CveRecord
from cve2action.engine import rank, score_finding
from cve2action.models import DECISION_NEEDS_CONTEXT, DECISION_SCORED
from cve2action.normalization.cvss import CvssSet, make_score
from cve2action.rules import load_rules

RULES = load_rules(Path(__file__).resolve().parents[1] / "config" / "risk_rules.yaml")
CTX = {"asset": "A", "environment": "PROD", "reachability": "INTERNET",
       "control_effectiveness": "NONE", "business_criticality": "CRITICAL"}
V31 = "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N"


def record(scores=()):
    return CveRecord(cve_id="CVE-2022-41082", cvss=CvssSet(tuple(scores)), published=None,
                     last_modified=None, description="", source_url="u", retrieved_at="t")


NVD_80 = record([make_score(version="3.1", base_score=8.0, vector=V31,
                            scorer="nvd@nist.gov", scorer_type="Primary")])


def test_snapshot_score_overrides_hand_filled_value_and_says_so():
    row = score_finding({"asset": "A", "cve": "CVE-2022-41082", "cvss": "8.8"}, CTX, RULES, NVD_80)
    assert row["decision"] == DECISION_SCORED
    assert (row["cvss"], row["cvss_version"], row["cvss_source"]) == (8.0, "3.1", "nvd/primary")
    assert row["priority_score"] == 9.0  # Day 6 手填 8.8 時是 9.40
    assert "scanner said 8.8" in row["reason"]


def test_blank_scanner_value_is_filled_from_snapshot():
    v40_only = record([make_score(version="4.0", base_score=7.3, vector=V40,
                                  scorer="PSIRT@rockwellautomation.com", scorer_type="Secondary")])
    row = score_finding({"asset": "A", "cve": "CVE-2024-6242", "cvss": ""}, CTX, RULES, v40_only)
    assert (row["cvss"], row["cvss_version"], row["cvss_source"]) == (7.3, "4.0", "nvd/secondary")
    assert "scanner said" not in row["reason"]


def test_no_snapshot_falls_back_to_scanner_value():
    row = score_finding({"asset": "A", "cve": "CVE-0000-1", "cvss": "8.8"}, CTX, RULES, None)
    assert (row["cvss"], row["cvss_version"], row["cvss_source"]) == (8.8, "", "scanner")


def test_unscored_snapshot_keeps_scanner_value_but_never_zero():
    finding = {"asset": "A", "cve": "CVE-2022-41082", "cvss": "8.8"}
    row = score_finding(finding, CTX, RULES, record())
    assert (row["cvss"], row["cvss_source"]) == (8.8, "scanner")
    assert "nvd unscored" in row["reason"]


def test_unscored_snapshot_and_blank_scanner_is_needs_context():
    row = score_finding({"asset": "A", "cve": "CVE-2022-41082", "cvss": ""}, CTX, RULES, record())
    assert row["decision"] == DECISION_NEEDS_CONTEXT
    assert "nvd unscored" in row["reason"]


def test_version_preference_can_flip_priority_band():
    """CVE-2025-21590 的形狀：v3.1=4.4、v4.0=6.7；偏好順序決定同一列落在哪個分級。"""
    juniper = record([
        make_score(version="3.1", base_score=4.4, scorer="sirt@juniper.net",
                   scorer_type="Secondary",
                   vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N"),
        make_score(version="4.0", base_score=6.7, scorer="sirt@juniper.net",
                   scorer_type="Secondary",
                   vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"),
    ])
    ctx = dict(CTX, control_effectiveness="PARTIAL")
    finding = {"asset": "A", "cve": "CVE-2025-21590", "cvss": "4.4"}

    prefer_31 = score_finding(finding, ctx, RULES, juniper)
    rules_40 = replace(RULES, cvss_version_preference=("4.0", "3.1"))
    prefer_40 = score_finding(finding, ctx, rules_40, juniper)
    assert (prefer_31["priority_score"], prefer_31["priority"]) == (6.45, "Medium")
    assert (prefer_40["priority_score"], prefer_40["priority"]) == (7.6, "High")


def test_rank_matches_snapshots_by_cve_id_case_insensitively():
    rows = rank([{"asset": "A", "cve": "cve-2022-41082", "cvss": "8.8"}], {"A": CTX}, RULES,
                {"CVE-2022-41082": NVD_80})
    assert rows[0]["cvss_source"] == "nvd/primary"
