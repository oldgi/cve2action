"""有效曝險的兩個輸入：Reachability 與 Control Effectiveness 的推導與來源標示。"""

from datetime import date
from pathlib import Path

import pytest

from cve2action.normalization.exposure import (
    ExposureError,
    derive_asset_context,
    derive_control_effectiveness,
    derive_reachability,
)
from cve2action.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "config" / "risk_rules.yaml")
AS_OF = date(2026, 9, 24)


def asset(asset_id="A", zone="DMZ", **extra):
    return {"asset_id": asset_id, "zone": zone, "environment": "PROD",
            "criticality": "CRITICAL", **extra}


def control(asset_id="A", kind="waf", effectiveness="STRONG", verified="2026-09-01"):
    return {"asset_id": asset_id, "control_type": kind, "effectiveness": effectiveness,
            "evidence": "…", "verified_at": verified}


# --- Reachability：Zone 是假設，觀測優先 ---------------------------------------

@pytest.mark.parametrize("zone, expected", [
    ("DMZ", "INTERNET"), ("APP", "INTERNAL"), ("DATA", "INTERNAL"),
    ("MGMT", "INTERNAL"), ("OT", "ISOLATED"), ("LAB", "ISOLATED"),
])
def test_zone_maps_to_reachability_and_says_so(zone, expected):
    result = derive_reachability(asset(zone=zone), RULES)
    assert (result.value, result.source) == (expected, f"zone:{zone}")


def test_observed_reachability_overrides_the_zone_assumption():
    """Zone 說隔離，實際觀測到對外——以觀測為準，並標明。"""
    result = derive_reachability(asset(zone="LAB"), RULES, observed="INTERNET")
    assert (result.value, result.source) == ("INTERNET", "observed")


def test_unknown_zone_is_an_error_not_a_guess():
    with pytest.raises(ExposureError, match="no reachability mapping"):
        derive_reachability(asset(zone="WHEREVER"), RULES)


def test_missing_zone_without_observation_is_an_error():
    with pytest.raises(ExposureError, match="no zone"):
        derive_reachability({"asset_id": "A", "zone": ""}, RULES)


def test_observed_value_must_be_a_known_reachability():
    with pytest.raises(ExposureError, match="not a known value"):
        derive_reachability(asset(), RULES, observed="SORT_OF_EXPOSED")


# --- Control Effectiveness：證據會過期 -----------------------------------------

def test_control_with_fresh_evidence_is_used():
    result = derive_control_effectiveness("A", [control()], RULES, AS_OF)
    assert (result.value, result.source) == ("STRONG", "control:waf@2026-09-01")


def test_no_control_is_none_not_unknown():
    """沒有登錄任何控制 = 沒有防護，這是明確的（NONE）。"""
    result = derive_control_effectiveness("A", [], RULES, AS_OF)
    assert (result.value, result.source) == ("NONE", "no-control")


def test_expired_evidence_degrades_to_unknown_not_none():
    """過期不代表控制失效——我們只是不知道它現在還有沒有效，所以是 UNKNOWN。"""
    old = control(verified="2026-01-01")
    result = derive_control_effectiveness("A", [old], RULES, AS_OF)
    assert result.value == "UNKNOWN"
    assert "expired" in result.source and "2026-01-01" in result.source


def test_expiry_boundary_is_inclusive_of_the_window():
    inside = control(verified=(AS_OF.replace(month=6, day=26)).isoformat())  # 90 天
    assert derive_control_effectiveness("A", [inside], RULES, AS_OF).value == "STRONG"
    outside = control(verified=(AS_OF.replace(month=6, day=25)).isoformat())  # 91 天
    assert derive_control_effectiveness("A", [outside], RULES, AS_OF).value == "UNKNOWN"


def test_control_recorded_as_unknown_stays_unknown():
    result = derive_control_effectiveness("A", [control(effectiveness="UNKNOWN")], RULES, AS_OF)
    assert result.value == "UNKNOWN" and "unproven" in result.source


def test_unparseable_date_is_treated_as_no_usable_evidence():
    result = derive_control_effectiveness("A", [control(verified="quarterly")], RULES, AS_OF)
    assert result.value == "UNKNOWN" and "unknown-date" in result.source


# --- 多個控制：取最強，不相乘 ---------------------------------------------------

def test_multiple_controls_take_the_strongest_without_multiplying():
    """兩個控制可能被同一個繞過手法穿過；相乘（0.4×0.7）是假精確。"""
    result = derive_control_effectiveness(
        "A", [control(kind="edr", effectiveness="PARTIAL"), control(kind="waf")], RULES, AS_OF)
    assert (result.value, result.source) == ("STRONG", "control:waf@2026-09-01")


def test_one_expired_control_does_not_cancel_a_valid_one():
    result = derive_control_effectiveness(
        "A", [control(kind="waf", verified="2026-01-01"),
              control(kind="edr", effectiveness="PARTIAL")], RULES, AS_OF)
    assert (result.value, result.source) == ("PARTIAL", "control:edr@2026-09-01")


def test_an_unknown_control_does_not_cancel_a_proven_one():
    result = derive_control_effectiveness(
        "A", [control(kind="edr", effectiveness="UNKNOWN"), control(kind="waf")], RULES, AS_OF)
    assert result.value == "STRONG"


def test_all_controls_unusable_gives_unknown_and_lists_why():
    result = derive_control_effectiveness(
        "A", [control(kind="waf", verified="2026-01-01"),
              control(kind="edr", effectiveness="UNKNOWN")], RULES, AS_OF)
    assert result.value == "UNKNOWN"
    assert "expired" in result.source and "unproven" in result.source


def test_controls_belonging_to_other_assets_are_ignored():
    result = derive_control_effectiveness("A", [control(asset_id="B")], RULES, AS_OF)
    assert result.value == "NONE"


# --- 整份推導 -------------------------------------------------------------------

def test_derive_asset_context_carries_both_sources():
    rows = derive_asset_context([asset("A", zone="DMZ")], [control("A")], RULES, AS_OF)
    assert rows == [{
        "asset": "A", "environment": "PROD", "reachability": "INTERNET",
        "control_effectiveness": "STRONG", "business_criticality": "CRITICAL",
        "reachability_source": "zone:DMZ", "control_source": "control:waf@2026-09-01",
    }]


def test_tightening_the_evidence_window_expires_more_controls():
    """有效期是規則不是資料：收緊它，同一份資料會有更多控制失去折扣。"""
    from dataclasses import replace
    controls = [control("A", verified="2026-08-14")]  # 41 天
    assert derive_control_effectiveness("A", controls, RULES, AS_OF).value == "STRONG"
    strict = replace(RULES, control_evidence_max_age_days=30)
    assert derive_control_effectiveness("A", controls, strict, AS_OF).value == "UNKNOWN"
