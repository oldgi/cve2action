"""Day 15：控制措施的適用性——攔截點不在攻擊路徑上就不得折減。"""

from __future__ import annotations

from datetime import date

import pytest

from cve2action.normalization.control import (
    APPLICABLE,
    NOT_APPLICABLE,
    UNDECIDABLE,
    Attack,
    ControlRulesError,
    applicability,
    parse_attack,
    parse_control_rules,
)
from cve2action.normalization.exposure import derive_control_effectiveness
from cve2action.rules import RulesError, load_rules

RULES_PATH = "config/risk_rules.v0.1.yaml"
AS_OF = date(2026, 9, 24)

ZEROLOGON = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
PRINTNIGHTMARE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
DIRTY_COW = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_PATH)


# --- 向量解析 ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        (ZEROLOGON, Attack("NETWORK", "NONE")),
        (DIRTY_COW, Attack("LOCAL", "LOW")),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H", Attack("ADJACENT_NETWORK", "HIGH")),
        ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Attack("PHYSICAL", "NONE")),
    ],
)
def test_parse_attack_reads_av_and_pr_from_both_versions(vector, expected):
    assert parse_attack(vector) == expected


@pytest.mark.parametrize("vector", ["", None, "CVSS:3.1/AC:L/UI:N", "not-a-vector"])
def test_parse_attack_returns_none_when_vector_unreadable(vector):
    assert parse_attack(vector) is None


def test_privileges_required_none_means_no_authentication_in_the_path():
    assert parse_attack(ZEROLOGON).needs_authentication is False
    assert parse_attack(PRINTNIGHTMARE).needs_authentication is True


# --- 適用性三態 -------------------------------------------------------------

def test_network_control_does_not_apply_to_a_local_attack(rules):
    verdict, why = applicability("network_segmentation", parse_attack(DIRTY_COW), rules.controls)
    assert verdict == NOT_APPLICABLE
    assert "AV:LOCAL" in why


def test_authentication_control_does_not_apply_to_a_pre_auth_attack(rules):
    verdict, why = applicability("mfa_admin_tiering", parse_attack(ZEROLOGON), rules.controls)
    assert verdict == NOT_APPLICABLE
    assert "PR:NONE" in why


def test_same_control_applies_when_the_path_goes_through_an_account(rules):
    verdict, _why = applicability("mfa_admin_tiering", parse_attack(PRINTNIGHTMARE), rules.controls)
    assert verdict == APPLICABLE


def test_unreadable_vector_is_undecidable_not_applicable(rules):
    """不能證明攔得到，就不能拿它打折——但這是未知，不是『攔不到』這個事實。"""
    assert applicability("waf", None, rules.controls)[0] == UNDECIDABLE


def test_undeclared_control_type_is_undecidable(rules):
    verdict, _why = applicability("carrier_pigeon", parse_attack(ZEROLOGON), rules.controls)
    assert verdict == UNDECIDABLE


# --- 併入強度推導 -----------------------------------------------------------

SEGMENTED_DB = [{
    "asset_id": "NS-DB-CUSTOMER-01", "control_type": "network_segmentation",
    "effectiveness": "STRONG", "verified_at": "2026-09-10",
}]


def test_inapplicable_control_yields_none_not_unknown(rules):
    """已知攔不到是事實，記為 NONE；來源要說得出為什麼。"""
    derived = derive_control_effectiveness(
        "NS-DB-CUSTOMER-01", SEGMENTED_DB, rules, AS_OF,
        parse_attack(DIRTY_COW), check_applicability=True,
    )
    assert derived.value == "NONE"
    assert "not applicable to AV:LOCAL" in derived.source


def test_undecidable_control_yields_unknown(rules):
    derived = derive_control_effectiveness(
        "NS-DB-CUSTOMER-01", SEGMENTED_DB, rules, AS_OF, None, check_applicability=True,
    )
    assert derived.value == "UNKNOWN"


def test_applicable_control_still_discounts(rules):
    derived = derive_control_effectiveness(
        "NS-DB-CUSTOMER-01", SEGMENTED_DB, rules, AS_OF,
        parse_attack("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), check_applicability=True,
    )
    assert derived.value == "STRONG"


def test_asset_level_derivation_ignores_applicability(rules):
    """Day 12 的資產層視圖不看適用性，行為不變。"""
    derived = derive_control_effectiveness("NS-DB-CUSTOMER-01", SEGMENTED_DB, rules, AS_OF)
    assert derived.value == "STRONG"
    assert derived.source == "control:network_segmentation@2026-09-10"


def test_expired_evidence_still_wins_over_applicability(rules):
    """證據先過期就輪不到談適用性，理由要保留『過期』而不是『不適用』。"""
    stale = [{**SEGMENTED_DB[0], "verified_at": "2026-01-02"}]
    derived = derive_control_effectiveness(
        "NS-DB-CUSTOMER-01", stale, rules, AS_OF,
        parse_attack("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), check_applicability=True,
    )
    assert derived.value == "UNKNOWN"
    assert "expired" in derived.source


def test_one_applicable_control_survives_an_inapplicable_sibling(rules):
    """不適用的控制不該把還適用的那一項一起拖下水。"""
    both = SEGMENTED_DB + [{
        "asset_id": "NS-DB-CUSTOMER-01", "control_type": "edr",
        "effectiveness": "PARTIAL", "verified_at": "2026-09-10",
    }]
    derived = derive_control_effectiveness(
        "NS-DB-CUSTOMER-01", both, rules, AS_OF,
        parse_attack(DIRTY_COW), check_applicability=True,
    )
    assert derived.value == "PARTIAL"
    assert "edr" in derived.source


# --- 設定檔驗證 -------------------------------------------------------------

def test_missing_controls_section_is_rejected(tmp_path):
    from pathlib import Path
    text = Path(RULES_PATH).read_text(encoding="utf-8")
    broken = tmp_path / "no-controls.yaml"
    broken.write_text(text.replace("\ncontrols:\n", "\ncontrols_disabled:\n"), encoding="utf-8")
    with pytest.raises(RulesError, match="controls"):
        load_rules(broken)


def test_unknown_attack_vector_in_config_is_rejected():
    with pytest.raises(ControlRulesError, match="unknown attack vectors"):
        parse_control_rules({"applicability": {"waf": {"attack_vectors": ["CARRIER_PIGEON"]}}})


def test_attack_vectors_must_be_a_non_empty_list():
    with pytest.raises(ControlRulesError, match="attack_vectors"):
        parse_control_rules({"applicability": {"waf": {"attack_vectors": []}}})
