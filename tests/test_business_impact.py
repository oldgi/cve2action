"""Business Criticality 的推導：三項事實，取最嚴重的一個。"""

from pathlib import Path

import pytest

from cve2action.normalization.business import derive_business_criticality
from cve2action.normalization.exposure import ExposureError
from cve2action.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
# Day 5–18 的基準用 **v0.1 凍結版**規則：那些數字是已發表文章的依據，
# 必須永遠重現得出來。production 設定（config/risk_rules.yaml）自 Day 23 起
# 多了路徑項，分數因此不同——那是預期的，不是回歸。
RULES = load_rules(ROOT / "config" / "risk_rules.v0.1.yaml").business_impact


def ctx(data_class="INTERNAL", rto="48", customer_facing="no", asset_id="A"):
    return {"asset_id": asset_id, "data_class": data_class, "rto_hours": rto,
            "customer_facing": customer_facing}


# --- 三個維度各自的效果 ---------------------------------------------------------

@pytest.mark.parametrize("data_class, expected", [
    ("RESTRICTED", "CRITICAL"), ("CONFIDENTIAL", "IMPORTANT"),
    ("INTERNAL", "NORMAL"), ("PUBLIC", "NORMAL"), ("NONE", "NORMAL"),
])
def test_data_class_sets_a_floor(data_class, expected):
    result = derive_business_criticality(ctx(data_class=data_class), RULES)
    assert result.value == expected
    if expected != "NORMAL":
        assert result.source == f"data:{data_class}"


@pytest.mark.parametrize("rto, expected", [
    ("1", "CRITICAL"), ("4", "CRITICAL"), ("4.5", "IMPORTANT"),
    ("24", "IMPORTANT"), ("25", "NORMAL"), ("168", "NORMAL"),
])
def test_rto_bands_are_inclusive_of_their_upper_bound(rto, expected):
    assert derive_business_criticality(ctx(rto=rto), RULES).value == expected


def test_customer_facing_lifts_the_floor_to_important():
    result = derive_business_criticality(ctx(rto="72", customer_facing="yes"), RULES)
    assert (result.value, result.source) == ("IMPORTANT", "customer-facing")


# --- 合併：取最嚴重，不平均 -----------------------------------------------------

def test_data_sensitivity_is_not_diluted_by_a_generous_rto():
    """受管制資料 + 可以慢慢修 ≠ 折衷。外洩的衝擊跟停機容忍度無關。"""
    result = derive_business_criticality(ctx(data_class="RESTRICTED", rto="168"), RULES)
    assert (result.value, result.source) == ("CRITICAL", "data:RESTRICTED")


def test_an_asset_holding_no_data_can_still_be_critical():
    """機房環控不存任何業務資料，但兩小時內非復原不可。"""
    result = derive_business_criticality(ctx(data_class="NONE", rto="2"), RULES)
    assert (result.value, result.source) == ("CRITICAL", "rto:2h")


def test_the_source_names_the_dimension_that_won():
    result = derive_business_criticality(
        ctx(data_class="CONFIDENTIAL", rto="1", customer_facing="yes"), RULES)
    assert (result.value, result.source) == ("CRITICAL", "rto:1h")


# --- 缺事實就報錯，不猜 ---------------------------------------------------------

@pytest.mark.parametrize("missing", ["data_class", "rto_hours"])
def test_missing_fact_is_an_error_not_a_default(missing):
    context = ctx()
    context[missing] = ""
    with pytest.raises(ExposureError, match="required"):
        derive_business_criticality(context, RULES)


@pytest.mark.parametrize("rto", ["soon", "0", "-4"])
def test_unusable_rto_is_rejected(rto):
    with pytest.raises(ExposureError):
        derive_business_criticality(ctx(rto=rto), RULES)


def test_unknown_data_class_is_rejected():
    with pytest.raises(ExposureError, match="unknown data_class"):
        derive_business_criticality(ctx(data_class="SECRET-ISH"), RULES)


# --- 對上 Northstar 的實際資料 --------------------------------------------------

def test_northstar_business_facts_reproduce_the_committed_context():
    import csv

    from cve2action.normalization.business import derive_business_context

    data = ROOT / "data" / "synthetic" / "northstar"

    def read(name):
        with (data / name).open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    derived = derive_business_context(read("business_context.csv"), RULES)
    for row in read("asset_context.csv"):
        assert derived[row["asset"]].value == row["business_criticality"], row["asset"]
        assert derived[row["asset"]].source == row["business_source"], row["asset"]


def test_four_assets_disagree_with_the_label_i_typed_on_day_11():
    """推導值與 assets.csv 上人標的 declared_criticality 不同的，就是這四台。"""
    import csv

    from cve2action.normalization.business import derive_business_context

    data = ROOT / "data" / "synthetic" / "northstar"

    def read(name):
        with (data / name).open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    derived = derive_business_context(read("business_context.csv"), RULES)
    disagree = {a["asset_id"]: (a["declared_criticality"], derived[a["asset_id"]].value)
                for a in read("assets.csv")
                if a["declared_criticality"] != derived[a["asset_id"]].value}
    assert disagree == {
        "NS-MAIL-GW-01": ("CRITICAL", "IMPORTANT"),
        "NS-APP-INTRANET-01": ("IMPORTANT", "NORMAL"),
        "NS-FILE-SRV-01": ("NORMAL", "IMPORTANT"),
        "NS-PLC-DC-ENV": ("IMPORTANT", "CRITICAL"),
    }
