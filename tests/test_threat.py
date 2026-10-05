"""EPSS 與 KEV 合併成威脅輸入：取大不取平均，沒有資料不補零。"""

from pathlib import Path

import pytest

from cve2action.collectors.epss import EpssRecord
from cve2action.collectors.kev import KevEntry
from cve2action.normalization.threat import derive_threat, epss_to_score
from cve2action.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
# Day 5–18 的基準用 **v0.1 凍結版**規則：那些數字是已發表文章的依據，
# 必須永遠重現得出來。production 設定（config/risk_rules.yaml）自 Day 23 起
# 多了路徑項，分數因此不同——那是預期的，不是回歸。
RULES = load_rules(ROOT / "config" / "risk_rules.v0.1.yaml").threat


def epss(value=0.5, model_date="2026-09-22"):
    return EpssRecord(cve_id="CVE-1", epss=value, percentile=0.9, model_date=model_date,
                      source_url="u", retrieved_at="t")


def kev_entry(date_added="2025-03-13"):
    return KevEntry(cve_id="CVE-1", vendor_project="V", product="P", vulnerability_name="N",
                    date_added=date_added, due_date=None, required_action="", known_ransomware=None)


# --- EPSS 對數轉換：把偏斜的低端拉開 ---------------------------------------------

@pytest.mark.parametrize("probability, expected", [(0.0, 0.0), (1.0, 1.0)])
def test_transform_keeps_the_endpoints(probability, expected):
    assert epss_to_score(probability, RULES) == pytest.approx(expected)


def test_transform_lifts_the_crowded_low_end():
    """EPSS 0.0171 原始看起來貼著零，轉換後才跟 0.001 分得開。"""
    low, tiny = epss_to_score(0.0171, RULES), epss_to_score(0.001, RULES)
    assert low == pytest.approx(0.215, abs=0.01)
    assert tiny < 0.03
    assert low > tiny * 5


def test_transform_is_monotonic():
    values = [epss_to_score(p, RULES) for p in (0.001, 0.0356, 0.095, 0.9997, 1.0)]
    assert values == sorted(values)


@pytest.mark.parametrize("bad", [-0.01, 1.01])
def test_out_of_range_probability_rejected(bad):
    with pytest.raises(ValueError, match="within 0-1"):
        epss_to_score(bad, RULES)


# --- 合併：取大不取平均 ----------------------------------------------------------

def test_kev_rescues_a_low_epss():
    """真實案例 CVE-2025-21590：EPSS 只有 1.7%，但 CISA 確認它被利用過。"""
    result = derive_threat(epss(0.0171), kev_entry(), True, RULES)
    assert float(result.value) == pytest.approx(1.0)
    assert "kev:LISTED@2025-03-13" in result.source
    assert "over epss:0.0171" in result.source, "落選的來源也要留在理由裡"


def test_high_epss_wins_when_not_in_kev():
    result = derive_threat(epss(0.9997), None, True, RULES)
    assert float(result.value) > 0.99
    assert result.source.startswith("epss:0.9997@2026-09-22")
    assert "kev:NOT_LISTED" in result.source


def test_not_listed_contributes_zero_but_does_not_cancel_epss():
    """目錄在手上、沒收錄它，是明確事實：威脅貢獻 0，但不會蓋掉 EPSS。"""
    result = derive_threat(epss(0.5), None, True, RULES)
    assert float(result.value) == pytest.approx(epss_to_score(0.5, RULES), abs=1e-4)


def test_kev_alone_is_enough():
    result = derive_threat(None, kev_entry(), True, RULES)
    assert float(result.value) == pytest.approx(1.0)


def test_epss_alone_is_enough_when_the_catalog_is_missing():
    result = derive_threat(epss(0.3), None, False, RULES)
    assert float(result.value) == pytest.approx(epss_to_score(0.3, RULES), abs=1e-4)
    assert "kev" not in result.source, "沒有目錄就不該宣稱 NOT_LISTED"


def test_no_threat_data_at_all_returns_none_not_zero():
    """零代表『確定沒有威脅』；不知道就是不知道，交給呼叫端移除威脅項。"""
    assert derive_threat(None, None, False, RULES) is None


def test_unscored_epss_without_catalog_is_also_none():
    unscored = EpssRecord(cve_id="CVE-1", epss=None, percentile=None, model_date=None,
                          source_url="u", retrieved_at="t")
    assert derive_threat(unscored, None, False, RULES) is None


def test_source_records_the_epss_model_date():
    result = derive_threat(epss(0.9, model_date="2026-01-05"), None, False, RULES)
    assert "@2026-01-05" in result.source
