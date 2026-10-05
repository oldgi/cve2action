"""Day 15：1.0 / 0.7 / 0.4 這三個數字要守得住的性質。

係數本身是假設（Day 17 才校準），但「一項控制最多能搬動多少」必須是可驗證的，
否則沒有人能判斷這組數字是太鬆還是太緊。
"""

from __future__ import annotations

import itertools

import pytest

from cve2action.engine import score_finding
from cve2action.rules import load_rules

RULES_PATH = "config/risk_rules.v0.1.yaml"


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_PATH)


def _context(control: str, reachability: str = "INTERNET", business: str = "CRITICAL") -> dict:
    return {
        "environment": "PROD",
        "reachability": reachability,
        "control_effectiveness": control,
        "business_criticality": business,
    }


def _score(rules, cvss: float, control: str, reachability: str = "INTERNET") -> float:
    row = score_finding({"asset": "A", "cve": "CVE-0000-0001", "cvss": cvss},
                        _context(control, reachability), rules)
    return row["priority_score"]


def test_strongest_control_never_moves_a_finding_more_than_one_band(rules):
    """一項補償控制可以改變相鄰名次，但不該單獨把 Critical 變成 Medium。"""
    labels = [band.label for band in sorted(rules.priority_bands, key=lambda b: b.floor)]
    for cvss in [round(x * 0.1, 1) for x in range(0, 101)]:
        for reachability in rules.reachability:
            undefended = _score(rules, cvss, "NONE", reachability)
            defended = _score(rules, cvss, "STRONG", reachability)
            moved = labels.index(rules.band_for(undefended)) - labels.index(
                rules.band_for(defended))
            assert 0 <= moved <= 1, (
                f"CVSS {cvss} on {reachability}: {undefended} -> {defended} moved {moved} bands"
            )


def test_maximum_discount_is_smaller_than_the_narrowest_two_band_gap(rules):
    """上面那條性質的算術依據，寫成測試才不會在改權重時悄悄失效。"""
    weakest = max(rules.control_effectiveness.values())
    strongest = min(rules.control_effectiveness.values())
    max_reach = max(rules.reachability.values())
    largest_drop = 10.0 * rules.weights["exposure"] * max_reach * (weakest - strongest)

    ordered = sorted(rules.priority_bands, key=lambda b: b.floor)
    two_band_gaps = [ordered[i + 2].floor - ordered[i].ceiling for i in range(len(ordered) - 2)]
    assert largest_drop < min(two_band_gaps), (
        f"一項控制最多降 {largest_drop} 分，已經足以跨兩個分級（最窄 {min(two_band_gaps)} 分）"
    )


def test_control_levels_are_strictly_ordered(rules):
    """證據愈強、殘餘攻擊面愈小；UNKNOWN 與 NONE 併列在最保守的一端。"""
    effectiveness = rules.control_effectiveness
    assert effectiveness["STRONG"] < effectiveness["PARTIAL"] < effectiveness["NONE"]
    assert effectiveness["UNKNOWN"] >= effectiveness["NONE"]


def test_no_control_level_can_raise_the_score(rules):
    """折減只能往下，不能因為登錄了一項控制而變得更危險。"""
    baseline = _score(rules, 9.8, "NONE")
    for level in rules.control_effectiveness:
        assert _score(rules, 9.8, level) <= baseline


def test_control_and_reachability_are_independent_dimensions(rules):
    """同一個折減比例，在任何 reachability 下造成的分數差都成固定比例。"""
    for (a, b) in itertools.combinations(rules.reachability, 2):
        drop_a = _score(rules, 7.5, "NONE", a) - _score(rules, 7.5, "STRONG", a)
        drop_b = _score(rules, 7.5, "NONE", b) - _score(rules, 7.5, "STRONG", b)
        expected = rules.reachability[a] / rules.reachability[b]
        assert drop_a == pytest.approx(drop_b * expected, abs=0.02)
