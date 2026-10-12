"""Day 29：四個必測情境（藍圖 §8.4）。

**這些測試釘的是「量到什麼」，不是「應該要過」。** 情境二與情境一的 PARTIAL 是
模型在這份資料上的真實表現；哪天有人調權重讓它們變成 PASS，這裡會紅——
那時要做的是重寫 Day 29 的結論，而不是改測試讓它綠。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import data  # noqa: E402
import scenarios  # noqa: E402


@pytest.fixture(scope="module")
def results():
    p = data.run()
    return p, {s.number: s for s in scenarios.run_all(p)}


def test_scenario_one_high_cvss_isolated_is_ranked_low(results):
    _p, s = results
    one = s[1]
    assert len(one.cases) == 5
    assert sorted(c["rank"] for c in one.cases) == [29, 31, 32, 33, 38]
    # 判準是 #30 以後；監控主機的 Log4Shell 在 #29，差一名。線是事先畫的，不事後挪
    assert one.verdict == scenarios.PARTIAL
    assert [c["asset"] for c in one.cases if not c["ok"]] == ["NS-MON-01"]
    # 對照組：CVSS 把它們排在並列第 1 或第 7
    assert {c["cvss_rank"] for c in one.cases} == {1, 7}


def test_scenario_two_moves_up_but_not_to_the_top(results):
    _p, s = results
    two = s[2]
    assert [(c["asset"], c["cve"]) for c in two.cases] == [("NS-BACKUP-01", "CVE-2017-0144")]
    case = two.cases[0]
    assert (case["cvss_rank"], case["rank"]) == (19, 14)
    assert (case["tier_before"], case["tier"]) == ("P1", "P0")
    assert two.verdict == scenarios.PARTIAL


def test_scenario_three_controls_lower_the_guarded_twin(results):
    _p, s = results
    three = s[3]
    pairs = {(c["cve"], c["guarded"], c["open"], c["guarded_rank"], c["open_rank"])
             for c in three.cases}
    assert pairs == {
        ("CVE-2021-41773", "NS-WEB-PORTAL-01", "NS-WEB-PORTAL-02", 16, 3),
        ("CVE-2023-44487", "NS-WEB-PORTAL-01", "NS-WEB-PORTAL-02", 25, 8),
    }
    assert three.verdict == scenarios.PASS


def test_scenario_four_one_connection_cuts_half(results):
    _p, s = results
    four = s[4]
    assert four.cases[0]["measure"] == "關閉 NS-JUMP-01:3389 的連線"
    assert four.cases[0]["paths"] == "30 → 15"
    assert not four.cases[0]["registered"]
    assert four.verdict == scenarios.PASS


def test_no_case_is_not_a_pass():
    s = scenarios.Scenario(9, "x", "x", "x")
    assert s.verdict == scenarios.NO_CASE != scenarios.PASS


def test_model_agrees_with_the_expert_more_than_cvss(results):
    p, _s = results
    result = scenarios.versus_expert(p, ROOT / "data/calibration/day-17-expert-ranking.yaml")
    assert result["n"] == 5
    assert result["model"] == (0.6, 8, 2, 0)
    assert result["cvss"] == (0.527, 7, 2, 1)


def test_tau_b_counts_ties_in_the_denominator():
    """CVSS 同分很常見；把平手丟掉，CVSS 會看起來比實際更有主見。"""
    tau, c, d, t = scenarios.tau_b([1, 2, 3], [9.8, 9.8, 1.0])
    assert (c, d, t) == (2, 0, 1)
    assert tau == round(2 / (3 * 2) ** 0.5, 4)
