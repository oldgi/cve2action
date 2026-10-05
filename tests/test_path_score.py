"""Day 23：攻擊路徑分數 A（藍圖 §9.3），以及它進入公式之後要守住的性質。

路徑進分數有兩個容易出事的地方，兩個都在這裡鎖住：

1. **查無路徑不得等於安全。** Day 22 已經證明那六台「查無路徑」沒有一台是被擋住的。
   所以 `A_Reachability` 的下限是 0.05 而不是 0——給 0 等於宣告「證明不可達」。
2. **沒有圖資料時整項移除，不補零。** 補零是「走不到」這個事實的宣告，
   而我們只是沒查。權重退回 exposure，那是同一件事的另一個尺度。
"""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

import pytest

from cve2action.attack_graph.build import build_graph
from cve2action.attack_graph.identity import PRIVILEGE_RANK, privilege_obtainable
from cve2action.attack_graph.reachability import annotate
from cve2action.collectors.nvd import load_snapshots
from cve2action.rules import load_rules
from cve2action.scoring import path_score
from cve2action.scoring.engine import explain_finding
from cve2action.scoring.path_score import UNREACHED_FLOOR, WEIGHTS

ROOT = Path(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"
AS_OF = date(2026, 9, 24)


def _rows(name: str) -> list[dict]:
    with (NORTHSTAR / name).open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


@pytest.fixture(scope="module")
def rules():
    return load_rules(ROOT / "config/risk_rules.yaml")


@pytest.fixture(scope="module")
def scores():
    assets, services = _rows("assets.csv"), _rows("services.csv")
    graph = build_graph(assets, _rows("asset_interfaces.csv"), services,
                        _rows("network_edges.csv"), _rows("identity_edges.csv"))
    annotate(graph, _rows("network_edges.csv"), _rows("network_policies.csv"),
             {a["asset_id"]: a["zone"] for a in assets})
    vectors = {}
    for cve, record in load_snapshots(ROOT / "data/snapshots/nvd").items():
        chosen = record.cvss.preferred(("3.1", "4.0"))
        if chosen is not None:
            vectors[cve.upper()] = chosen.vector
    scan = _rows("scanner.csv")
    privileges = {a["asset_id"]: privilege_obtainable(a["asset_id"], services, scan, vectors)
                  for a in assets}
    return path_score.compute(graph, privileges)


# --- §9.3 的四項 -------------------------------------------------------------

def test_weights_match_the_blueprint():
    assert WEIGHTS == {"reachability": 0.40, "privilege": 0.25,
                       "crown_jewel": 0.25, "hops": 0.10}
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


def test_every_asset_gets_a_score_in_range(scores):
    assert len(scores) == 20
    assert all(0.0 <= s.value <= 1.0 for s in scores.values())


def test_unreached_assets_keep_the_floor_not_zero(scores):
    """查無路徑的可達性取下限。Day 22：那六台沒有一台是被擋住的。"""
    unreached = [s for s in scores.values() if s.hops is None]
    assert unreached, "資料集裡要有查無路徑的例子，否則這條測試是空的"
    for score in unreached:
        assert score.components["reachability"] == UNREACHED_FLOOR
        assert score.value > 0.0, "下限的意義就是分數不歸零"
        assert "不是證明不可達" in score.detail


def test_shorter_path_scores_higher_when_everything_else_is_equal(scores):
    """A_Hops ＝ 1/跳數。同樣都通往 Crown Jewel 時，近的要比遠的高。"""
    jewel_bound = [s for s in scores.values() if s.hops and s.reaches_jewel]
    by_hops: dict[int, list[float]] = {}
    for score in jewel_bound:
        by_hops.setdefault(score.hops, []).append(score.components["hops"])
    for hops, values in by_hops.items():
        assert all(v == pytest.approx(1.0 / hops) for v in values)
    assert min(by_hops) < max(by_hops), "資料集要同時有近的與遠的，比較才有意義"


def test_unknown_privilege_removes_the_term_and_gives_the_weight_back(scores):
    """不猜中間值——跟 Day 14 缺威脅資料時用的是同一招。"""
    unknown = [s for s in scores.values() if "privilege" not in s.components]
    for score in unknown:
        assert score.applied_weights["reachability"] == pytest.approx(
            WEIGHTS["reachability"] + WEIGHTS["privilege"])
        assert "權限未知" in score.detail
        assert sum(score.applied_weights.values()) == pytest.approx(1.0)


def test_weights_always_sum_to_one(scores):
    for score in scores.values():
        assert sum(score.applied_weights.values()) == pytest.approx(1.0)


def test_privilege_is_normalised_against_the_highest_rank(scores):
    top = max(PRIVILEGE_RANK.values())
    for score in scores.values():
        if "privilege" in score.components:
            assert 0.0 <= score.components["privilege"] <= 1.0
            assert score.components["privilege"] * top == pytest.approx(
                round(score.components["privilege"] * top))


# --- 路徑項進公式 ------------------------------------------------------------

def _context(**over) -> dict:
    base = {"environment": "PROD", "reachability": "INTERNET",
            "control_effectiveness": "NONE", "business_criticality": "CRITICAL"}
    base.update(over)
    return base


def _score(rules, path: float | None) -> float:
    return explain_finding({"asset": "A", "cve": "CVE-0000-0001", "cvss": 7.0},
                           _context(), rules, path_score=path).score


def test_path_term_is_monotonic(rules):
    values = [_score(rules, a / 10) for a in range(11)]
    assert values == sorted(values)


def test_missing_path_data_does_not_lower_the_score(rules):
    """沒有圖資料不得換來比較安全的名次——UNKNOWN 不得降低風險的第五次套用。"""
    absent = _score(rules, None)
    assert absent >= _score(rules, 0.0)
    assert absent >= _score(rules, UNREACHED_FLOOR)


def test_missing_path_data_returns_the_weight_to_exposure(rules):
    explanation = explain_finding(
        {"asset": "A", "cve": "CVE-0000-0001", "cvss": 7.0}, _context(), rules)
    assert explanation.factor("path") is None, "沒資料就不該有這一項，不是補零"
    exposure = explanation.factor("exposure")
    assert exposure.weight == pytest.approx(
        rules.weights["exposure"] + rules.weights["path"])
    assert sum(f.weight for f in explanation.factors) == pytest.approx(1.0)


def test_path_weight_is_optional_so_the_frozen_rules_still_load():
    """Day 5–18 的已發表數字靠 v0.1 凍結檔重現，它沒有 path 權重。"""
    frozen = load_rules(ROOT / "config/risk_rules.v0.1.yaml")
    assert "path" not in frozen.weights
    assert sum(frozen.weights.values()) == pytest.approx(1.0)
