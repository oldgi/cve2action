"""Day 23：兩種合成形式，以及工具自己做出的決定（ADR-day-23）。

藍圖 §10 的 Day 23 那一列寫得很清楚：加權相加與 §9.5 的幾何平均**都要實作並各跑一次**，
以 `calibrate` 的 tau 與 `acceptance` 的門檻決定採用哪一種，**不以論述決定**。

跑出來的結果是：

| | tau | discrimination | range_coverage | attributable |
|---|---:|---:|---:|---:|
| 加權相加 | 0.6 | 0.8421 | 0.443 | **37/37** |
| 幾何平均 | 0.6 | 0.9211 | 0.578 | **0/37** |

tau 一樣，所以沒有任何證據說幾何平均**排得更對**；它只是**分得更開**。
而它分得開的代價是逐項歸因整個消失——那是 Day 16 做 `gap_to` 的全部理由。

這個檔鎖住的就是這張表背後的性質，以及「幾何平均保留但不採用」這件事：
設定檔還在、能載入、能跑，只是 production 用加法。否決一個選項不等於把它刪掉。
"""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

import pytest
import yaml

from cve2action.models import ADDITIVE, GEOMETRIC, GEOMETRIC_FLOOR
from cve2action.rules import RulesError, load_rules
from cve2action.scoring.engine import explain_finding

ROOT = Path(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"
ADDITIVE_RULES = ROOT / "config/risk_rules.yaml"
GEOMETRIC_RULES = ROOT / "config/risk_rules.geometric.yaml"


@pytest.fixture(scope="module")
def additive():
    return load_rules(ADDITIVE_RULES)


@pytest.fixture(scope="module")
def geometric():
    return load_rules(GEOMETRIC_RULES)


def _context(**over) -> dict:
    base = {"environment": "PROD", "reachability": "INTERNET",
            "control_effectiveness": "NONE", "business_criticality": "CRITICAL"}
    base.update(over)
    return base


def _explain(rules, cvss: float = 7.0, path: float | None = 0.5, **over):
    return explain_finding({"asset": "A", "cve": "CVE-0000-0001", "cvss": cvss},
                           _context(**over), rules, path_score=path)


# --- 設定檔：兩種形式都要是真的，不是註解裡的構想 -----------------------------

def test_production_is_additive_and_the_alternative_is_kept(additive, geometric):
    assert additive.form == ADDITIVE, "Day 23 的決定：production 用加權相加"
    assert geometric.form == GEOMETRIC, "被否決的選項要留得下來、跑得起來"


def test_both_forms_use_the_same_weights(additive, geometric):
    """比較兩種形式時只能有一個變數。權重一樣，差別才真的是形式。"""
    assert additive.weights == geometric.weights


def test_unknown_form_is_rejected(tmp_path):
    raw = yaml.safe_load(ADDITIVE_RULES.read_text(encoding="utf-8"))
    raw["form"] = "harmonic"
    broken = tmp_path / "r.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(RulesError, match="form"):
        load_rules(broken)


def test_rules_without_a_form_default_to_additive():
    """v0.1 凍結檔沒有 form 欄位，行為必須與 Day 5–18 完全一樣。"""
    assert load_rules(ROOT / "config/risk_rules.v0.1.yaml").form == ADDITIVE


# --- 幾何平均是平均數，不是乘法 ----------------------------------------------

def test_exponents_sum_to_one_so_it_is_a_weighted_geometric_mean(geometric):
    """§9.5 的指數和為 1。這就是它是加權幾何平均、而不是「連乘」的理由。

    Day 18 我把它寫成「乘法」，暗示任何一項接近 0 就一票否決。那是錯的，
    已在文章與 ADR 更正。這條測試讓那個錯誤不會再回來。
    """
    assert sum(geometric.weights.values()) == pytest.approx(1.0)


def test_all_factors_at_one_gives_full_marks_under_both_forms(additive, geometric):
    """權重和為 1 的直接後果：全滿就是 10 分，兩種形式都一樣。"""
    for rules in (additive, geometric):
        explanation = _explain(rules, cvss=10.0, path=1.0)
        assert explanation.factor("exposure").value == 1.0
        assert explanation.score == pytest.approx(10.0, abs=0.01)


def test_a_floored_factor_does_not_veto_the_score(geometric):
    """幾何平均碰到 0 會整體歸零，所以有下限；下限的意義是「查無」不等於「沒有」。"""
    explanation = _explain(geometric, cvss=10.0, path=0.0)
    assert explanation.factor("path").value == 0.0
    # 0.05^0.2 ≈ 0.55——路徑項最多把分數打到約一半，不是歸零
    assert explanation.score > 4.0
    assert GEOMETRIC_FLOOR == 0.05


def test_geometric_scores_are_never_higher_than_additive_ones(additive, geometric):
    """算術平均不小於幾何平均（AM–GM）。這是數學性質，不是這份資料的巧合。"""
    for cvss in (0.0, 2.5, 5.0, 7.5, 10.0):
        for path in (None, 0.0, 0.3, 1.0):
            assert _explain(geometric, cvss, path).score <= _explain(
                additive, cvss, path).score + 0.01


# --- 為什麼不採用：逐項歸因會整個消失 ----------------------------------------

def test_additive_decomposition_rebuilds_the_score(additive):
    explanation = _explain(additive)
    assert explanation.additive
    assert sum(f.contribution for f in explanation.factors) == pytest.approx(
        explanation.score, abs=0.05)


def test_geometric_has_no_per_factor_contribution(geometric):
    """沒有「這一項貢獻幾分」可言，所以不報一個加不回總分的數字。"""
    explanation = _explain(geometric)
    assert not explanation.additive
    assert sum(f.contribution for f in explanation.factors) != pytest.approx(
        explanation.score, abs=0.05)
    machine = explanation.to_dict()
    assert all(f["contribution"] is None and f["share"] is None
               for f in machine["factors"])


def test_geometric_cannot_answer_why_it_ranks_below_the_one_above(geometric, additive):
    """Day 16 做 `gap_to` 的理由是「單看一列的算式答不了為什麼它在第三名」。

    幾何平均下總分差不等於逐項貢獻差之和，所以這個問題答不出來——
    回空 list 而不是回一組加不回去的數字。這就是 `attributable` 門檻擋下它的地方。
    """
    high, low = _explain(geometric, cvss=9.0), _explain(geometric, cvss=4.0)
    assert low.gap_to(high) == []
    assert _explain(additive, cvss=4.0).gap_to(_explain(additive, cvss=9.0))


def test_the_formula_string_follows_the_form(additive, geometric):
    """Day 16 的紀律：字串是從數字長出來的，所以算式形狀必須跟著形式走。"""
    assert "+" in _explain(additive).formula
    geometric_formula = _explain(geometric).formula
    assert "×" in geometric_formula and "^" in geometric_formula
    assert "+" not in geometric_formula


def test_the_rendered_explanation_says_contributions_do_not_apply(geometric):
    from cve2action.scoring import explain_row

    text = explain_row(_explain(geometric))
    assert "總分不是各項之和" in text


# --- 兩種形式的實跑結果（文章引用的數字） -------------------------------------

def _measured(rules_path: Path) -> dict:
    """跑一次完整流程，回傳 acceptance 的量測值。文章引用的數字從這裡來。"""
    from cve2action.attack_graph.build import build_graph
    from cve2action.attack_graph.identity import privilege_obtainable
    from cve2action.attack_graph.reachability import annotate
    from cve2action.collectors.epss import load_snapshots as load_epss
    from cve2action.collectors.kev import load_catalog
    from cve2action.collectors.nvd import load_snapshots
    from cve2action.io import read_asset_context, read_scanner
    from cve2action.scoring import rank_explained, row_from
    from cve2action.scoring.acceptance import evaluate, load_criteria
    from cve2action.scoring.path_score import compute

    def rows(name: str) -> list[dict]:
        with (NORTHSTAR / name).open(encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    rules = load_rules(rules_path)
    assets, services = rows("assets.csv"), rows("services.csv")
    graph = build_graph(assets, rows("asset_interfaces.csv"), services,
                        rows("network_edges.csv"), rows("identity_edges.csv"))
    annotate(graph, rows("network_edges.csv"), rows("network_policies.csv"),
             {a["asset_id"]: a["zone"] for a in assets})
    snapshots = load_snapshots(ROOT / "data/snapshots/nvd")
    vectors = {}
    for cve, record in snapshots.items():
        chosen = record.cvss.preferred(rules.cvss_version_preference)
        if chosen is not None:
            vectors[cve.upper()] = chosen.vector
    scan = rows("scanner.csv")
    privileges = {a["asset_id"]: privilege_obtainable(a["asset_id"], services, scan, vectors)
                  for a in assets}
    paths = {asset: score.value for asset, score in compute(graph, privileges).items()}

    explanations = rank_explained(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"), rules, snapshots,
        load_epss(ROOT / "data/snapshots/epss"), load_catalog(ROOT / "data/snapshots/kev"),
        rows("controls.csv"), date(2026, 9, 24), paths)
    result = evaluate(load_criteria(ROOT / "config/acceptance.yaml"), rules,
                      [row_from(e) for e in explanations], explanations,
                      today=date(2026, 10, 7))
    return {c.id: c for c in result.checks} | {"accepted": result.accepted}


@pytest.fixture(scope="module")
def additive_run():
    return _measured(ADDITIVE_RULES)


@pytest.fixture(scope="module")
def geometric_run():
    return _measured(GEOMETRIC_RULES)


def test_additive_passes_every_criterion_that_is_not_waived(additive_run):
    assert additive_run["accepted"]
    assert additive_run["attributable"].measured == 1.0
    assert additive_run["attributable"].detail.startswith("37/37")


def test_geometric_is_blocked_by_attributable(geometric_run):
    """決定是工具下的，不是我論述出來的：這一條沒過、沒有豁免，所以 exit 1。"""
    assert not geometric_run["accepted"]
    assert geometric_run["attributable"].measured == 0.0
    assert geometric_run["attributable"].status == "FAIL"


def test_geometric_really_does_spread_scores_better(geometric_run, additive_run):
    """誠實記錄對方贏的地方。它確實分得更開——但分得開不是分得對。"""
    assert geometric_run["discrimination"].measured > additive_run[
        "discrimination"].measured
    assert geometric_run["range_coverage"].measured > additive_run[
        "range_coverage"].measured


def test_the_article_numbers(additive_run, geometric_run):
    assert additive_run["discrimination"].measured == pytest.approx(0.8421)
    assert geometric_run["discrimination"].measured == pytest.approx(0.9211)
    assert additive_run["range_coverage"].measured == pytest.approx(0.443)
    assert geometric_run["range_coverage"].measured == pytest.approx(0.578)
