"""Day 18：評分門檻——「可用」要量得出來。

兩件事在這裡被鎖住：
1. structural 與 empirical 不能混為一談（這個混淆讓我把資料集的缺口誤判成公式缺陷七天）。
2. 沒過的條件必須有 waiver，waiver 必須寫根因與重新量測的日子；否則 exit 1。
"""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

import pytest
import yaml

from cve2action.cli import main as cli_main
from cve2action.collectors.epss import load_snapshots as load_epss
from cve2action.collectors.kev import load_catalog
from cve2action.collectors.nvd import load_snapshots
from cve2action.io import read_asset_context, read_scanner
from cve2action.rules import load_rules
from cve2action.scoring import rank_explained, row_from
from cve2action.scoring.acceptance import (
    AcceptanceError,
    evaluate,
    load_criteria,
    report,
)

ROOT = Path(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"
CRITERIA = ROOT / "config/acceptance.yaml"
RULES = load_rules(ROOT / "config/risk_rules.yaml")
AS_OF = date(2026, 9, 24)


def _controls() -> list[dict]:
    with (NORTHSTAR / "controls.csv").open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def acceptance():
    snapshots = ROOT / "data/snapshots"
    explanations = rank_explained(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(snapshots / "nvd"), load_epss(snapshots / "epss"),
        load_catalog(snapshots / "kev"), _controls(), AS_OF,
    )
    rows = [row_from(e) for e in explanations]
    return evaluate(load_criteria(CRITERIA), RULES, rows, explanations)


# --- 門檻結論 ---------------------------------------------------------------

def test_v01_is_accepted_with_every_failure_waived(acceptance):
    assert acceptance.accepted
    assert not acceptance.blocking


def test_the_numbers_the_article_quotes(acceptance):
    by_id = {c.id: c for c in acceptance.checks}
    assert by_id["discrimination"].measured == 0.7368
    assert by_id["band_balance"].measured == 0.6316
    assert by_id["range_coverage"].measured == 0.44
    assert by_id["ceiling_saturation"].measured == 0.0263
    passed = sum(1 for c in acceptance.checks if c.passed)
    assert (passed, len(acceptance.checks), len(acceptance.waived)) == (6, 8, 2)


def test_the_two_waived_criteria_are_the_ones_we_documented(acceptance):
    assert {c.id for c in acceptance.waived} == {"band_balance", "range_coverage"}


def test_every_waiver_names_a_root_cause_and_a_revisit_day(acceptance):
    for check in acceptance.waived:
        assert len(check.waiver["reason"].strip()) > 60
        assert check.waiver["revisit_on"], check.id


# --- structural：公式的性質，與資料集無關 -----------------------------------

def test_the_formula_can_reach_every_band(acceptance):
    """從 Day 11 到 Day 17，我把『Northstar 產不出 Low』寫成『公式產不出 Low』。

    這條測試就是當初應該先寫的那十行：公式四個分級全部構造得出來。
    """
    check = next(c for c in acceptance.checks if c.id == "bands_reachable")
    assert check.passed
    assert set(check.measured) == {"Critical", "High", "Medium", "Low"}


def test_low_is_reachable_but_northstar_has_no_such_asset():
    """公式產得出 Low；Northstar 沒有『低嚴重度 × 隔離 × 不重要』這個組合。"""
    from cve2action.scoring import score_finding

    row = score_finding(
        {"asset": "PROBE", "cve": "CVE-0000-0001", "cvss": 5.5},
        {"environment": "NON_PROD", "reachability": "ISOLATED",
         "control_effectiveness": "STRONG", "business_criticality": "NORMAL"}, RULES)
    assert row["priority"] == "Low" and row["priority_score"] == 3.95


def test_structural_checks_do_not_depend_on_the_dataset(acceptance):
    """抽掉所有資料重跑，structural 的結論必須一字不差——它們問的是公式，不是資料。"""
    raw = load_criteria(CRITERIA)
    structural_only = dict(raw, criteria=[c for c in raw["criteria"]
                                          if c["kind"] == "structural"])
    empty = evaluate(structural_only, RULES, [], [])
    assert [c.id for c in empty.checks] == ["bands_reachable", "degradation_safe", "monotonic"]
    for check in empty.checks:
        original = next(c for c in acceptance.checks if c.id == check.id)
        assert (check.passed, check.measured) == (original.passed, original.measured)


def test_empirical_criteria_refuse_to_report_on_an_empty_dataset():
    """沒有資料就量不出 empirical——報個 0 比報錯更危險。"""
    with pytest.raises(AcceptanceError, match="no measurement"):
        evaluate(load_criteria(CRITERIA), RULES, [], [])


# --- 設定檔規矩 -------------------------------------------------------------

def test_waiver_without_a_reason_is_rejected(tmp_path):
    raw = yaml.safe_load(CRITERIA.read_text(encoding="utf-8"))
    raw["waivers"][0]["reason"] = "  "
    broken = tmp_path / "a.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(AcceptanceError, match="reason"):
        load_criteria(broken)


def test_waiver_without_a_revisit_day_is_rejected(tmp_path):
    raw = yaml.safe_load(CRITERIA.read_text(encoding="utf-8"))
    del raw["waivers"][0]["revisit_on"]
    broken = tmp_path / "a.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(AcceptanceError, match="revisit_on"):
        load_criteria(broken)


def test_waiver_for_an_unknown_criterion_is_rejected(tmp_path):
    raw = yaml.safe_load(CRITERIA.read_text(encoding="utf-8"))
    raw["waivers"][0]["id"] = "not_a_criterion"
    broken = tmp_path / "a.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(AcceptanceError, match="unknown criterion"):
        load_criteria(broken)


def test_removing_a_waiver_turns_the_gate_red(tmp_path, acceptance):
    """豁免是決定，拿掉就該擋下來——否則 waiver 只是裝飾。"""
    raw = yaml.safe_load(CRITERIA.read_text(encoding="utf-8"))
    raw["waivers"] = []
    thin = tmp_path / "a.yaml"
    thin.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")

    snapshots = ROOT / "data/snapshots"
    explanations = rank_explained(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(snapshots / "nvd"), load_epss(snapshots / "epss"),
        load_catalog(snapshots / "kev"), _controls(), AS_OF,
    )
    result = evaluate(load_criteria(thin), RULES, [row_from(e) for e in explanations],
                      explanations)
    assert not result.accepted
    assert {c.id for c in result.blocking} == {"band_balance", "range_coverage"}
    assert "未通過" in report(result)


def test_criteria_declare_which_rules_version_they_apply_to():
    raw = yaml.safe_load(CRITERIA.read_text(encoding="utf-8"))
    assert raw["applies_to_rules_version"] == RULES.version, (
        "門檻是對某一版規則量的；規則進版就要重新量並更新這一行"
    )


# --- CLI --------------------------------------------------------------------

def test_cli_acceptance_exits_zero_and_prints_the_verdict(capsys):
    code = cli_main([
        "acceptance",
        "--scanner", str(NORTHSTAR / "scanner.csv"),
        "--context", str(NORTHSTAR / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.yaml"),
        "--criteria", str(CRITERIA),
        "--snapshots", str(ROOT / "data/snapshots/nvd"),
        "--epss", str(ROOT / "data/snapshots/epss"),
        "--kev", str(ROOT / "data/snapshots/kev"),
        "--controls", str(NORTHSTAR / "controls.csv"),
        "--as-of", "2026-09-24",
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "通過 6/8" in out and "WAIVED" in out


# --- Day 18：對外的 P0–P3 層級（ADR-day-18-crps-tier-mapping） ---------------

def test_every_band_maps_to_a_unique_tier_with_an_action():
    tiers = [(b.label, b.tier, b.action) for b in RULES.priority_bands]
    assert [t for _l, t, _a in tiers] == ["P0", "P1", "P2", "P3"]
    assert all(action for _l, _t, action in tiers), "每個層級都要說得出該做什麼"
    assert len({t for _l, t, _a in tiers}) == 4


def test_rules_without_tiers_are_rejected(tmp_path):
    from cve2action.rules import RulesError
    from cve2action.rules import load_rules as load
    text = (ROOT / "config/risk_rules.yaml").read_text(encoding="utf-8")
    broken = tmp_path / "r.yaml"
    broken.write_text(text.replace("tier: P0, ", ""), encoding="utf-8")
    with pytest.raises(RulesError, match="tier"):
        load(broken)


def test_tier_tracks_the_internal_band_exactly():
    """tier 是 label 的對外名稱，不是另一套判斷——兩者永遠同步。"""
    expected = {b.label: b.tier for b in RULES.priority_bands}
    for score in [round(x * 0.1, 1) for x in range(0, 101)]:
        assert RULES.tier_for(score) == expected[RULES.band_for(score)]


def test_blueprint_thresholds_are_deliberately_not_adopted():
    """藍圖的 80/60/35 是為 CRPS 乘法模型訂的；搬到加法分數上會產生 21 筆 P0。

    這條測試把那個量測結果釘住，免得之後有人「順手對齊藍圖」而不知道代價。
    """
    snapshots = ROOT / "data/snapshots"
    rows = [row_from(e) for e in rank_explained(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(snapshots / "nvd"), load_epss(snapshots / "epss"),
        load_catalog(snapshots / "kev"), _controls(), AS_OF,
    )]
    scored = [float(r["priority_score"]) * 10 for r in rows if r["priority_score"] != ""]
    as_blueprint = sum(1 for x in scored if x >= 80)
    as_shipped = sum(1 for r in rows if r["priority_tier"] == "P0")
    assert (as_blueprint, as_shipped) == (21, 9)
