"""Day 17：校準測試——人工排序 vs 模型排序，分歧必須有書面解釋。

這裡鎖住的不是「相關係數要多高」。係數高只代表模型複製了排序者的直覺。
鎖住的是流程：基準檔要有理由、分歧要有結論、結論要是三種可行動的其中一種。
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
from cve2action.scoring import rank
from cve2action.scoring.calibration import (
    VERDICTS,
    CalibrationError,
    compare,
    load_baseline,
    report,
)

ROOT = Path(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"
BASELINE = ROOT / "data/calibration/day-17-expert-ranking.yaml"
# Day 5–18 的基準用 **v0.1 凍結版**規則：那些數字是已發表文章的依據，
# 必須永遠重現得出來。production 設定（config/risk_rules.yaml）自 Day 23 起
# 多了路徑項，分數因此不同——那是預期的，不是回歸。
RULES = load_rules(ROOT / "config/risk_rules.v0.1.yaml")
AS_OF = date(2026, 9, 24)


def _controls() -> list[dict]:
    with (NORTHSTAR / "controls.csv").open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def calibration():
    snapshots = ROOT / "data/snapshots"
    rows = rank(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(snapshots / "nvd"), load_epss(snapshots / "epss"),
        load_catalog(snapshots / "kev"), _controls(), AS_OF,
    )
    return compare(load_baseline(BASELINE), rows)


# --- 驗收條件：藍圖 Day 17「差異都有書面解釋」 ------------------------------

def test_no_disagreement_is_left_unexplained(calibration):
    assert not calibration.has_unexplained, [
        f"{d.higher_for_expert.key} vs {d.higher_for_model.key}"
        for d in calibration.unexplained
    ]


def test_every_resolution_picks_an_actionable_verdict(calibration):
    """model／expert／data 各自對應不同動作；寫個模稜兩可的結論等於沒寫。"""
    for item in calibration.disagreements:
        assert item.verdict in VERDICTS
        assert len(item.explanation.strip()) > 40, "一句話交代不算解釋"


def test_expert_verdicts_require_an_adr():
    """判定『人對』就是在說模型要改——那必須留下 ADR，不能只改一行權重。"""
    raw = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    for entry in raw.get("resolutions") or []:
        if entry.get("verdict") == "expert":
            assert "ADR" in entry.get("follow_up", ""), entry["pair"]


# --- 基準檔本身的規矩 -------------------------------------------------------

def test_baseline_states_who_ranked_and_when():
    raw = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    assert raw["ranked_by"] and raw["authored_on"]
    assert "findings" in raw and len(raw["findings"]) >= 5, "藍圖要求至少五個案例"


def test_every_ranked_finding_has_a_rationale():
    assert load_baseline(BASELINE)  # load_baseline 會對缺理由的條目拋錯


def test_baseline_with_a_missing_rationale_is_rejected(tmp_path):
    raw = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    raw["findings"][0]["rationale"] = "  "
    broken = tmp_path / "b.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CalibrationError, match="rationale"):
        load_baseline(broken)


def test_baseline_with_duplicate_ranks_is_rejected(tmp_path):
    raw = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    raw["findings"][1]["rank"] = raw["findings"][0]["rank"]
    broken = tmp_path / "b.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    with pytest.raises(CalibrationError, match="ranks must be"):
        load_baseline(broken)


def test_unknown_verdict_is_rejected(tmp_path):
    raw = yaml.safe_load(BASELINE.read_text(encoding="utf-8"))
    raw["resolutions"][0]["verdict"] = "大概吧"
    broken = tmp_path / "b.yaml"
    broken.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    rows = [{"asset": f["asset"], "cve": f["cve"], "priority_score": 1.0, "priority": "Low"}
            for f in raw["findings"]]
    with pytest.raises(CalibrationError, match="verdict"):
        compare(load_baseline(broken), rows)


# --- 比較本身 ---------------------------------------------------------------

def test_the_numbers_the_article_quotes(calibration):
    """文章引用這組數字；改動資料集或權重就要一起更新，不能悄悄漂移。"""
    assert calibration.pairs == 10
    assert (calibration.concordant, calibration.discordant) == (9, 1)
    assert calibration.tau == 0.8


def test_the_single_disagreement_is_the_one_we_documented(calibration):
    assert len(calibration.disagreements) == 1
    item = calibration.disagreements[0]
    assert item.higher_for_expert.key == "NS-APP-BILLING-01/CVE-2023-34362"
    assert item.higher_for_model.key == "NS-EDGE-RTR-01/CVE-2023-20198"
    assert item.verdict == "model"


def test_the_disagreement_is_entirely_exposure(calibration):
    """結論說『分得出勝負的只有曝險』——這句話要能被資料證實。"""
    item = calibration.disagreements[0]
    expert, model = item.higher_for_expert, item.higher_for_model
    assert model.model_score - expert.model_score == pytest.approx(1.07, abs=0.01)


def test_ties_count_as_neither_agreement_nor_disagreement():
    """模型同分時它沒有表態，不該被算成一致——那會灌水。"""
    baseline = {
        "findings": [
            {"rank": 1, "asset": "A", "cve": "CVE-1", "rationale": "x" * 50},
            {"rank": 2, "asset": "B", "cve": "CVE-2", "rationale": "y" * 50},
        ],
    }
    rows = [{"asset": "A", "cve": "CVE-1", "priority_score": 5.0, "priority": "Medium"},
            {"asset": "B", "cve": "CVE-2", "priority_score": 5.0, "priority": "Medium"}]
    result = compare(baseline, rows)
    assert (result.concordant, result.discordant, result.pairs) == (0, 0, 0)
    assert result.tau == 0.0


def test_a_finding_missing_from_the_model_output_is_an_error():
    baseline = {"findings": [{"rank": 1, "asset": "GHOST", "cve": "CVE-1",
                              "rationale": "z" * 50}]}
    with pytest.raises(CalibrationError, match="不在模型輸出中"):
        compare(baseline, [])


def test_report_names_every_unexplained_disagreement():
    baseline = {
        "findings": [
            {"rank": 1, "asset": "A", "cve": "CVE-1", "rationale": "x" * 50},
            {"rank": 2, "asset": "B", "cve": "CVE-2", "rationale": "y" * 50},
        ],
    }
    rows = [{"asset": "B", "cve": "CVE-2", "priority_score": 9.0, "priority": "Critical"},
            {"asset": "A", "cve": "CVE-1", "priority_score": 5.0, "priority": "Medium"}]
    result = compare(baseline, rows)
    assert result.has_unexplained
    assert "沒有書面解釋" in report(result)


# --- CLI --------------------------------------------------------------------

def test_cli_calibrate_passes_on_the_committed_baseline(capsys):
    code = cli_main([
        "calibrate",
        "--scanner", str(NORTHSTAR / "scanner.csv"),
        "--context", str(NORTHSTAR / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.v0.1.yaml"),
        "--snapshots", str(ROOT / "data/snapshots/nvd"),
        "--epss", str(ROOT / "data/snapshots/epss"),
        "--kev", str(ROOT / "data/snapshots/kev"),
        "--controls", str(NORTHSTAR / "controls.csv"),
        "--as-of", "2026-09-24",
        "--baseline", str(BASELINE),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "Kendall tau-b = 0.8" in out
    assert "結論：模型對" in out
