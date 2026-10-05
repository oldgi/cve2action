"""Day 16：Explain——分數的結構化說明。

最重要的一條在最前面：CSV 列與 reason 字串都必須是同一份 Explanation 的投影。
這條不成立的話，理由就會像 Day 6 的規格文件一樣，慢慢跟程式漂開。
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

from cve2action.cli import main as cli_main
from cve2action.collectors.epss import load_snapshots as load_epss
from cve2action.collectors.kev import load_catalog
from cve2action.collectors.nvd import load_snapshots
from cve2action.io import read_asset_context, read_scanner
from cve2action.models import DECISION_NEEDS_CONTEXT, OUTPUT_COLUMNS
from cve2action.rules import load_rules
from cve2action.scoring import (
    Explanation,
    Factor,
    explain_finding,
    rank,
    rank_explained,
    row_from,
    score_finding,
)

ROOT = Path(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"
# Day 5–18 的基準用 **v0.1 凍結版**規則：那些數字是已發表文章的依據，
# 必須永遠重現得出來。production 設定（config/risk_rules.yaml）自 Day 23 起
# 多了路徑項，分數因此不同——那是預期的，不是回歸。
RULES = load_rules(ROOT / "config/risk_rules.v0.1.yaml")
AS_OF = date(2026, 9, 24)

CTX = {"environment": "PROD", "reachability": "INTERNET",
       "control_effectiveness": "STRONG", "business_criticality": "CRITICAL"}


@pytest.fixture(scope="module")
def ordered() -> list[Explanation]:
    snapshots = ROOT / "data/snapshots"
    return rank_explained(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(snapshots / "nvd"), load_epss(snapshots / "epss"),
        load_catalog(snapshots / "kev"), list(_rows("controls.csv")), AS_OF,
    )


def _rows(name: str):
    import csv
    with (NORTHSTAR / name).open(encoding="utf-8-sig", newline="") as stream:
        yield from csv.DictReader(stream)


# --- 投影關係：字串不可能與數字對不上 ---------------------------------------

def test_every_number_in_the_reason_comes_from_the_explanation(ordered):
    """逐筆把 reason 裡的每個數字抓出來，必須都在 Explanation 的欄位裡找得到。

    這是 Day 16 的核心主張。字串若是另外拼的，改公式時它會悄悄說錯話。
    """
    for explanation in ordered:
        reason = explanation.to_reason()
        if explanation.decision == DECISION_NEEDS_CONTEXT:
            assert reason.startswith("needs context: ")
            continue
        known = {f"{explanation.score:g}"}
        for factor in explanation.factors:
            known.add(f"{factor.value:g}")
            for value in factor.inputs.values():
                if isinstance(value, (int, float)):
                    known.add(f"{value:g}")
        # reason 裡的數字：排除來源字串中的日期與 CVE 編號
        stripped = re.sub(r"\[[^\]]*\]", "", reason)
        for number in re.findall(r"\d+(?:\.\d+)?", stripped):
            assert number in known, (
                f"{explanation.cve} on {explanation.asset}: reason 裡的 {number} "
                f"在 Explanation 中找不到對應值\n{reason}"
            )


def test_row_is_a_projection_of_the_explanation(ordered):
    for explanation in ordered:
        row = row_from(explanation)
        assert list(row) == list(OUTPUT_COLUMNS)
        assert row["reason"] == explanation.to_reason()
        assert row["decision"] == explanation.decision
        if explanation.scored:
            assert row["priority_score"] == explanation.score
            assert row["priority"] == explanation.band


def test_rank_and_rank_explained_cannot_disagree(ordered):
    rows = rank(
        read_scanner(NORTHSTAR / "scanner.csv"),
        read_asset_context(NORTHSTAR / "asset_context.csv"),
        RULES, load_snapshots(ROOT / "data/snapshots/nvd"),
        load_epss(ROOT / "data/snapshots/epss"), load_catalog(ROOT / "data/snapshots/kev"),
        list(_rows("controls.csv")), AS_OF,
    )
    assert [(r["asset"], r["cve"]) for r in rows] == [(e.asset, e.cve) for e in ordered]


def test_score_finding_still_returns_the_same_row():
    """Day 15 之前的呼叫方式不變——重構不該讓既有使用者改碼。"""
    finding = {"asset": "A", "cve": "CVE-0000-1", "cvss": "8.8"}
    assert score_finding(finding, CTX, RULES) == row_from(
        explain_finding(finding, CTX, RULES))


# --- 分解 -------------------------------------------------------------------

def test_contributions_add_up_to_the_score():
    explanation = explain_finding({"asset": "A", "cve": "CVE-0000-1", "cvss": "8.8"},
                                  CTX, RULES)
    total = sum(f.contribution for f in explanation.factors)
    assert round(total, 2) == pytest.approx(explanation.score, abs=0.02)
    assert sum(f.share_of(explanation.score) for f in explanation.factors) \
        == pytest.approx(1.0, abs=0.01)


def test_degraded_run_has_three_factors_and_says_so():
    """沒有威脅資料時威脅項不存在，而不是值為 0 的一項。"""
    explanation = explain_finding({"asset": "A", "cve": "CVE-0000-1", "cvss": "8.8"},
                                  CTX, RULES)
    assert [f.key for f in explanation.factors] == ["severity", "exposure", "business"]
    assert explanation.degraded is True
    # 權重退回 severity，不是按比例分配
    assert explanation.factor("severity").weight == pytest.approx(0.50)
    assert explanation.factor("exposure").weight == pytest.approx(0.25)


def test_every_factor_carries_a_source(ordered):
    for explanation in ordered:
        for factor in explanation.factors:
            assert factor.source, f"{explanation.cve}: {factor.key} 沒有來源"


def test_needs_context_explains_what_is_missing_and_scores_nothing():
    explanation = explain_finding({"asset": "GHOST", "cve": "CVE-0000-1", "cvss": "9.8"},
                                  None, RULES)
    assert explanation.scored is False
    assert explanation.score is None
    assert explanation.gaps == ("asset not found in asset_context",)
    assert explanation.formula == ""


# --- 比較：為什麼排在這裡 ---------------------------------------------------

def test_gap_decomposition_adds_up_to_the_score_difference(ordered):
    scored = [e for e in ordered if e.scored]
    for lower, upper in zip(scored[1:], scored, strict=False):
        total = sum(delta for _key, delta in lower.gap_to(upper))
        assert round(total, 2) == pytest.approx(
            round(lower.score - upper.score, 2), abs=0.02)


def test_a_finding_can_lose_overall_while_winning_a_factor(ordered):
    """排序的理由不是一個數字。RC4 的業務衝擊高於前一名，卻仍排在它後面。"""
    rc4 = next(e for e in ordered if e.cve == "CVE-2013-2566")
    position = ordered.index(rc4)
    above = ordered[position - 1]
    deltas = dict(rc4.gap_to(above))
    assert rc4.score < above.score
    assert deltas["business"] > 0
    assert deltas["severity"] < 0


# --- CLI --------------------------------------------------------------------

def _explain_argv(*extra: str) -> list[str]:
    return [
        "explain",
        "--scanner", str(NORTHSTAR / "scanner.csv"),
        "--context", str(NORTHSTAR / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.v0.1.yaml"),
        "--snapshots", str(ROOT / "data/snapshots/nvd"),
        "--epss", str(ROOT / "data/snapshots/epss"),
        "--kev", str(ROOT / "data/snapshots/kev"),
        "--controls", str(NORTHSTAR / "controls.csv"),
        "--as-of", "2026-09-24", *extra,
    ]


def test_cli_explain_prints_the_breakdown(capsys):
    assert cli_main(_explain_argv("--cve", "CVE-2020-1472")) == 0
    out = capsys.readouterr().out
    assert "NS-AD-DC-01" in out and "9" in out
    assert "formula" in out
    for symbol in ("S severity", "T threat", "E exposure", "B business"):
        assert symbol in out


def test_cli_explain_json_is_machine_readable(capsys):
    assert cli_main(_explain_argv("--cve", "CVE-2020-1472", "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    item = payload[0]
    assert item["score"] == 9.0 and item["band"] == "Critical" and item["rank"] == 9
    assert {f["symbol"] for f in item["factors"]} == {"S", "T", "E", "B"}
    assert all(f["source"] for f in item["factors"])


def test_cli_explain_top_matches_the_ranking(capsys, ordered):
    assert cli_main(_explain_argv("--top", "3", "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [p["cve"] for p in payload] == [e.cve for e in ordered[:3]]
    assert [p["rank"] for p in payload] == [1, 2, 3]


def test_cli_explain_exits_2_when_nothing_matches(capsys):
    assert cli_main(_explain_argv("--cve", "CVE-9999-9999")) == 2
    assert "nothing matched" in capsys.readouterr().err


# --- Factor 本身 ------------------------------------------------------------

def test_share_of_zero_score_is_zero_not_a_crash():
    factor = Factor(key="severity", value=0.0, weight=0.5)
    assert factor.share_of(0.0) == 0.0
