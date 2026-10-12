"""Day 27：措施重算與 ROI。

鎖住四件事：

1. **降幅是重算出來的。** 每一項措施套到圖的複本上，整條管線重跑。
2. **在這個圖模型裡 patch 切不掉路徑。** 圖不看漏洞，只看服務在不在聽。
3. **沒驗證、沒重掃、沒成本的，不給 ROI。** 不知道不能換來第一名。
4. **切斷數不可相加**（Day 24）。組合要重算。
"""

from __future__ import annotations

import pytest

from cve2action.cli import _add_treat_arguments, _plans, _scorer, _treatments
from cve2action.remediation.candidates import Candidate
from cve2action.remediation.roi import (
    NO_GRAPH_EFFECT,
    PENDING_RESCAN,
    PENDING_VERIFICATION,
    PROVEN,
    Outcome,
    evaluate,
    jewel_paths,
    service_nodes,
    what_if,
    without_asset,
)
from test_candidates import _cli_args, read


@pytest.fixture(scope="module")
def setup():
    import argparse

    parser = argparse.ArgumentParser()
    _add_treat_arguments(parser)
    args = parser.parse_args(_cli_args("treat")[1:])
    treatments, _ = _treatments(args)
    plans = _plans(args, treatments)
    graph, score = _scorer(args)
    services = {(r["asset"], r["cve"].upper()): r["service"] for r in read("scanner.csv")}
    return graph, score, plans, services


@pytest.fixture(scope="module")
def report(setup):
    graph, score, plans, services = setup
    return evaluate(graph, plans, score, services)


def outcome(report, rem_id: str) -> Outcome:
    return next(o for o in report.outcomes if o.candidate.remediation_id == rem_id)


def test_baseline_matches_day_22(report):
    assert report.paths_total == 30


def test_patch_cuts_no_path_but_closes_the_finding(report):
    """圖模型只看服務在不在聽，不看有沒有漏洞——修掉漏洞，圖一條邊都不少。"""
    for item in report.outcomes:
        if item.candidate.action == "patch":
            assert item.paths_cut == 0, item
            assert item.status == PROVEN
            assert item.findings_moved == 1


def test_only_one_registered_measure_cuts_any_path(report):
    cutters = [o for o in report.outcomes if o.paths_cut > 0]
    assert [o.candidate.remediation_id for o in cutters] == ["REM-004"]
    assert cutters[0].paths_cut == 2


def test_isolating_an_unreachable_host_buys_nothing(report):
    """實驗室 Confluence 本來就走不到（§8.4 情境一）：隔離它，佇列一分都不降。"""
    item = outcome(report, "REM-014")
    assert item.paths_cut == 0
    assert item.score_drop == 0.0


def test_unverified_and_unrescanned_measures_have_no_roi(report):
    assert outcome(report, "REM-006").status == PENDING_VERIFICATION
    assert outcome(report, "REM-008").status == PENDING_RESCAN
    for rem in ("REM-006", "REM-008", "REM-009", "REM-015"):
        item = outcome(report, rem)
        assert item.score_drop == 0.0
        assert item.per_hour is None


def test_unknown_effort_has_no_roi():
    cand = Candidate("X", "A", "CVE-1", "patch", None, 0, "", "CLOSES")
    assert Outcome(cand, PROVEN, 30, 30, 9.0).per_hour is None


def test_disable_service_does_not_guess_the_service(setup):
    """弱掃寫 log4j2，圖上是 tomcat——對不到就不切，不拿名稱硬接（Day 21）。"""
    graph, _score, _plans, _services = setup
    assert service_nodes(graph, "NS-APP-ORDER-01", "log4j2") == []
    assert service_nodes(graph, "NS-EDGE-RTR-01", "ios-xe-webui") == ["NS-EDGE-RTR-01:443"]


def test_unmatched_service_is_reported_not_skipped(setup):
    graph, score, plans, services = setup
    fake = dict(services)
    fake[("NS-EDGE-RTR-01", "CVE-2023-20198")] = "no-such-service"
    result = evaluate(graph, plans, score, fake)
    assert outcome(result, "REM-002").status == NO_GRAPH_EFFECT


def test_cuts_do_not_add_up(setup):
    """跳板與 VPN 各切 15 條，一起隔離還是 15——它們在同一條串聯上（Day 24）。"""
    graph = setup[0]
    jump = jewel_paths(without_asset(graph, "NS-JUMP-01"))
    vpn = jewel_paths(without_asset(graph, "NS-VPN-GW-01"))
    both = jewel_paths(without_asset(without_asset(graph, "NS-JUMP-01"), "NS-VPN-GW-01"))
    assert (30 - jump, 30 - vpn) == (15, 15)
    assert 30 - both == 15


def test_paths_and_score_disagree(setup, report):
    """切最多路徑的那台，幾乎不降佇列；降最多的 patch，一條路都不切。兩個量不能合併。"""
    graph, score, _plans, _services = setup
    [jump] = what_if(graph, score, ["NS-JUMP-01"])
    assert jump.paths_after == 15
    best_patch = max(o.score_drop for o in report.outcomes if o.candidate.action == "patch")
    assert jump.score_drop < best_patch / 2


def test_cli_roi_reports_the_article_numbers(capsys):
    from cve2action.cli import main as cli_main

    assert cli_main(_cli_args("roi")) == 0
    out = capsys.readouterr().out
    assert "通往 Crown Jewel 的路徑 30 條；佇列總分 304.13" in out
    assert "切得掉路徑的措施：1 項（patch 7 項，一條都切不掉）" in out
    assert "一起做：路徑 30 → 30，佇列降 35.56" in out
    assert "NS-JUMP-01           路徑 30 → 15，佇列降 2.86" in out
    assert "NS-APP-ORDER-01      路徑 30 → 14，佇列降 7.16" in out
