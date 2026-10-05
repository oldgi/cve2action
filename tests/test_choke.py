"""Day 24：共同瓶頸——出現頻率不是切斷力。

Day 22 的 `shared_hops` docstring 寫著「Day 24 的 choke point 就是這個數字」。
今天把它推翻，而且推翻的方式是量：在 Northstar 上，兩種排法的第一名**不是同一台**。

| 排法 | 第一名 | 數字 |
|---|---|---|
| 出現頻率 | `NS-APP-ORDER-01` | 16/30 |
| 反事實切斷 | `NS-DB-CUSTOMER-01` | 切 22/30（只出現在 11 條上） |

而切得最多的那台是 Crown Jewel——「移除它」不是一個做得到的處置。所以反事實
必須知道哪些節點可以動，否則它會給出一個沒人能執行的答案。

§16 的 Day 24 門檻兩條都在這裡驗：
  1. 能呈現入口、弱點、權限與 Crown Jewel 的有效路徑。
  2. 無法到達的資產不會被誤標為可達——反過來那半句一樣要守：
     **切斷了幾條路徑不等於它從此安全。**
"""

from __future__ import annotations

import csv
import itertools
from pathlib import Path as FsPath

import pytest

from cve2action.attack_graph.build import build_graph
from cve2action.attack_graph.choke import MAX_EXHAUSTIVE, analyse, combined_cut
from cve2action.attack_graph.choke import render as render_choke
from cve2action.attack_graph.identity import annotate as identity_annotate
from cve2action.attack_graph.identity import privilege_obtainable
from cve2action.attack_graph.paths import PathContext, find_paths, render_path
from cve2action.attack_graph.reachability import annotate
from cve2action.cli import main as cli_main
from cve2action.collectors.nvd import load_snapshots

ROOT = FsPath(__file__).resolve().parents[1]
NORTHSTAR = ROOT / "data/synthetic/northstar"


def _rows(name: str) -> list[dict]:
    with (NORTHSTAR / name).open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _vectors() -> dict[str, str]:
    vectors = {}
    for cve, record in load_snapshots(ROOT / "data/snapshots/nvd").items():
        chosen = record.cvss.preferred(("3.1", "4.0"))
        if chosen is not None:
            vectors[cve.upper()] = chosen.vector
    return vectors


@pytest.fixture(scope="module")
def graph():
    assets, services = _rows("assets.csv"), _rows("services.csv")
    built = build_graph(assets, _rows("asset_interfaces.csv"), services,
                        _rows("network_edges.csv"), _rows("identity_edges.csv"))
    annotate(built, _rows("network_edges.csv"), _rows("network_policies.csv"),
             {a["asset_id"]: a["zone"] for a in assets})
    identity_annotate(built, _rows("identity_edges.csv"), services,
                      _rows("scanner.csv"), _vectors())
    return built


@pytest.fixture(scope="module")
def report(graph):
    return analyse(graph)


# --- 今天的主張：頻率不是切斷力 ------------------------------------------------

def test_the_two_rankings_disagree(report):
    """如果兩種排法永遠一致，今天就沒有題目。"""
    assert not report.rankings_agree
    assert report.by_frequency[0].asset == "NS-APP-ORDER-01"
    assert report.by_cuts[0].asset == "NS-DB-CUSTOMER-01"


def test_the_numbers_the_article_quotes(report):
    assert report.total_paths == 30
    by_asset = {c.asset: c for c in report.chokes}
    assert by_asset["NS-APP-ORDER-01"].on_paths == 16
    assert by_asset["NS-APP-ORDER-01"].cuts == 16
    assert by_asset["NS-DB-CUSTOMER-01"].on_paths == 11
    assert by_asset["NS-DB-CUSTOMER-01"].cuts == 22
    assert by_asset["NS-VPN-GW-01"].cuts == 15
    assert by_asset["NS-JUMP-01"].cuts == 15


def test_a_node_can_cut_more_paths_than_it_appears_on(report):
    """資料庫只在 11 條路上卻切得掉 22 條——因為它是通往備份主機的唯一一跳。

    這就是頻率答不出來的那一半：被切掉的路徑有些根本不經過它，
    而是經過**只能從它過去**的下游。
    """
    database = next(c for c in report.chokes if c.asset == "NS-DB-CUSTOMER-01")
    assert database.cuts > database.on_paths
    assert set(database.jewels_cut) == {"NS-DB-CUSTOMER-01", "NS-BACKUP-01"}


def test_cuts_are_not_additive(graph):
    """VPN 切 15、Jump 切 15，一起修還是 15——它們在同一條串聯上。

    把切斷數加起來會得到 30，也就是「全部擋掉」，而真實答案是一半。
    所以組合效果只能重算，不能加。
    """
    vpn = combined_cut(graph, ["NS-VPN-GW-01"])
    jump = combined_cut(graph, ["NS-JUMP-01"])
    both = combined_cut(graph, ["NS-VPN-GW-01", "NS-JUMP-01"])
    assert vpn == jump == 15
    assert both == 15
    assert both < vpn + jump


def test_an_unrelated_pair_really_does_add_up(graph):
    """反例也要有：不在同一條串聯上的兩台，組合起來確實比單獨多。"""
    order = combined_cut(graph, ["NS-APP-ORDER-01"])
    together = combined_cut(graph, ["NS-APP-ORDER-01", "NS-VPN-GW-01"])
    assert together > order


# --- 可處置性：反事實要算得出能執行的答案 --------------------------------------

def test_crown_jewels_are_marked_unactionable(report):
    for choke in report.chokes:
        if choke.asset in report.jewels:
            assert not choke.actionable
            assert "不可處置" in choke.note


def test_minimum_cuts_only_use_actionable_nodes(report):
    for cut in report.cuts:
        assert cut.found, cut.note
        assert not set(cut.assets) & set(report.jewels)


def test_no_single_actionable_node_cuts_any_crown_jewel(report):
    """單點瓶頸在這份清冊上不存在。每個目標都要至少兩台。"""
    assert all(len(cut.assets) >= 2 for cut in report.cuts)
    for choke in report.chokes:
        if choke.actionable:
            assert not choke.jewels_cut


def test_the_universal_choke_point_is_in_every_cut(report):
    """`NS-JUMP-01` 不是出現最多次的，但它是每個切割集合都少不了的那一台。"""
    assert report.universal == ("NS-JUMP-01",)
    for cut in report.cuts:
        assert "NS-JUMP-01" in cut.assets


def test_the_minimum_cuts_really_do_cut(graph, report):
    """算出來的集合要真的讓目標不可達，否則這份報告是編的。"""
    for cut in report.cuts:
        assert not find_paths(graph, cut.jewel, without=frozenset(cut.assets))


def test_no_smaller_set_would_have_worked(graph, report):
    """「最小」要名副其實：任何更小的子集都切不斷。"""
    for cut in report.cuts:
        for size in range(1, len(cut.assets)):
            for smaller in itertools.combinations(cut.assets, size):
                assert find_paths(graph, cut.jewel, without=frozenset(smaller)), (
                    f"{cut.jewel}：{smaller} 就夠了，{cut.assets} 不是最小"
                )


def test_cutting_everything_needs_four_machines(graph, report):
    assert report.full_cut == ("NS-API-GW-01", "NS-APP-ORDER-01",
                               "NS-JUMP-01", "NS-MAIL-GW-01")
    for jewel in report.jewels:
        assert not find_paths(graph, jewel, without=frozenset(report.full_cut))


# --- find_paths(without=) 的性質 ----------------------------------------------

def test_engine_exclusion_matches_filtering_the_enumerated_paths(graph):
    """`choke.py` 為了跑 255 個子集而改用篩選；兩者必須等價。"""
    for jewel in (n.id for n in graph.crown_jewels):
        everything = find_paths(graph, jewel)
        for removed in ("NS-JUMP-01", "NS-APP-ORDER-01", "NS-VPN-GW-01"):
            engine = find_paths(graph, jewel, without=frozenset({removed}))
            filtered = [p for p in everything if removed not in p.assets[:-1]]
            assert [p.assets for p in engine] == [p.assets for p in filtered]


def test_excluding_the_target_itself_returns_nothing(graph):
    assert find_paths(graph, "NS-DB-CUSTOMER-01",
                      without=frozenset({"NS-DB-CUSTOMER-01"})) == []


def test_removing_a_node_never_creates_a_path(graph):
    """移除節點只能讓路徑變少。多出來就代表搜尋有狀態殘留。"""
    for jewel in (n.id for n in graph.crown_jewels):
        baseline = len(find_paths(graph, jewel))
        for removed in ("NS-JUMP-01", "NS-MAIL-GW-01", "NS-WEB-PORTAL-01"):
            assert len(find_paths(graph, jewel,
                                  without=frozenset({removed}))) <= baseline


def test_analysis_is_deterministic(graph):
    """同樣的資料要得到同一份報告，文章與截圖才對得上。"""
    first, second = analyse(graph), analyse(graph)
    assert [(c.asset, c.cuts) for c in first.by_cuts] == [
        (c.asset, c.cuts) for c in second.by_cuts]
    assert [c.assets for c in first.cuts] == [c.assets for c in second.cuts]


# --- §16 Day 24 門檻 ---------------------------------------------------------

def test_a_rendered_path_shows_entry_vulnerability_privilege_and_jewel(graph):
    """門檻原文：能呈現入口、弱點、權限與 Crown Jewel 的有效路徑。

    前三樣 Day 22 就有了，**權限一直只進了分數、沒進呈現**——Day 24 補上。
    """
    services, scan = _rows("services.csv"), _rows("scanner.csv")
    vectors = _vectors()
    findings: dict[str, list[str]] = {}
    for row in scan:
        findings.setdefault(row["asset"], []).append(row["cve"])
    privileges = {a["asset_id"]: privilege_obtainable(a["asset_id"], services, scan, vectors)
                  for a in _rows("assets.csv")}
    context = PathContext(findings=findings,
                          crown_jewels=frozenset(n.id for n in graph.crown_jewels),
                          privileges=privileges)
    text = render_path(find_paths(graph, "NS-DB-CUSTOMER-01")[0], graph, context)

    assert "INTERNET" in text
    assert "漏洞：" in text
    assert "取得權限：" in text
    assert "👑 Crown Jewel" in text


def test_unprovable_privilege_says_so_instead_of_guessing(graph):
    privileges = {"NS-API-GW-01": privilege_obtainable("NS-API-GW-01", [], [], {})}
    context = PathContext(crown_jewels=frozenset(), privileges=privileges)
    text = render_path(find_paths(graph, "NS-DB-CUSTOMER-01")[0], graph, context)
    assert "證不出來——不代表拿不到" in text


def test_cutting_paths_is_not_called_safe(report):
    """反過來那半句：切斷了幾條不等於它從此安全。

    報告裡只出現「切斷」「不可達」，不出現任何宣告安全的字眼。
    """
    text = render_choke(report)
    assert "安全" not in text
    assert "不可達" in text and "切斷" in text


def test_the_report_names_both_rankings_and_says_they_differ(report):
    text = render_choke(report)
    assert "頻率不是切斷力" in text
    assert "沒有任何單一可處置節點" in text
    assert "這才是共同瓶頸" in text


def test_the_report_flags_the_unactionable_top_cutter(report):
    assert "不可處置" in render_choke(report)


def test_exhaustive_search_has_a_declared_limit():
    """超過上限就說算不出來，不給一個只掃了一部分的答案。"""
    assert MAX_EXHAUSTIVE == 12


# --- CLI ---------------------------------------------------------------------

GRAPH_ARGS = [
    "--assets", str(NORTHSTAR / "assets.csv"),
    "--interfaces", str(NORTHSTAR / "asset_interfaces.csv"),
    "--services", str(NORTHSTAR / "services.csv"),
    "--network", str(NORTHSTAR / "network_edges.csv"),
    "--identity", str(NORTHSTAR / "identity_edges.csv"),
    "--policies", str(NORTHSTAR / "network_policies.csv"),
    "--findings", str(NORTHSTAR / "scanner.csv"),
    "--snapshots", str(ROOT / "data/snapshots/nvd"),
]


def test_cli_choke_prints_both_rankings(capsys):
    assert cli_main(["path", *GRAPH_ARGS, "--choke"]) == 0
    out = capsys.readouterr().out
    assert "30 條路徑" in out
    assert "頻率不是切斷力" in out
    assert "NS-JUMP-01" in out


def test_cli_without_reports_the_counterfactual(capsys):
    assert cli_main(["path", *GRAPH_ARGS, "--to", "NS-DB-CUSTOMER-01",
                     "--without", "NS-APP-ORDER-01"]) == 0
    out = capsys.readouterr().out
    assert "11 條剩 3 條（切斷 8 條）" in out


def test_cli_without_everything_does_not_claim_safety(capsys):
    assert cli_main(["path", *GRAPH_ARGS, "--to", "NS-DB-CUSTOMER-01",
                     "--without", "NS-APP-ORDER-01", "--without", "NS-JUMP-01"]) == 0
    out = capsys.readouterr().out
    assert "不是「它從此安全」" in out
