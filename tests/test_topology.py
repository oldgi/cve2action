"""Day 18 盤點補上的三組關係：網路連線、帳號權限、候選措施。

這些資料本身不進 v0.1 的評分；它們是 Day 19–27 的輸入。現在就把完整性鎖住，
免得到 Day 22 才發現有條邊指向不存在的資產。
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"
INTERNET = "INTERNET"


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def assets() -> set[str]:
    return {a["asset_id"] for a in read("assets.csv")}


@pytest.fixture(scope="module")
def crown_jewels() -> set[str]:
    return {a["asset_id"] for a in read("assets.csv") if a["crown_jewel"] == "yes"}


def _allowed_graph() -> dict[str, list[str]]:
    graph: dict[str, list[str]] = defaultdict(list)
    for edge in read("network_edges.csv"):
        if edge["allowed"] == "yes":
            graph[edge["source"]].append(edge["target"])
    return graph


def _paths(graph, source: str, goal: str, seen: tuple = ()) -> list[tuple]:
    if source in seen:
        return []
    if source == goal and seen:
        return [seen + (source,)]
    found = []
    for target in graph.get(source, []):
        found.extend(_paths(graph, target, goal, seen + (source,)))
    return found


# --- 完整性 -----------------------------------------------------------------

def test_every_network_endpoint_is_a_real_asset(assets):
    for edge in read("network_edges.csv"):
        assert edge["source"] in assets or edge["source"] == INTERNET, edge
        assert edge["target"] in assets, edge
        assert edge["target"] != INTERNET, "INTERNET 只能是來源，不是目標"


def test_every_identity_endpoint_is_a_real_asset(assets):
    for edge in read("identity_edges.csv"):
        assert edge["source"] in assets and edge["target"] in assets, edge


def test_every_remediation_points_at_a_real_finding():
    findings = {(f["asset"], f["cve"]) for f in read("scanner.csv")}
    for item in read("remediations.csv"):
        assert (item["asset"], item["cve"]) in findings, item


def test_remediation_ids_are_unique():
    ids = [r["remediation_id"] for r in read("remediations.csv")]
    assert len(set(ids)) == len(ids)


def test_no_self_loops():
    for edge in read("network_edges.csv"):
        assert edge["source"] != edge["target"], edge


# --- 必測情境的前提（藍圖 §8.4、成功標準 #7） -------------------------------

def test_every_crown_jewel_is_reachable_from_the_internet(crown_jewels):
    graph = _allowed_graph()
    for jewel in sorted(crown_jewels):
        assert _paths(graph, INTERNET, jewel), f"{jewel} 沒有任何 Internet 可達路徑"


def test_the_shortest_path_to_the_customer_database_is_three_hops():
    """情境 2 與成功標準 #7 引用這條路徑。"""
    graph = _allowed_graph()
    paths = _paths(graph, INTERNET, "NS-DB-CUSTOMER-01")
    shortest = min(paths, key=len)
    assert shortest == ("INTERNET", "NS-WEB-PORTAL-01", "NS-APP-ORDER-01",
                        "NS-DB-CUSTOMER-01")
    assert len(shortest) - 1 == 3


def test_a_choke_point_exists_for_scenario_four(crown_jewels):
    """情境 4：一次措施要能切斷多條路徑，前提是存在共用節點。"""
    graph = _allowed_graph()
    paths = [p for jewel in crown_jewels for p in _paths(graph, INTERNET, jewel)]
    assert len(paths) == 14
    middles = Counter(node for path in paths for node in path[1:-1])
    node, count = middles.most_common(1)[0]
    assert (node, count) == ("NS-APP-ORDER-01", 8)


def test_denied_edges_do_not_create_paths():
    """被政策拒絕的連線不得構成路徑——未允許不等於可達。"""
    denied = [e for e in read("network_edges.csv") if e["allowed"] == "no"]
    assert denied, "資料集要留至少一條被拒絕的連線，否則這條規則沒有被測到"
    graph = _allowed_graph()
    for edge in denied:
        assert edge["target"] not in graph.get(edge["source"], [])


def test_the_isolated_ot_asset_has_no_recorded_edge():
    """沒有邊代表『這份清冊沒記錄到路徑』，不是『證明不可達』。

    Day 17 把這台排在最後，理由正是『沒有已知的可達路徑』——那個判斷
    建立在這個事實上，所以把它釘住。
    """
    edges = read("network_edges.csv")
    touching = [e for e in edges
                if "NS-PLC-DC-ENV" in (e["source"], e["target"])]
    assert touching == []


# --- 身分關係 ---------------------------------------------------------------

def test_the_break_glass_account_matches_the_control_evidence():
    """controls.csv 說 NS-JUMP-01 的 MFA 在 break-glass 帳號上有缺口；
    identity_edges 必須真的有那條邊，兩份資料不能各說各話。"""
    control = next(c for c in read("controls.csv") if c["asset_id"] == "NS-JUMP-01")
    assert "break-glass" in control["evidence"]
    edges = read("identity_edges.csv")
    assert any(e["account"] == "break_glass" and e["source"] == "NS-JUMP-01"
               and e["privilege"] == "domain_admin" for e in edges)


def test_domain_admin_edges_all_originate_from_the_jump_host():
    """tier-0 權限只從跳板出發；這是 Day 21 橫向移動分析的前提。"""
    for edge in read("identity_edges.csv"):
        if edge["privilege"] == "domain_admin":
            assert edge["source"] == "NS-JUMP-01", edge


# --- 候選措施 ---------------------------------------------------------------

def test_remediations_offer_more_than_patching():
    """Day 25 的論點是『修補不是唯一選項』；候選措施表要撐得起那個比較。

    這不是在主張「多數漏洞不該修補」——是在要求這份清單裡有足夠的替代方案，
    否則 Day 26 的「哪一個先做」會退化成「全部都修」。
    """
    actions = Counter(r["action"] for r in read("remediations.csv"))
    assert actions["patch"] < len(read("remediations.csv")) / 2
    assert set(actions) >= {"patch", "isolate", "disable_service", "config_change",
                            "compensating_control"}


def test_some_findings_have_competing_remediations():
    """同一筆 finding 有多個候選措施，Day 26 才有東西可以比較。"""
    pairs = Counter((r["asset"], r["cve"]) for r in read("remediations.csv"))
    assert sum(1 for count in pairs.values() if count > 1) >= 3
