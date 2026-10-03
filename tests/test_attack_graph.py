"""Day 19：攻擊圖的節點與邊，以及多介面資產歸併。

兩個驗收：藍圖 §10 的「節點與邊定義完成」、成功標準 #2 #10 的
「多介面併成穩定資產，重複觀測只形成一項修補工作」。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from cve2action.attack_graph import (
    ACCOUNT,
    AMBIGUOUS,
    ASSET,
    EDGE_KINDS,
    GRANTS,
    HOSTS,
    INTERNET,
    INTERNET_ID,
    NODE_KINDS,
    REACHES,
    RESOLVED,
    SERVICE,
    UNKNOWN,
    USES,
    AttackGraph,
    Edge,
    Node,
    build_graph,
    build_inventory,
    resolve,
)
from cve2action.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def inventory():
    return build_inventory(read("asset_interfaces.csv"))


@pytest.fixture(scope="module")
def graph():
    return build_graph(read("assets.csv"), read("asset_interfaces.csv"),
                       read("services.csv"), read("network_edges.csv"),
                       read("identity_edges.csv"))


# --- 歸併：§9.0 閘門 1、成功標準 #2 #10 -------------------------------------

def test_thirty_interfaces_become_twenty_asset_nodes(graph):
    assert len(graph.of_kind(ASSET)) == 20
    assert sum(n.attrs["interfaces"] for n in graph.of_kind(ASSET)) == 30


def test_a_vip_resolves_to_ambiguous_not_to_one_of_them(inventory):
    """VIP 被兩台宣稱。挑一台當答案等於憑空決定，所以回 AMBIGUOUS。"""
    result = resolve("203.0.113.10", inventory)
    assert result.status == AMBIGUOUS
    assert result.candidates == ("NS-WEB-PORTAL-01", "NS-WEB-PORTAL-02")
    assert result.matched_on == "ip"
    assert result.asset is None


def test_two_hostnames_on_one_nic_resolve_to_the_same_asset(inventory):
    """lab-wiki 與 wiki-old 是同一台；照 hostname 當主鍵會把它拆成兩台。"""
    first = resolve("lab-wiki.northstar.example", inventory)
    second = resolve("wiki-old.northstar.example", inventory)
    assert first.status == second.status == RESOLVED
    assert first.asset == second.asset == "NS-LAB-CONFLUENCE-01"


def test_a_host_outside_the_inventory_is_unknown_not_ambiguous(inventory):
    result = resolve("10.99.0.5", inventory)
    assert result.status == UNKNOWN
    assert result.candidates == ()


def test_mac_wins_over_ip_when_both_match(inventory):
    """管理介面的 MAC 只屬於一台；解析順序要讓它先決定答案。"""
    assert resolve("02:1a:00:04:10:02", inventory).matched_on == "mac"
    assert resolve("02:1a:00:04:10:02", inventory).asset == "NS-AD-DC-01"


def test_resolution_never_falls_through_to_a_weaker_identifier(inventory):
    """對到多台就回 AMBIGUOUS，不得改用下一種識別子「試到單一答案為止」。

    那樣做會讓 VIP 悄悄被歸給其中一台，而且沒有任何痕跡。
    """
    result = resolve("203.0.113.10", inventory)
    assert result.status == AMBIGUOUS, "IP 對到兩台時不該再去試別的識別子"


def test_empty_observation_is_unknown(inventory):
    assert resolve("   ", inventory).status == UNKNOWN


# --- 圖的形狀：藍圖 §10「節點與邊定義完成」、§15「節點類型不超過六種」-------

def test_node_and_edge_kinds_stay_small():
    assert len(NODE_KINDS) == 4 and len(EDGE_KINDS) == 4


def test_crown_jewel_is_a_flag_not_a_node_kind(graph):
    """做成節點就要多一種邊，而那條邊不帶新資訊——jewel 就是那台資產。"""
    assert "crown_jewel" not in NODE_KINDS
    assert len(graph.crown_jewels) == 4
    assert all(n.kind == ASSET for n in graph.crown_jewels)


def test_internet_is_a_source_only(graph):
    assert graph.nodes[INTERNET_ID].kind == INTERNET
    assert not any(e.target == INTERNET_ID for e in graph.edges)
    assert graph.out_edges(INTERNET_ID, REACHES)


def test_the_graph_has_the_shape_the_article_quotes(graph):
    counts = graph.counts()
    assert counts == {
        "node:internet": 1, "node:asset": 20, "node:service": 28, "node:account": 9,
        "edge:hosts": 28, "edge:reaches": 24, "edge:uses": 10, "edge:grants": 10,
        "excluded": 1,
    }


def test_every_service_node_hangs_off_its_asset(graph):
    for service in graph.of_kind(SERVICE):
        owner = service.attrs["asset"]
        assert any(e.source == owner and e.target == service.id and e.kind == HOSTS
                   for e in graph.edges)


def test_identity_edges_go_through_an_account_node(graph):
    """帳號是節點，不是邊上的標籤——Day 24 要找共用帳號這種瓶頸。"""
    assert len(graph.of_kind(ACCOUNT)) == 9
    for edge in graph.edges:
        if edge.kind == USES:
            assert graph.nodes[edge.target].kind == ACCOUNT
        if edge.kind == GRANTS:
            assert graph.nodes[edge.source].kind == ACCOUNT


# --- 排除的邊：理由必須留著 -------------------------------------------------

def test_a_denied_connection_is_excluded_with_its_reason(graph):
    assert len(graph.excluded) == 1
    item = graph.excluded[0]
    assert item.source == "NS-LAB-CONFLUENCE-01"
    assert item.kind == REACHES and "政策拒絕" in item.reason


def test_reaches_edges_only_land_on_listening_services(graph):
    for edge in graph.edges:
        if edge.kind == REACHES:
            assert graph.nodes[edge.target].attrs["state"] == "listening"


def test_a_filtered_service_keeps_its_node_but_gets_no_reaches_edge(graph):
    """服務還在（要修補），只是打不到（不構成路徑）。兩件事不能混。"""
    filtered = [n for n in graph.of_kind(SERVICE) if n.attrs["state"] != "listening"]
    assert filtered, "資料集要留 filtered／closed 樣本"
    for node in filtered:
        assert not any(e.target == node.id and e.kind == REACHES for e in graph.edges)
        assert any(e.target == node.id and e.kind == HOSTS for e in graph.edges)


def test_an_edge_to_an_unlisted_asset_is_excluded_not_crashed():
    graph = build_graph(
        [{"asset_id": "A", "hostname": "a", "zone": "APP", "crown_jewel": "no"}],
        [{"asset_id": "A", "ip": "10.0.0.1", "hostname": "a", "mac": "aa",
          "interface_type": "service"}],
        [{"asset_id": "A", "port": "80", "protocol": "tcp", "service": "http",
          "version": "1", "state": "listening"}],
        [{"source": "INTERNET", "target": "GHOST", "port": "80", "protocol": "tcp",
          "allowed": "yes"}],
        [],
    )
    assert [x.reason for x in graph.excluded] == ["目的端不在清冊上"]


# --- 模型本身 ---------------------------------------------------------------

def test_unknown_kinds_are_rejected():
    graph = AttackGraph()
    with pytest.raises(ValueError, match="node kind"):
        graph.add_node(Node("x", "planet"))
    graph.add_node(Node("a", ASSET))
    graph.add_node(Node("b", ASSET))
    with pytest.raises(ValueError, match="edge kind"):
        graph.add_edge(Edge("a", "b", "teleports"))


def test_an_edge_to_a_missing_node_is_rejected():
    graph = AttackGraph()
    graph.add_node(Node("a", ASSET))
    with pytest.raises(ValueError, match="not a node"):
        graph.add_edge(Edge("a", "nowhere", HOSTS))


def test_json_round_trips_the_counts(graph):
    payload = json.loads(graph.to_json())
    assert payload["counts"] == graph.counts()
    assert len(payload["nodes"]) == len(graph.nodes)
    assert len(payload["edges"]) == len(graph.edges)


# --- CLI --------------------------------------------------------------------

def _argv(*extra: str) -> list[str]:
    return [
        "graph",
        "--assets", str(DATA / "assets.csv"),
        "--interfaces", str(DATA / "asset_interfaces.csv"),
        "--services", str(DATA / "services.csv"),
        "--network", str(DATA / "network_edges.csv"),
        "--identity", str(DATA / "identity_edges.csv"), *extra,
    ]


def test_cli_graph_reports_the_merge_and_the_counts(capsys):
    assert cli_main(_argv()) == 0
    out = capsys.readouterr().out
    assert "30 個介面 -> 20 台資產" in out
    assert "Crown Jewel 4 台" in out
    assert "政策拒絕" in out


def test_cli_graph_writes_json(tmp_path, graph):
    out = tmp_path / "graph.json"
    assert cli_main(_argv("--out", str(out))) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["counts"] == graph.counts()


def test_cli_graph_resolves_a_single_observation(capsys):
    assert cli_main(_argv("--resolve", "203.0.113.10")) == 0
    assert "AMBIGUOUS" in capsys.readouterr().out
