"""Day 20：可達性——一條連線憑什麼算數（藍圖 §9.0 閘門 3、§10「Port 與方向納入判斷」）。

兩條規則在這裡被鎖住：
1. **port 要逐一比對**，zone 對上不代表 port 也對上。
2. **觀測贏過政策，但差異不得被刪掉**——沒有依據的連線留在圖上，帶著標記。
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from cve2action.attack_graph import (
    BY_POLICY,
    DRIFT,
    INTRA_ZONE,
    REACHES,
    UNGOVERNED,
    annotate,
    build_graph,
    classify,
    egress_governance,
    find_paths,
)
from cve2action.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "synthetic" / "northstar"


def read(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


@pytest.fixture(scope="module")
def policies():
    return read("network_policies.csv")


@pytest.fixture(scope="module")
def annotated():
    graph = build_graph(read("assets.csv"), read("asset_interfaces.csv"),
                        read("services.csv"), read("network_edges.csv"),
                        read("identity_edges.csv"))
    zones = {a["asset_id"]: a["zone"] for a in read("assets.csv")}
    counts = annotate(graph, read("network_edges.csv"), read("network_policies.csv"), zones)
    return graph, counts


# --- port 要逐一比對 --------------------------------------------------------

def test_a_policy_for_one_port_does_not_authorise_another(policies):
    """DMZ→MGMT 只允許 3389。389 是另一個服務，差一個字元而已。"""
    assert classify("DMZ", "MGMT", 3389, policies).status == BY_POLICY
    assert classify("DMZ", "MGMT", 389, policies).status == UNGOVERNED


def test_port_zero_means_every_port(policies):
    """MGMT→APP 的政策寫 0，代表整段範圍，不是 port 零。"""
    for port in (22, 8080, 65535):
        assert classify("MGMT", "APP", port, policies).status == BY_POLICY


def test_same_zone_is_not_governed_by_these_policies(policies):
    basis = classify("DATA", "DATA", 873, policies)
    assert basis.status == INTRA_ZONE and basis.governed


# --- 觀測贏過政策，但要標記 -------------------------------------------------

def test_a_connection_that_contradicts_a_deny_is_drift_not_removed():
    """政策寫錯不會讓封包不通。標記為 DRIFT，不是把觀測刪掉。"""
    policies = [{"policy_id": "POL-X", "source_scope": "CORP", "destination": "DATA",
                 "port": "0", "action": "deny", "verified_at": "2026-09-12"}]
    basis = classify("CORP", "DATA", 5432, policies)
    assert basis.status == DRIFT
    assert basis.policy == "POL-X"
    assert not basis.governed


def test_allow_wins_over_deny_when_both_match():
    """同一方向同時有 allow 與 deny 時，實際連得通代表 allow 生效。"""
    policies = [
        {"policy_id": "D", "source_scope": "A", "destination": "B", "port": "0",
         "action": "deny", "verified_at": "2026-01-01"},
        {"policy_id": "A1", "source_scope": "A", "destination": "B", "port": "443",
         "action": "allow", "verified_at": "2026-01-01"},
    ]
    assert classify("A", "B", 443, policies).policy == "A1"


def test_no_policy_at_all_is_ungoverned_not_denied(policies):
    basis = classify("OT", "DATA", 5432, policies)
    assert basis.status == UNGOVERNED
    assert not basis.governed, "找不到政策不代表被擋住，但也不算有依據"


# --- 回程通道：沒有 egress 政策 ≠ egress 被擋住 -----------------------------

def test_missing_egress_policy_is_ungoverned(policies):
    """Log4Shell 這類利用要靠受害端往外連。擋不擋得住要看政策——
    而這份政策一條出向規則都沒有，所以不得宣稱它被擋住。"""
    for zone in ("APP", "DATA", "DMZ"):
        basis = egress_governance(zone, policies)
        assert basis.status == UNGOVERNED
        assert "不得視為已阻擋" in basis.detail


def test_an_explicit_outbound_deny_is_recognised():
    policies = [{"policy_id": "E1", "source_scope": "DATA", "destination": "INTERNET",
                 "port": "0", "action": "deny", "verified_at": "2026-09-12"}]
    basis = egress_governance("DATA", policies)
    assert basis.governed and "全面阻擋" in basis.detail


# --- 套到 Northstar 上 ------------------------------------------------------

def test_the_numbers_the_article_quotes(annotated):
    _graph, counts = annotated
    assert counts == {BY_POLICY: 21, INTRA_ZONE: 2, UNGOVERNED: 1}
    assert sum(counts.values()) == 24, "24 條 reaches 邊都要有判定"


def test_the_one_ungoverned_link_is_mail_gateway_to_the_domain_controller(annotated):
    graph, _counts = annotated
    loose = [e for e in graph.edges if e.attrs.get("basis") == UNGOVERNED]
    assert len(loose) == 1
    assert (loose[0].source, loose[0].target) == ("NS-MAIL-GW-01", "NS-AD-DC-01:389")


def test_the_shortest_path_to_the_domain_controller_rides_that_link(annotated):
    """最短的那條路只有兩跳，而它整條就靠一條沒有依據的連線。"""
    graph, _counts = annotated
    paths = find_paths(graph, "NS-AD-DC-01")
    shortest = paths[0]
    assert shortest.length == 2
    assert shortest.assets == ("internet", "NS-MAIL-GW-01", "NS-AD-DC-01")
    assert ("NS-MAIL-GW-01", "NS-AD-DC-01") in shortest.edge_keys


def test_northstar_has_no_drift_and_that_is_stated_not_assumed(annotated):
    """這份資料沒有設定漂移的例子，所以 DRIFT 由單元測試覆蓋，不是由資料集。"""
    _graph, counts = annotated
    assert DRIFT not in counts


def test_annotating_never_removes_an_edge(annotated):
    graph, counts = annotated
    assert sum(1 for e in graph.edges if e.kind == REACHES) == sum(counts.values())


# --- CLI --------------------------------------------------------------------

def test_cli_graph_reports_the_basis_breakdown(capsys):
    code = cli_main([
        "graph",
        "--assets", str(DATA / "assets.csv"),
        "--interfaces", str(DATA / "asset_interfaces.csv"),
        "--services", str(DATA / "services.csv"),
        "--network", str(DATA / "network_edges.csv"),
        "--identity", str(DATA / "identity_edges.csv"),
        "--policies", str(DATA / "network_policies.csv"),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "BY_POLICY 21" in out and "UNGOVERNED 1" in out
    assert "NS-MAIL-GW-01" in out
    assert "回程通道不得視為已阻擋" in out
