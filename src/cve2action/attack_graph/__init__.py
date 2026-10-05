"""攻擊圖：把基礎架構變成節點與邊（Day 19 起）。

`resolve` 把掃描觀測歸併成資產，`model` 定義節點與邊，`build` 從資料檔組出圖。
被排除的邊連同理由一起保留——「查無路徑」和「證明不可達」不是同一件事。
"""

from .build import build_graph
from .choke import Choke, ChokeReport, Cut, analyse, combined_cut
from .choke import render as render_choke
from .diagnose import (
    BLOCKED_BY_POLICY,
    EXCLUDED,
    NO_INBOUND,
    REACHABLE,
    SOURCE_UNREACHABLE,
    Coverage,
    NoPath,
    coverage,
    diagnose,
    render_coverage,
)
from .identity import BLOCKED, SATISFIED, UNPROVEN, Obtainable, Precondition, privilege_obtainable
from .identity import annotate as identity_annotate
from .identity import check as identity_check
from .model import (
    ACCOUNT,
    ASSET,
    EDGE_KINDS,
    GRANTS,
    HOSTS,
    INTERNET,
    INTERNET_ID,
    NODE_KINDS,
    REACHES,
    SERVICE,
    USES,
    AttackGraph,
    Edge,
    Excluded,
    Node,
)
from .paths import Path, PathContext, find_paths, render_path, render_summary, shared_hops
from .reachability import (
    BY_POLICY,
    DRIFT,
    INTRA_ZONE,
    UNGOVERNED,
    Basis,
    annotate,
    classify,
    egress_governance,
)
from .resolve import AMBIGUOUS, RESOLVED, UNKNOWN, Inventory, build_inventory, resolve

__all__ = [
    "build_graph", "AttackGraph", "Node", "Edge", "Excluded",
    "NODE_KINDS", "EDGE_KINDS", "INTERNET", "ASSET", "SERVICE", "ACCOUNT",
    "HOSTS", "REACHES", "USES", "GRANTS", "INTERNET_ID",
    "resolve", "build_inventory", "Inventory", "RESOLVED", "AMBIGUOUS", "UNKNOWN",
    "find_paths", "render_path", "render_summary", "shared_hops", "Path", "PathContext",
    "classify", "annotate", "egress_governance", "Basis",
    "BY_POLICY", "INTRA_ZONE", "DRIFT", "UNGOVERNED",
    "identity_annotate", "identity_check", "privilege_obtainable",
    "Obtainable", "Precondition", "SATISFIED", "BLOCKED", "UNPROVEN",
    "diagnose", "coverage", "render_coverage", "NoPath", "Coverage",
    "NO_INBOUND", "SOURCE_UNREACHABLE", "BLOCKED_BY_POLICY", "EXCLUDED", "REACHABLE",
    "analyse", "render_choke", "combined_cut", "Choke", "ChokeReport", "Cut",
]
