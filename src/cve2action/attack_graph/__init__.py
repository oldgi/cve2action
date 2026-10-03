"""攻擊圖：把基礎架構變成節點與邊（Day 19 起）。

`resolve` 把掃描觀測歸併成資產，`model` 定義節點與邊，`build` 從資料檔組出圖。
被排除的邊連同理由一起保留——「查無路徑」和「證明不可達」不是同一件事。
"""

from .build import build_graph
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
from .resolve import AMBIGUOUS, RESOLVED, UNKNOWN, Inventory, build_inventory, resolve

__all__ = [
    "build_graph", "AttackGraph", "Node", "Edge", "Excluded",
    "NODE_KINDS", "EDGE_KINDS", "INTERNET", "ASSET", "SERVICE", "ACCOUNT",
    "HOSTS", "REACHES", "USES", "GRANTS", "INTERNET_ID",
    "resolve", "build_inventory", "Inventory", "RESOLVED", "AMBIGUOUS", "UNKNOWN",
]
