"""從資料檔建出攻擊圖（Day 19）。

四份輸入，四種邊：

```text
assets.csv + asset_interfaces.csv  →  asset 節點（歸併後）
services.csv                       →  service 節點 + hosts 邊
network_edges.csv                  →  reaches 邊
identity_edges.csv                 →  account 節點 + uses/grants 邊
```

建圖時會丟掉三種東西，而且**每一種都留下理由**：

- 政策拒絕的連線（`allowed=no`）
- 指向沒有服務在聽的 port 的連線
- 指向 `filtered`／`closed` 服務的連線

它們記在 `graph.excluded` 裡。Day 22 要回答「為什麼這台沒有路徑」，
答案就在那份清單上；靜靜丟掉，就只剩「查無路徑」這種什麼都沒說的答案。
"""

from __future__ import annotations

from .model import (
    ACCOUNT,
    ASSET,
    GRANTS,
    HOSTS,
    INTERNET,
    INTERNET_ID,
    REACHES,
    SERVICE,
    USES,
    AttackGraph,
    Edge,
    Node,
    account_id,
    service_id,
)
from .resolve import build_inventory

LISTENING = "listening"


def build_graph(assets: list[dict], interfaces: list[dict], services: list[dict],
                network_edges: list[dict], identity_edges: list[dict]) -> AttackGraph:
    graph = AttackGraph()
    inventory = build_inventory(interfaces)

    graph.add_node(Node(INTERNET_ID, INTERNET, label="Internet",
                        attrs={"note": "虛擬入口，不是資產"}))

    # --- 資產：歸併後的結果，一台機器一個節點 -----------------------------
    known: set[str] = set()
    for row in assets:
        asset = str(row["asset_id"])
        known.add(asset)
        graph.add_node(Node(asset, ASSET, label=str(row.get("hostname", asset)), attrs={
            "zone": row.get("zone", ""),
            "crown_jewel": row.get("crown_jewel") == "yes",
            "interfaces": sum(1 for i in interfaces if i["asset_id"] == asset),
        }))

    missing_inventory = inventory.assets - known
    for asset in sorted(missing_inventory):
        graph.exclude(asset, asset, ASSET, "介面指向清冊上沒有的資產")

    # --- 服務：攻擊面是服務，不是主機 -------------------------------------
    listening: set[tuple[str, int]] = set()
    for row in services:
        asset, port, state = str(row["asset_id"]), int(row["port"]), str(row["state"])
        if asset not in known:
            graph.exclude(asset, service_id(asset, port), HOSTS, "服務掛在清冊外的資產上")
            continue
        node = service_id(asset, port)
        label = f"{row['service']} {row.get('version', '')}".strip()
        graph.add_node(Node(node, SERVICE, label=label,
                            attrs={"asset": asset, "port": port, "state": state,
                                   "service": row["service"],
                                   "version": row.get("version", "")}))
        graph.add_edge(Edge(asset, node, HOSTS))
        if state == LISTENING:
            listening.add((asset, port))

    # --- 網路：只有「政策允許」且「真的有人在聽」的連線才是一步 -----------
    for row in network_edges:
        source, target, port = str(row["source"]), str(row["target"]), int(row["port"])
        node = service_id(target, port)
        if row.get("allowed") != "yes":
            graph.exclude(source, node, REACHES, "政策拒絕這條連線")
            continue
        if target not in known:
            graph.exclude(source, node, REACHES, "目的端不在清冊上")
            continue
        if node not in graph.nodes:
            graph.exclude(source, node, REACHES, f"{target} 的 {port} 埠沒有登錄任何服務")
            continue
        if (target, port) not in listening:
            state = graph.nodes[node].attrs.get("state")
            graph.exclude(source, node, REACHES, f"服務狀態為 {state}，不是 listening")
            continue
        if source != INTERNET_ID.upper() and source not in known and source != INTERNET_ID:
            graph.exclude(source, node, REACHES, "來源不在清冊上")
            continue
        origin = INTERNET_ID if source.upper() == "INTERNET" else source
        graph.add_edge(Edge(origin, node, REACHES,
                            attrs={"port": port, "protocol": row.get("protocol", "tcp")}))

    # --- 身分：帳號讓攻擊者從一台走到另一台 -------------------------------
    for row in identity_edges:
        source, target = str(row["source"]), str(row["target"])
        account = account_id(str(row["account"]))
        if source not in known or target not in known:
            graph.exclude(source, target, GRANTS, "帳號關係的兩端必須都在清冊上")
            continue
        graph.add_node(Node(account, ACCOUNT, label=str(row["account"]),
                            attrs={"account": row["account"]}))
        graph.add_edge(Edge(source, account, USES))
        graph.add_edge(Edge(account, target, GRANTS,
                            attrs={"privilege": row.get("privilege", "")}))
    return graph
