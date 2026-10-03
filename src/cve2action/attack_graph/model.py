"""攻擊圖的節點與邊（Day 19）。

藍圖 §15 把「節點類型超過六種」列為攻擊圖失控的徵兆，要求 MVP 只留
資產、服務、帳號、Crown Jewel。這裡用了**三種**加一個虛擬入口：

| 節點 | 代表 |
|---|---|
| `internet` | 外部攻擊者的起點。虛擬節點，不是資產。 |
| `asset` | 一台機器——歸併後的結果，不是一個 IP。 |
| `service` | 某台機器某個 port 上在聽的東西。攻擊面是服務，不是主機。 |
| `account` | 一個帳號。它讓攻擊者從一台機器走到另一台。 |

**Crown Jewel 沒有做成節點，它是資產的一個旗標。** 做成節點就要多一種邊，
而那條邊不帶任何新資訊——jewel 就是那台資產本身。少一種節點就少一種
之後每天都要維護的東西。

邊有四種，對應四件可查證的事：

| 邊 | 從 → 到 | 來源 |
|---|---|---|
| `hosts` | asset → service | services.csv |
| `reaches` | internet/asset → service | network_edges.csv（帶 port） |
| `uses` | asset → account | identity_edges.csv |
| `grants` | account → asset | identity_edges.csv（帶 privilege） |

一步攻擊＝`reaches` 到一個 service，拿下它所在的 asset，再經由
`uses`／`grants` 走到下一台。Day 22 的路徑搜尋就是在這四種邊上走。

**被排除的邊不會消失。** 政策拒絕的連線、沒有服務在聽的 port、被防火牆
擋住的服務，都記在 `excluded` 裡並附理由。Day 22 要回答「為什麼這台沒有路徑」，
答案就在那裡——「查無路徑」和「證明不可達」是兩件事。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

INTERNET = "internet"
ASSET = "asset"
SERVICE = "service"
ACCOUNT = "account"
NODE_KINDS = (INTERNET, ASSET, SERVICE, ACCOUNT)

HOSTS = "hosts"
REACHES = "reaches"
USES = "uses"
GRANTS = "grants"
EDGE_KINDS = (HOSTS, REACHES, USES, GRANTS)

INTERNET_ID = "internet"


def service_id(asset: str, port: int | str) -> str:
    return f"{asset}:{port}"


def account_id(account: str) -> str:
    return f"account:{account}"


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    label: str = ""
    attrs: dict = field(default_factory=dict)

    @property
    def crown_jewel(self) -> bool:
        return bool(self.attrs.get("crown_jewel"))


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str
    attrs: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.kind)


@dataclass(frozen=True)
class Excluded:
    """一條**沒有**進入圖的邊，以及它被排除的理由。"""

    source: str
    target: str
    kind: str
    reason: str


@dataclass
class AttackGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    excluded: list[Excluded] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is not None:
            return existing
        if node.kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind {node.kind!r}")
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> None:
        if edge.kind not in EDGE_KINDS:
            raise ValueError(f"unknown edge kind {edge.kind!r}")
        for end in (edge.source, edge.target):
            if end not in self.nodes:
                raise ValueError(f"edge endpoint {end!r} is not a node")
        self.edges.append(edge)

    def exclude(self, source: str, target: str, kind: str, reason: str) -> None:
        self.excluded.append(Excluded(source, target, kind, reason))

    # --- 查詢 ---------------------------------------------------------------

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    @property
    def crown_jewels(self) -> list[Node]:
        return [n for n in self.of_kind(ASSET) if n.crown_jewel]

    def out_edges(self, node_id: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self.edges
                if e.source == node_id and (kind is None or e.kind == kind)]

    def counts(self) -> dict[str, int]:
        result = {f"node:{k}": len(self.of_kind(k)) for k in NODE_KINDS}
        for kind in EDGE_KINDS:
            result[f"edge:{kind}"] = sum(1 for e in self.edges if e.kind == kind)
        result["excluded"] = len(self.excluded)
        return result

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, "label": n.label, **n.attrs}
                      for n in self.nodes.values()],
            "edges": [{"source": e.source, "target": e.target, "kind": e.kind, **e.attrs}
                      for e in self.edges],
            "excluded": [{"source": x.source, "target": x.target, "kind": x.kind,
                          "reason": x.reason} for x in self.excluded],
            "counts": self.counts(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
