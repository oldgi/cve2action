"""在攻擊圖上找路徑，並把它render 成人讀得懂的樣子。

**路徑的數量不是資訊量。** Northstar 現在有 14 條 Internet → Crown Jewel 的路徑，
但它們只用到 9 個中間節點，同一條邊最多被重複走 8 次。把 14 條全畫出來，
是把同一件事講 8 遍。

所以呈現的主體是**一條路徑**，線性的、每一跳旁邊附上它憑什麼走得過去：
port 與服務版本、用到的帳號與權限、沿途有什麼可利用的漏洞。沒有那行證據，
箭頭只是裝飾。最後再用一行告訴你這條路不孤單，就不必畫出另外 13 條。

走一步有兩種方式，對應圖上兩組邊：

- **網路**：`asset --reaches--> service`，而那個 service 掛在目標資產上。
- **身分**：`asset --uses--> account --grants--> asset`。

兩者缺一不可才構成橫向移動：網路到得了但沒有權限、有權限但網路到不了，
都不算走得過去。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import ASSET, GRANTS, INTERNET_ID, REACHES, USES, AttackGraph

NETWORK = "network"
IDENTITY = "identity"


@dataclass(frozen=True)
class Hop:
    """路徑上的一步：從哪裡、到哪台、憑什麼。"""

    kind: str
    source: str
    target: str
    via: str = ""          # port 或帳號
    detail: str = ""       # 服務版本或權限
    service_node: str = ""

    @property
    def arrow(self) -> str:
        return f"[{self.via}]" if self.kind == NETWORK else f"({self.via})"


@dataclass(frozen=True)
class Path:
    hops: tuple[Hop, ...]
    source: str = INTERNET_ID

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def target(self) -> str:
        return self.hops[-1].target if self.hops else self.source

    @property
    def assets(self) -> tuple[str, ...]:
        return (self.source,) + tuple(h.target for h in self.hops)

    @property
    def edge_keys(self) -> tuple[tuple[str, str], ...]:
        return tuple((h.source, h.target) for h in self.hops)


def _steps(graph: AttackGraph, asset: str) -> list[Hop]:
    """從一台資產（或 internet）可以走到哪裡。"""
    found: list[Hop] = []
    for edge in graph.out_edges(asset, REACHES):
        service = graph.nodes[edge.target]
        found.append(Hop(NETWORK, asset, service.attrs["asset"],
                         via=f"{edge.attrs.get('port')}/{edge.attrs.get('protocol', 'tcp')}",
                         detail=service.label, service_node=service.id))
    for use in graph.out_edges(asset, USES):
        for grant in graph.out_edges(use.target, GRANTS):
            found.append(Hop(IDENTITY, asset, grant.target,
                             via=graph.nodes[use.target].label,
                             detail=grant.attrs.get("privilege", "")))
    return found


def find_paths(graph: AttackGraph, target: str, source: str = INTERNET_ID,
               max_hops: int = 8) -> list[Path]:
    """列出 source 到 target 的所有簡單路徑（不重複造訪同一台）。

    依跳數由短到長排序。長度相同時依沿途資產名稱排序——**排序必須是決定性的**，
    否則同樣的資料每次跑出不同的「最短路徑」，截圖與文章就對不起來。
    """
    results: list[Path] = []

    def walk(current: str, seen: tuple[str, ...], hops: tuple[Hop, ...]) -> None:
        if len(hops) > max_hops:
            return
        if current == target and hops:
            results.append(Path(hops, source))
            return
        for hop in _steps(graph, current):
            if hop.target in seen:
                continue
            walk(hop.target, seen + (hop.target,), hops + (hop,))

    walk(source, (source,), ())
    results.sort(key=lambda p: (p.length, p.assets))
    return results


def shared_hops(paths: list[Path]) -> dict[str, int]:
    """每個中間節點出現在幾條路徑上——Day 24 的 choke point 就是這個數字。"""
    counts: dict[str, int] = {}
    for path in paths:
        for asset in path.assets[1:-1]:
            counts[asset] = counts.get(asset, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


@dataclass
class PathContext:
    """渲染時要附上的旁證。"""

    findings: dict[str, list[str]] = field(default_factory=dict)  # asset -> [CVE]
    crown_jewels: frozenset[str] = frozenset()
    siblings: int = 0  # 還有幾條路徑共用這條路上的節點


def render_path(path: Path, graph: AttackGraph, context: PathContext | None = None) -> str:
    """把一條路徑排成線性的樣子，每一跳附上它憑什麼走得過去。"""
    context = context or PathContext()
    lines = [path.source.upper()]
    for hop in path.hops:
        jewel = " 👑 Crown Jewel" if hop.target in context.crown_jewels else ""
        lines.append(f"  └─{hop.arrow}→ {hop.target}{jewel}")
        if hop.detail:
            label = "服務" if hop.kind == NETWORK else "權限"
            lines.append(f"              {label}：{hop.detail}")
        cves = context.findings.get(hop.target, [])
        if cves:
            lines.append(f"              漏洞：{'、'.join(cves)}")
    summary = f"{path.length} 跳"
    exploitable = sum(1 for h in path.hops if context.findings.get(h.target))
    if exploitable:
        summary += f"　｜　沿途 {exploitable} 台有已知漏洞"
    if context.siblings:
        summary += f"　｜　另有 {context.siblings} 條路徑共用其中的節點"
    lines.append(summary)
    return "\n".join(lines)


def render_summary(paths: list[Path], graph: AttackGraph) -> str:
    """路徑很多時不要全畫——講數量、講共用節點，然後只展開一條。"""
    if not paths:
        return "沒有找到路徑。注意：查無路徑不等於證明不可達，被排除的連線見 excluded。"
    lengths: dict[int, int] = {}
    for path in paths:
        lengths[path.length] = lengths.get(path.length, 0) + 1
    spread = "、".join(f"{k} 跳 {v} 條" for k, v in sorted(lengths.items()))
    lines = [f"共 {len(paths)} 條路徑（{spread}）",
             f"只用到 {len({a for p in paths for a in p.assets[1:-1]})} 個中間節點"]
    top = list(shared_hops(paths).items())[:3]
    for asset, count in top:
        jewel = graph.nodes[asset].kind == ASSET
        lines.append(f"  {asset:<22}{'' if jewel else '?'} 在 {count}/{len(paths)} 條路徑上")
    return "\n".join(lines)
