"""查無路徑時，說得出是為什麼（Day 22）。

藍圖 §16 的 Day 24 門檻只寫了一句：「無法到達的資產不會被誤標為可達」。
反過來那半句沒寫，但更容易出事：**可達的資產不應該被誤標為安全。**

路徑搜尋回空集合有四種完全不同的意思，混成一句「查無路徑」就看不出該做什麼：

| 判定 | 意思 | 要做什麼 |
|---|---|---|
| `NO_INBOUND` | 清冊裡沒有任何指向它的連線 | **去查清冊**——這是資料缺口，不是隔離 |
| `SOURCE_UNREACHABLE` | 有入邊，但來源自己也到不了 | 看來源那條鏈 |
| `BLOCKED_BY_POLICY` | 入邊都被政策明文拒絕 | 這才接近「被擋住」 |
| `EXCLUDED` | 入邊因服務沒在聽、前提不成立等被排除 | 看排除理由，可能只是暫時 |

只有 `BLOCKED_BY_POLICY` 勉強算「安全」，而且也只在政策確實被執行的前提下。
其餘三種都是**我們不知道**，不是**它到不了**。
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import ASSET, GRANTS, REACHES, USES, AttackGraph

NO_INBOUND = "NO_INBOUND"
SOURCE_UNREACHABLE = "SOURCE_UNREACHABLE"
BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
EXCLUDED = "EXCLUDED"
REACHABLE = "REACHABLE"


@dataclass(frozen=True)
class NoPath:
    """為什麼找不到通往這台資產的路徑。"""

    asset: str
    status: str
    evidence: tuple[str, ...] = ()

    @property
    def means_safe(self) -> bool:
        """只有政策明文拒絕勉強算安全——其餘都是「我們不知道」。"""
        return self.status == BLOCKED_BY_POLICY

    def __str__(self) -> str:
        head = f"{self.asset}：{self.status}"
        return head + ("\n  " + "\n  ".join(self.evidence) if self.evidence else "")


def _inbound(graph: AttackGraph, asset: str) -> tuple[list, list]:
    """指向這台資產的網路邊與身分邊。"""
    services = {n.id for n in graph.nodes.values()
                if n.kind != ASSET and n.attrs.get("asset") == asset}
    network = [e for e in graph.edges if e.kind == REACHES and e.target in services]
    identity = [e for e in graph.edges if e.kind == GRANTS and e.target == asset]
    return network, identity


def _source_of(graph: AttackGraph, account_node: str) -> str | None:
    return next((e.source for e in graph.edges
                 if e.kind == USES and e.target == account_node), None)


def diagnose(graph: AttackGraph, asset: str, reachable: set[str]) -> NoPath:
    """`reachable` 是已知有路徑的資產集合，用來分辨「來源自己也到不了」。"""
    if asset in reachable:
        return NoPath(asset, REACHABLE)

    network, identity = _inbound(graph, asset)
    excluded = [x for x in graph.excluded if x.target.startswith(asset)
                or x.target == asset]

    denied = [x for x in excluded if "政策拒絕" in x.reason]
    if not network and not identity:
        if not excluded:
            return NoPath(asset, NO_INBOUND,
                          ("清冊裡沒有任何指向它的連線或權限關係",
                           "這是資料缺口，不是隔離——沒有記錄不等於到不了"))
        # 入邊全部被政策明文拒絕，才勉強算「被擋住」；
        # 混雜其他排除理由（服務沒在聽、前提不成立）就只是走不通，不是被擋住。
        status = BLOCKED_BY_POLICY if len(denied) == len(excluded) else EXCLUDED
        return NoPath(asset, status,
                      tuple(f"{x.source} → {x.target}：{x.reason}" for x in excluded))

    sources = {e.source for e in network}
    sources |= {s for e in identity if (s := _source_of(graph, e.source))}
    orphans = sorted(s for s in sources if s not in reachable and s != "internet")
    if orphans:
        return NoPath(asset, SOURCE_UNREACHABLE,
                      tuple(f"入邊來自 {s}，而 {s} 自己也沒有路徑" for s in orphans))

    blocked = [e for e in identity if e.attrs.get("precondition") == "BLOCKED"]
    if blocked:
        return NoPath(asset, EXCLUDED,
                      tuple(f"身分邊前提不成立：{e.attrs.get('precondition_reason', '')}"
                            for e in blocked))
    return NoPath(asset, EXCLUDED, ("有入邊但都走不通，理由見 graph.excluded",))


@dataclass
class Coverage:
    """整份清冊的路徑覆蓋狀況。"""

    reachable: tuple[str, ...] = ()
    unreached: tuple[NoPath, ...] = ()

    @property
    def counts(self) -> dict[str, int]:
        found: dict[str, int] = {REACHABLE: len(self.reachable)}
        for item in self.unreached:
            found[item.status] = found.get(item.status, 0) + 1
        return found

    @property
    def genuinely_blocked(self) -> tuple[NoPath, ...]:
        return tuple(n for n in self.unreached if n.means_safe)


def coverage(graph: AttackGraph, reachable: set[str]) -> Coverage:
    assets = sorted(n.id for n in graph.of_kind(ASSET))
    unreached = tuple(diagnose(graph, a, reachable) for a in assets if a not in reachable)
    return Coverage(tuple(sorted(reachable)), unreached)


def render_coverage(result: Coverage) -> str:
    lines = [f"有路徑 {len(result.reachable)} 台、查無路徑 {len(result.unreached)} 台", ""]
    grouped: dict[str, list[NoPath]] = {}
    for item in result.unreached:
        grouped.setdefault(item.status, []).append(item)
    for status, items in sorted(grouped.items()):
        lines.append(f"  {status}（{len(items)} 台）：{'、'.join(i.asset for i in items)}")
        if items[0].evidence:
            lines.append(f"    {items[0].evidence[0]}")
    safe = len(result.genuinely_blocked)
    lines.append("")
    lines.append(f"其中真的算「被擋住」的：{safe} 台——"
                 "其餘是我們不知道，不是它到不了。")
    return "\n".join(lines)
