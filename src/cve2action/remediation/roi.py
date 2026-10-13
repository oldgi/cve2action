"""Remediation ROI（Day 27）：用最少變更切斷最多攻擊路徑。

Day 26 回答「同一筆 finding 內，先做哪一項」。今天回答跨 finding 的問題：
**每一項措施做下去，分數降多少、路徑少幾條、花幾個小時。**

## 做法：反事實重算，不是查表

每一項措施都套到一份圖的複本上，然後**整條管線重跑**——路徑搜尋（Day 22）、
路徑分數 A（Day 23）、40 筆重新排名。降低幅度是重算出來的差，不是估的。

| 措施 | 對圖做什麼 | 對佇列做什麼 |
|---|---|---|
| `isolate` | 拿掉這台資產進出的每一條邊 | 漏洞還在，分數照圖重算 |
| `disable_service` | 拿掉通往這個服務的 `reaches` 邊 | 同上 |
| `patch` | **什麼都不做**（見下） | 這筆離開佇列 |
| `config_change` | 不做 | 待重掃：降幅記 0，不是估計值 |
| `compensating_control` | 不做 | 待驗證：降幅記 0（Day 12：分數只認驗證過的控制） |

### 為什麼 patch 切不掉任何路徑

Day 19 的圖模型裡，一步攻擊是「到得了一個在聽的服務，就拿下那台機器」——
**它從來不看那個服務有沒有可利用的漏洞。** 這是保守的讀法：不知道能不能打，
就當它能打（UNKNOWN 不得降低風險）。代價是：修掉一個漏洞，圖一條邊都不會少。

在這個模型裡，**只有隔離與關服務切得掉路徑**。要讓 patch 也能切路徑，
就得替每一步登記「憑哪一個漏洞」——那會改動 Day 22–24 已發表的 30 條路徑。
今天不改，量出它的後果並寫下來。

## 降幅是 Priority Score 點數，不是機率

`score_drop` 是全部 finding 重算前後的分數差加總。它回答「這項措施讓佇列輕了多少」，
不回答「風險少了幾成」——藍圖 §15：模型看似精確，是要防的風險。

## 成本不明就沒有 ROI

工時讀不到時 `per_hour` 是 `None`，不參與排名。把不知道當成零，除下去會得到無限大，
它就會永遠第一名。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..attack_graph.model import REACHES, AttackGraph
from ..attack_graph.paths import find_paths
from .candidates import NO_CANDIDATE, Candidate, Plan

Key = tuple[str, str]  # (asset, cve)
# 給一份圖，回傳每筆 finding 的分數。由呼叫端組裝（它知道評分要哪些輸入）。
Scorer = Callable[[AttackGraph], dict[Key, float]]

PROVEN = "PROVEN"
PENDING_RESCAN = "PENDING_RESCAN"
PENDING_VERIFICATION = "PENDING_VERIFICATION"
NO_GRAPH_EFFECT = "NO_GRAPH_EFFECT"  # disable_service 對不到圖上的服務


def without_asset(graph: AttackGraph, asset: str) -> AttackGraph:
    """隔離：這台資產、它的服務、通往它的帳號邊全部斷開。節點留著（它還在，只是走不到）。"""
    def touches(edge) -> bool:
        if asset in (edge.source, edge.target):
            return True
        for end in (edge.source, edge.target):
            if graph.nodes[end].attrs.get("asset") == asset:
                return True
        return False
    return AttackGraph(nodes=dict(graph.nodes),
                       edges=[e for e in graph.edges if not touches(e)],
                       excluded=list(graph.excluded))


def without_service(graph: AttackGraph, service_node: str) -> AttackGraph:
    return AttackGraph(nodes=dict(graph.nodes),
                       edges=[e for e in graph.edges
                              if not (e.kind == REACHES and e.target == service_node)],
                       excluded=list(graph.excluded))


def jewel_paths(graph: AttackGraph) -> int:
    return sum(len(find_paths(graph, j.id)) for j in graph.crown_jewels)


def service_nodes(graph: AttackGraph, asset: str, service: str) -> list[str]:
    """弱掃的服務名對到圖上的服務節點。對不到就回空——不猜（Day 21：名稱 join 會猜錯）。"""
    return sorted(n.id for n in graph.nodes.values()
                  if n.attrs.get("asset") == asset and n.attrs.get("service") == service)


@dataclass(frozen=True)
class Outcome:
    candidate: Candidate
    status: str
    paths_before: int
    paths_after: int
    score_drop: float
    findings_moved: int = 0  # 分數有變的 finding 數（含自己）
    note: str = ""

    @property
    def paths_cut(self) -> int:
        return self.paths_before - self.paths_after

    @property
    def per_hour(self) -> float | None:
        hours = self.candidate.effort_hours
        if hours is None or hours <= 0 or self.status != PROVEN:
            return None
        return round(self.score_drop / hours, 3)


@dataclass
class RoiReport:
    paths_total: int
    queue_total: float
    outcomes: list[Outcome] = field(default_factory=list)
    skipped: int = 0  # 沒有候選的 finding 數


def _diff(before: dict[Key, float], after: dict[Key, float],
          leaves: Key | None = None) -> tuple[float, int]:
    drop, moved = 0.0, 0
    for key, value in before.items():
        new = 0.0 if key == leaves else after.get(key, value)
        if abs(value - new) > 1e-9:
            moved += 1
            drop += value - new
    return round(drop, 2), moved


def evaluate(graph: AttackGraph, plans: list[Plan], scorer: Scorer,
             services: dict[Key, str]) -> RoiReport:
    """對每一筆有候選的 finding、每一個沒被否決的候選，重算一次。

    `services` 是弱掃的 (資產, CVE) → 服務名，關服務時用來找圖上的服務節點。
    """
    baseline = scorer(graph)
    total = jewel_paths(graph)
    report = RoiReport(paths_total=total, queue_total=round(sum(baseline.values()), 2),
                       skipped=sum(1 for p in plans if p.status == NO_CANDIDATE))
    cache: dict[tuple[str, str], tuple[int, dict[Key, float]]] = {}

    for item in plans:
        if item.status != "PLANNED":
            continue
        key = (item.asset, item.cve.upper())
        for cand in item.offered:
            if cand.action == "patch":
                drop, moved = _diff(baseline, baseline, leaves=key)
                report.outcomes.append(Outcome(cand, PROVEN, total, total, drop, moved,
                                               "離開佇列；圖模型不看漏洞，切不掉路徑"))
                continue
            if cand.action == "config_change":
                report.outcomes.append(Outcome(cand, PENDING_RESCAN, total, total, 0.0,
                                               note="版本沒變，重掃前不計降幅"))
                continue
            if cand.action == "compensating_control":
                report.outcomes.append(Outcome(cand, PENDING_VERIFICATION, total, total, 0.0,
                                               note="控制驗證前不折減（Day 12）"))
                continue

            if cand.action == "isolate":
                cache_key = ("isolate", cand.asset)
                mutate = lambda g, a=cand.asset: without_asset(g, a)  # noqa: E731
            else:  # disable_service
                nodes = service_nodes(graph, cand.asset, services.get(key, ""))
                if len(nodes) != 1:
                    report.outcomes.append(Outcome(
                        cand, NO_GRAPH_EFFECT, total, total, 0.0,
                        note=f"弱掃服務 {services.get(key, '?')!r} 對到 {len(nodes)} 個服務節點，"
                             "不猜"))
                    continue
                cache_key = ("service", nodes[0])
                mutate = lambda g, n=nodes[0]: without_service(g, n)  # noqa: E731

            if cache_key not in cache:
                changed = mutate(graph)
                cache[cache_key] = (jewel_paths(changed), scorer(changed))
            after_paths, after_scores = cache[cache_key]
            drop, moved = _diff(baseline, after_scores)
            report.outcomes.append(Outcome(cand, PROVEN, total, after_paths, drop, moved,
                                           "漏洞還在；降的是走得到它的路"))
    return report


def combined(graph: AttackGraph, scorer: Scorer, outcomes: list[Outcome],
             services: dict[Key, str]) -> tuple[int, float]:
    """同時做這幾項之後，剩幾條路徑、佇列降多少。**不能把單項的數字加起來**（Day 24）。"""
    changed = graph
    leaving: set[Key] = set()
    for item in outcomes:
        cand = item.candidate
        key = (cand.asset, cand.cve)
        if item.status != PROVEN:
            continue
        if cand.action == "isolate":
            changed = without_asset(changed, cand.asset)
        elif cand.action == "disable_service":
            for node in service_nodes(graph, cand.asset, services.get(key, "")):
                changed = without_service(changed, node)
        elif cand.action == "patch":
            leaving.add(key)
    before, after = scorer(graph), scorer(changed)
    drop = sum(v - (0.0 if k in leaving else after.get(k, v)) for k, v in before.items())
    return jewel_paths(changed), round(drop, 2)


def greedy(graph: AttackGraph, scorer: Scorer, report: RoiReport,
           services: dict[Key, str], budget_hours: float) -> list[Outcome]:
    """在工時預算內，每一步挑「重算之後」每小時降最多的那一項。

    每加一項就重算組合，而不是用單項數字排一次就收工——兩台在同一條串聯上，
    修了一台另一台就不值那麼多了。同一筆 finding 只挑一項（Day 26 的先做／結案另外看）。
    """
    pool = [o for o in report.outcomes if o.per_hour is not None]
    chosen: list[Outcome] = []
    spent = 0.0
    taken: set[Key] = set()
    current = 0.0
    while True:
        best, best_rate, best_drop = None, 0.0, current
        for item in pool:
            cand = item.candidate
            key = (cand.asset, cand.cve)
            if item in chosen or key in taken or spent + cand.effort_hours > budget_hours:
                continue
            _paths, drop = combined(graph, scorer, chosen + [item], services)
            rate = (drop - current) / cand.effort_hours
            if rate > best_rate + 1e-9:
                best, best_rate, best_drop = item, rate, drop
        if best is None:
            return chosen
        chosen.append(best)
        taken.add((best.candidate.asset, best.candidate.cve))
        spent += best.candidate.effort_hours
        current = best_drop


@dataclass(frozen=True)
class WhatIf:
    """清冊裡沒有的措施：Day 24 的瓶頸如果能隔離。成本不知道，所以沒有 ROI、不進組合。"""

    asset: str
    paths_after: int
    score_drop: float


def choke_targets(chokes, top: int = 3) -> list[str]:
    """Day 24 說最該動的：每個最小切割都少不了的，加上單台切最多的可處置節點。

    同樣切數時依資產名排，結果必須是決定性的——CLI 與儀表板要列出同一組。
    """
    movable = sorted((c for c in chokes.chokes if c.actionable), key=lambda c: (-c.cuts, c.asset))
    return list(dict.fromkeys(list(chokes.universal) + [c.asset for c in movable[:top]]))


def what_if(graph: AttackGraph, scorer: Scorer, assets: list[str]) -> list[WhatIf]:
    baseline = scorer(graph)
    out = []
    for asset in assets:
        changed = without_asset(graph, asset)
        drop, _moved = _diff(baseline, scorer(changed))
        out.append(WhatIf(asset, jewel_paths(changed), drop))
    return out


def render(report: RoiReport, plan_paths: tuple[int, float] | None = None,
           chosen: list[Outcome] | None = None, budget: float | None = None,
           hypotheticals: list[WhatIf] | None = None) -> str:
    lines = [f"措施重算（{len(report.outcomes)} 項；通往 Crown Jewel 的路徑 "
             f"{report.paths_total} 條；佇列總分 {report.queue_total}）", ""]
    lines.append(f"  {'措施':<46}{'工時':>5}{'切路徑':>7}{'降分':>8}{'每小時':>8}  狀態")
    ordered = sorted(report.outcomes,
                     key=lambda o: (o.per_hour is None, -(o.per_hour or 0), -o.paths_cut))
    for item in ordered:
        cand = item.candidate
        name = f"{cand.remediation_id} {cand.action} {cand.asset}"
        hours = "?" if cand.effort_hours is None else f"{cand.effort_hours:g}"
        rate = "—" if item.per_hour is None else f"{item.per_hour:.2f}"
        lines.append(f"  {name:<46}{hours:>5}{item.paths_cut:>7}{item.score_drop:>8.2f}"
                     f"{rate:>8}  {item.status}　{item.note}")
    cutters = [o for o in report.outcomes if o.paths_cut > 0]
    lines.append("")
    lines.append(f"  切得掉路徑的措施：{len(cutters)} 項"
                 f"（patch {sum(o.candidate.action == 'patch' for o in report.outcomes)} 項"
                 "，一條都切不掉）")
    if chosen is not None:
        lines.append("")
        spent = sum(o.candidate.effort_hours or 0 for o in chosen)
        lines.append(f"  預算 {budget:g} 小時的組合（每步重算，花 {spent:g} 小時）：")
        for item in chosen:
            lines.append(f"      {item.candidate.remediation_id} {item.candidate.action} "
                         f"{item.candidate.asset}")
        if plan_paths is not None:
            lines.append(f"  一起做：路徑 {report.paths_total} → {plan_paths[0]}，"
                         f"佇列降 {plan_paths[1]}")
    if hypotheticals:
        lines.append("")
        lines.append("  清冊裡沒有、但 Day 24 說最該動的（隔離試算；成本不明，不進組合）：")
        for item in hypotheticals:
            lines.append(f"      {item.asset:<20} 路徑 {report.paths_total} → {item.paths_after}"
                         f"，佇列降 {item.score_drop}")
    lines.append(f"  沒有候選、不進比較的 finding：{report.skipped} 筆")
    return "\n".join(lines)
