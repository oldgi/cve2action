"""攻擊路徑分數 A（Day 23，藍圖 §9.3）。

```text
A = 0.40·A_Reachability + 0.25·A_Privilege + 0.25·A_CrownJewel + 0.10·A_Hops
```

四項都從 Day 19–22 建好的圖算出來，不另外發明輸入：

| 項 | 來自 | 定義 |
|---|---|---|
| `A_Reachability` | 路徑搜尋 | 有 Internet 可達路徑＝1.0，沒有＝0.05（下限，見下） |
| `A_Privilege` | Day 21 的 `privilege_obtainable` | 權限等級正規化到 0–1 |
| `A_CrownJewel` | 路徑搜尋 | 它自己是或能走到 Crown Jewel＝1.0，否則 0 |
| `A_Hops` | 最短路徑長度 | `1 / 跳數`，愈短愈高 |

## 兩個不補零的地方

**沒有路徑時 `A_Reachability` 取 0.05，不取 0。** Day 22 已經證明：六台「查無路徑」
沒有一台是被擋住的，全部是清冊裡沒有指向它的連線。給 0 等於宣告「證明不可達」，
而我們只能說「沒查到」。這個下限也正是藍圖 §9.5 在 `max(A, 0.05)` 裡寫的那個數。

**權限未知時整項移除，權重退給 `A_Reachability`。** 不猜中間值——Day 14 處理
缺威脅資料時用的是同一招。退給可達性是因為那是唯一一定知道的項。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..attack_graph.identity import PRIVILEGE_RANK
from ..attack_graph.model import ASSET, AttackGraph
from ..attack_graph.paths import find_paths

WEIGHTS = {"reachability": 0.40, "privilege": 0.25, "crown_jewel": 0.25, "hops": 0.10}
UNREACHED_FLOOR = 0.05
MAX_RANK = max(PRIVILEGE_RANK.values())


@dataclass(frozen=True)
class PathScore:
    """一台資產的路徑分數，連同四項的值與理由。"""

    asset: str
    value: float
    components: dict[str, float] = field(default_factory=dict)
    applied_weights: dict[str, float] = field(default_factory=dict)
    detail: str = ""
    hops: int | None = None
    reaches_jewel: bool = False

    @property
    def reachable(self) -> bool:
        return self.components.get("reachability", 0.0) > UNREACHED_FLOOR


def _hops_component(shortest: int | None) -> float:
    return 1.0 / shortest if shortest else 0.0


def compute(graph: AttackGraph, privileges: dict[str, object] | None = None
            ) -> dict[str, PathScore]:
    """對圖上每一台資產算 A。`privileges` 是 Day 21 的 `Obtainable`，可不給。"""
    privileges = privileges or {}
    jewels = {n.id for n in graph.crown_jewels}
    assets = [n.id for n in graph.of_kind(ASSET)]

    inbound: dict[str, list] = {a: find_paths(graph, a) for a in assets}
    # 從某台資產出發能不能走到 Crown Jewel：以它為起點再搜一次
    to_jewel: dict[str, bool] = {}
    for asset in assets:
        if asset in jewels:
            to_jewel[asset] = True
            continue
        to_jewel[asset] = any(find_paths(graph, jewel, source=asset) for jewel in jewels)

    scores: dict[str, PathScore] = {}
    for asset in assets:
        paths = inbound[asset]
        shortest = min((p.length for p in paths), default=None)
        reach = 1.0 if paths else UNREACHED_FLOOR

        components = {
            "reachability": reach,
            "crown_jewel": 1.0 if to_jewel[asset] else 0.0,
            "hops": _hops_component(shortest),
        }
        weights = dict(WEIGHTS)
        obtainable = privileges.get(asset)
        notes = []
        if obtainable is not None and getattr(obtainable, "proven", False):
            components["privilege"] = PRIVILEGE_RANK.get(obtainable.level, 0) / MAX_RANK
        else:
            # 權限未知：移除該項，權重退給可達性（唯一一定知道的項）
            weights["reachability"] += weights.pop("privilege")
            notes.append("權限未知，該項移除、權重退回可達性")
        if not paths:
            notes.append(f"查無路徑，可達性取下限 {UNREACHED_FLOOR}（不是證明不可達）")

        value = round(sum(weights[k] * v for k, v in components.items()), 4)
        scores[asset] = PathScore(asset, value, components, weights,
                                  detail="；".join(notes), hops=shortest,
                                  reaches_jewel=to_jewel[asset])
    return scores
