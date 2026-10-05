"""Choke point：通往 Crown Jewel 的共同瓶頸（Day 24，藍圖 §10 Day 24）。

Day 22 的 `shared_hops` 數的是「這台出現在幾條路徑上」，而它的註解當時寫著
「Day 24 的 choke point 就是這個數字」。**那句話是錯的，今天把它推翻。**

出現頻率回答的是「它在多少條路上」，不是「修掉它能擋掉多少條」。兩者在 Northstar
上給出不同的第一名，而且差距不小：

| 排法 | 第一名 | 數字 |
|---|---|---|
| 出現頻率 | `NS-APP-ORDER-01` | 16/30 條路徑 |
| 反事實切斷 | `NS-DB-CUSTOMER-01` | 切 22/30（只出現在 11 條上） |

資料庫只出現在 11 條路上卻切得掉 22 條，因為它同時是通往備份主機的唯一一跳。
**但它是 Crown Jewel——「把它移除」不是一個做得到的處置。** 所以反事實必須知道
哪些節點可以動、哪些是要保護的目標，否則它會算出一個沒人能執行的答案。

## 三件在這裡被量出來、而頻率看不出來的事

1. **切斷數不可相加。** `NS-VPN-GW-01` 切 15、`NS-JUMP-01` 切 15，兩台一起修
   還是切 15——它們在同一條串聯上。把兩個數字加起來會得到 30，也就是「全部擋掉」，
   而真實答案是一半。
2. **沒有任何單一可處置節點能切斷任何一個 Crown Jewel。** 四個目標各自都需要
   至少兩台。單點瓶頸在這份清冊上**不存在**。
3. **`NS-JUMP-01` 出現在全部四個最小切割集合裡。** 它不是出現最多次的那一台，
   但它是唯一每個答案都少不了的。這才是「共同瓶頸」該有的定義。

## 規模

最小切割用窮舉：可處置中間節點的所有子集，由小到大。8 個節點是 255 個子集，
乘上四個目標與路徑枚舉還算得動；再大就得換成真正的最小割演算法。
`MAX_EXHAUSTIVE` 擋住這件事，超過就明說算不出來，不給一個偷工的答案。
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .model import AttackGraph
from .paths import Path, find_paths

# 可處置節點超過這個數就不做窮舉；寧可說算不出來，也不給一個只掃了一部分的答案
MAX_EXHAUSTIVE = 12


@dataclass(frozen=True)
class Choke:
    """一個候選瓶頸：它出現在幾條路上，以及**移除它之後**還剩幾條。"""

    asset: str
    on_paths: int
    cuts: int
    remaining: int
    jewels_cut: tuple[str, ...] = ()
    actionable: bool = True
    note: str = ""

    @property
    def share(self) -> float:
        total = self.cuts + self.remaining
        return round(self.cuts / total, 4) if total else 0.0


@dataclass(frozen=True)
class Cut:
    """讓某個 Crown Jewel 完全不可達所需的最小可處置集合。"""

    jewel: str
    assets: tuple[str, ...] = ()
    found: bool = True
    note: str = ""


@dataclass
class ChokeReport:
    total_paths: int
    chokes: tuple[Choke, ...] = ()
    cuts: tuple[Cut, ...] = ()
    universal: tuple[str, ...] = ()  # 出現在每一個最小切割裡的節點
    full_cut: tuple[str, ...] | None = None
    exhaustive: bool = True
    jewels: tuple[str, ...] = field(default_factory=tuple)

    @property
    def by_frequency(self) -> tuple[Choke, ...]:
        return tuple(sorted(self.chokes, key=lambda c: (-c.on_paths, c.asset)))

    @property
    def by_cuts(self) -> tuple[Choke, ...]:
        return tuple(sorted(self.chokes, key=lambda c: (-c.cuts, c.asset)))

    @property
    def rankings_agree(self) -> bool:
        """兩種排法的第一名是不是同一台。不一致才是今天要講的事。"""
        return bool(self.chokes) and self.by_frequency[0].asset == self.by_cuts[0].asset


def _paths_to(graph: AttackGraph, jewels: list[str]) -> dict[str, list[Path]]:
    return {jewel: find_paths(graph, jewel) for jewel in jewels}


def _surviving(paths: dict[str, list[Path]], removed: frozenset[str]) -> dict[str, list[Path]]:
    """移除這些節點之後，每個 Crown Jewel 還剩哪些路徑。

    從已枚舉的路徑裡篩，而不是重跑搜尋——兩者等價（移除節點只會讓路徑消失，
    不會生出新的簡單路徑），但篩一次比重跑 255 次快得多。
    `find_paths(without=...)` 是同一件事的引擎版，`test_choke.py` 驗證兩者一致。
    """
    out: dict[str, list[Path]] = {}
    for jewel, found in paths.items():
        if jewel in removed:
            out[jewel] = []
            continue
        out[jewel] = [p for p in found if not (set(p.assets[:-1]) & removed)]
    return out


def _count(surviving: dict[str, list[Path]]) -> int:
    return sum(len(v) for v in surviving.values())


def analyse(graph: AttackGraph, protect: frozenset[str] | None = None) -> ChokeReport:
    """量每個中間節點的出現頻率與反事實切斷數。

    `protect` 是不可處置的節點（預設：全部 Crown Jewel）。它們仍然列出來，
    因為「它切得最多」是一件該知道的事；但標為不可處置，不進最小切割的候選。
    """
    jewels = [node.id for node in graph.crown_jewels]
    paths = _paths_to(graph, jewels)
    total = _count(paths)
    protect = protect if protect is not None else frozenset(jewels)

    intermediates: dict[str, int] = {}
    for found in paths.values():
        for path in found:
            for asset in set(path.assets[1:-1]):
                intermediates[asset] = intermediates.get(asset, 0) + 1

    chokes = []
    for asset, on_paths in intermediates.items():
        surviving = _surviving(paths, frozenset({asset}))
        remaining = _count(surviving)
        dead = tuple(sorted(j for j, v in surviving.items() if not v))
        actionable = asset not in protect
        note = "" if actionable else "Crown Jewel，不可處置——「移除它」不是做得到的處置"
        chokes.append(Choke(asset, on_paths, total - remaining, remaining,
                            jewels_cut=dead, actionable=actionable, note=note))

    actionable = sorted(a for a in intermediates if a not in protect)
    cuts, exhaustive = _minimum_cuts(paths, jewels, actionable)
    universal = tuple(sorted(
        set.intersection(*[set(c.assets) for c in cuts if c.found])
    )) if cuts and all(c.found for c in cuts) else ()
    full = _full_cut(paths, actionable) if exhaustive else None

    return ChokeReport(total_paths=total, chokes=tuple(chokes), cuts=tuple(cuts),
                       universal=universal, full_cut=full, exhaustive=exhaustive,
                       jewels=tuple(jewels))


def _minimum_cuts(paths: dict[str, list[Path]], jewels: list[str],
                  actionable: list[str]) -> tuple[list[Cut], bool]:
    if len(actionable) > MAX_EXHAUSTIVE:
        return ([Cut(j, found=False, note=f"可處置節點 {len(actionable)} 個，"
                     f"超過窮舉上限 {MAX_EXHAUSTIVE}") for j in jewels], False)
    cuts = []
    for jewel in jewels:
        smallest: tuple[str, ...] | None = None
        for size in range(1, len(actionable) + 1):
            for combo in itertools.combinations(actionable, size):
                if not _surviving(paths, frozenset(combo))[jewel]:
                    smallest = combo
                    break
            if smallest is not None:
                break
        if smallest is None:
            cuts.append(Cut(jewel, found=False,
                            note="任何可處置組合都切不斷——它的入口不在可處置清單上"))
        else:
            cuts.append(Cut(jewel, assets=smallest))
    return cuts, True


def _full_cut(paths: dict[str, list[Path]], actionable: list[str]) -> tuple[str, ...] | None:
    """同時切斷全部 Crown Jewel 的最小可處置集合。"""
    for size in range(1, len(actionable) + 1):
        for combo in itertools.combinations(actionable, size):
            if _count(_surviving(paths, frozenset(combo))) == 0:
                return combo
    return None


def combined_cut(graph: AttackGraph, assets: list[str]) -> int:
    """同時移除這幾台之後，總共切掉幾條路徑。

    存在的理由就是**切斷數不可相加**：兩台各切 15，一起修不保證切 30。
    要知道組合的效果，只能重算，不能加。
    """
    jewels = [node.id for node in graph.crown_jewels]
    paths = _paths_to(graph, jewels)
    return _count(paths) - _count(_surviving(paths, frozenset(assets)))


def render(report: ChokeReport) -> str:
    """把分析排成人讀的樣子。兩種排法並列——不一致本身就是結論。"""
    lines = [f"通往 {len(report.jewels)} 個 Crown Jewel 共 {report.total_paths} 條路徑", ""]
    lines.append(f"  {'節點':<22}{'出現':>6}{'切斷':>6}{'佔比':>7}  備註")
    for choke in report.by_cuts:
        flag = "" if choke.actionable else "  ⚠ "
        note = choke.note or (f"切斷後 {'、'.join(choke.jewels_cut)} 完全不可達"
                              if choke.jewels_cut else "")
        lines.append(f"  {choke.asset:<22}{choke.on_paths:>6}{choke.cuts:>6}"
                     f"{choke.share * 100:>6.0f}%{flag}{note}")

    lines.append("")
    if report.rankings_agree:
        lines.append("出現最多次的與切得最多的是同一台。")
    else:
        freq, cut = report.by_frequency[0], report.by_cuts[0]
        lines.append(f"出現最多次的是 {freq.asset}（{freq.on_paths} 條），"
                     f"切得最多的是 {cut.asset}（切 {cut.cuts} 條、只出現在 "
                     f"{cut.on_paths} 條上）。**頻率不是切斷力。**")

    lines.append("")
    if not report.exhaustive:
        lines.append(f"最小切割：可處置節點超過 {MAX_EXHAUSTIVE} 個，沒有窮舉。"
                     "這是算不出來，不是沒有瓶頸。")
        return "\n".join(lines)

    lines.append("讓各 Crown Jewel 完全不可達所需的最小可處置集合：")
    for cut in report.cuts:
        if cut.found:
            lines.append(f"  {cut.jewel:<22}{len(cut.assets)} 台：{'、'.join(cut.assets)}")
        else:
            lines.append(f"  {cut.jewel:<22}{cut.note}")
    singles = [c for c in report.cuts if c.found and len(c.assets) == 1]
    if not singles:
        lines.append("  **沒有任何單一可處置節點能切斷任何一個 Crown Jewel。**")
    if report.universal:
        lines.append(f"  每一個切割集合都少不了：{'、'.join(report.universal)}"
                     "——這才是共同瓶頸。")
    if report.full_cut:
        lines.append(f"  全部一起斷掉需要 {len(report.full_cut)} 台："
                     f"{'、'.join(report.full_cut)}")
    return "\n".join(lines)
