"""校準測試：把人工排序與模型排序擺在一起，並強制每個分歧都要有書面解釋。

重點不是「相關係數多高」。相關係數高只代表模型複製了排序者的直覺，而排序者可能
本來就錯。真正有價值的產出是**分歧清單**——每一對順序不一致的地方，都必須寫下
是誰對、為什麼，以及接下來要改什麼。

所以這個模組的驗收條件不是 tau 要大於某個數，而是：**沒有未解釋的分歧**。
有分歧而沒寫解釋，`has_unexplained` 為真，測試就紅。

方法上的先決條件在資料檔裡，不在這裡：人工排序必須在看到模型分數之前定稿並
commit。程式無法強制這件事，只能靠 git 的時間戳留證。
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml

# verdict 的三種結論，對應三種完全不同的後續動作
VERDICT_MODEL = "model"    # 模型對：排序者的直覺要修正
VERDICT_EXPERT = "expert"  # 排序者對：模型要改，必須有 ADR
VERDICT_DATA = "data"      # 兩邊都沒錯，是輸入資料不對：去修資料，不要動權重
VERDICTS = (VERDICT_MODEL, VERDICT_EXPERT, VERDICT_DATA)


class CalibrationError(ValueError):
    """校準基準檔內容不符合規格。"""


def key_of(asset: str, cve: str) -> str:
    return f"{asset}/{cve}"


@dataclass(frozen=True)
class Item:
    asset: str
    cve: str
    label: str
    expert_rank: int
    model_rank: int | None = None
    model_score: float | None = None
    band: str = ""

    @property
    def key(self) -> str:
        return key_of(self.asset, self.cve)


@dataclass(frozen=True)
class Disagreement:
    """一對順序相反的 finding，以及（如果有的話）它的書面解釋。"""

    higher_for_expert: Item
    higher_for_model: Item
    verdict: str = ""
    explanation: str = ""
    follow_up: str = ""

    @property
    def explained(self) -> bool:
        return bool(self.verdict) and bool(self.explanation.strip())


@dataclass(frozen=True)
class Calibration:
    items: tuple[Item, ...]
    disagreements: tuple[Disagreement, ...]
    concordant: int
    discordant: int

    @property
    def pairs(self) -> int:
        return self.concordant + self.discordant

    @property
    def tau(self) -> float:
        """Kendall tau-b；模型分數相同造成的平手計為既不一致也不不一致。"""
        return round((self.concordant - self.discordant) / self.pairs, 4) if self.pairs else 0.0

    @property
    def agreement(self) -> float:
        return round(self.concordant / self.pairs, 4) if self.pairs else 0.0

    @property
    def unexplained(self) -> tuple[Disagreement, ...]:
        return tuple(d for d in self.disagreements if not d.explained)

    @property
    def has_unexplained(self) -> bool:
        return bool(self.unexplained)


def load_baseline(path: str | Path) -> dict[str, Any]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
        raise CalibrationError(f"{path}: missing 'findings' list")
    ranks = [f.get("rank") for f in raw["findings"]]
    if sorted(ranks) != list(range(1, len(ranks) + 1)):
        raise CalibrationError(f"{path}: ranks must be 1..N with no gaps or ties, got {ranks}")
    for entry in raw["findings"]:
        if not str(entry.get("rationale", "")).strip():
            raise CalibrationError(
                f"{path}: {entry.get('asset')}/{entry.get('cve')} has no rationale——"
                "排序沒有寫理由就不是基準，只是一個順序"
            )
    return raw


def _resolution_index(raw: dict[str, Any]) -> dict[frozenset[str], dict[str, Any]]:
    index: dict[frozenset[str], dict[str, Any]] = {}
    for entry in raw.get("resolutions") or []:
        pair = entry.get("pair")
        if not isinstance(pair, list) or len(pair) != 2:
            raise CalibrationError("resolutions[].pair 必須是兩個 'ASSET/CVE' 字串")
        verdict = entry.get("verdict")
        if verdict not in VERDICTS:
            raise CalibrationError(
                f"resolutions[].verdict 必須是 {list(VERDICTS)} 之一，得到 {verdict!r}")
        index[frozenset(str(p) for p in pair)] = entry
    return index


def compare(baseline: dict[str, Any], ranked_rows: list[dict[str, Any]]) -> Calibration:
    """把基準檔與 `rank()` 的輸出對起來。

    `ranked_rows` 是完整的排序結果；只有出現在基準檔裡的那幾筆會參與比較，
    但名次取自全場，這樣「第 11 名 vs 第 18 名」這種資訊不會被壓縮掉。
    """
    position = {key_of(str(r["asset"]), str(r["cve"])): index
                for index, r in enumerate(ranked_rows, start=1)}
    by_key = {key_of(str(r["asset"]), str(r["cve"])): r for r in ranked_rows}

    items: list[Item] = []
    for entry in baseline["findings"]:
        key = key_of(str(entry["asset"]), str(entry["cve"]))
        row = by_key.get(key)
        if row is None:
            raise CalibrationError(f"{key} 在基準檔裡，但不在模型輸出中")
        score = row["priority_score"]
        items.append(Item(
            asset=str(entry["asset"]), cve=str(entry["cve"]),
            label=str(entry.get("label", "")), expert_rank=int(entry["rank"]),
            model_rank=position[key],
            model_score=float(score) if score not in ("", None) else None,
            band=str(row.get("priority", "")),
        ))
    items.sort(key=lambda i: i.expert_rank)

    resolutions = _resolution_index(baseline)
    disagreements: list[Disagreement] = []
    concordant = discordant = 0
    for first, second in combinations(items, 2):
        # items 依人工排序，所以 first 永遠是人認為該先處理的那一筆
        if first.model_score is None or second.model_score is None:
            continue
        if first.model_score == second.model_score:
            continue  # 平手：模型沒有表態，不算一致也不算分歧
        if first.model_rank < second.model_rank:
            concordant += 1
            continue
        discordant += 1
        entry = resolutions.get(frozenset({first.key, second.key}), {})
        disagreements.append(Disagreement(
            higher_for_expert=first, higher_for_model=second,
            verdict=str(entry.get("verdict", "")),
            explanation=str(entry.get("explanation", "")),
            follow_up=str(entry.get("follow_up", "")),
        ))
    return Calibration(tuple(items), tuple(disagreements), concordant, discordant)


def report(calibration: Calibration) -> str:
    lines = [f"{'人工':>4} {'模型':>4} {'全場':>5} {'分數':>6} {'級別':<9} finding"]
    for item in calibration.items:
        score = f"{item.model_score:g}" if item.model_score is not None else "-"
        model_order = sorted(calibration.items,
                             key=lambda i: (i.model_score is None, -(i.model_score or 0)))
        lines.append(
            f"{item.expert_rank:>4} {model_order.index(item) + 1:>4} {item.model_rank:>5} "
            f"{score:>6} {item.band:<9} {item.key}  {item.label}"
        )
    lines.append("")
    lines.append(f"成對比較 {calibration.pairs} 組：一致 {calibration.concordant}、"
                 f"分歧 {calibration.discordant}；Kendall tau-b = {calibration.tau:g}")

    if not calibration.disagreements:
        lines.append("沒有分歧。這不代表模型是對的，只代表它複製了排序者的判斷。")
        return "\n".join(lines)

    lines.append("")
    lines.append("分歧：")
    for index, item in enumerate(calibration.disagreements, start=1):
        lines.append(f"  {index}. 人排 {item.higher_for_expert.key} 在前，"
                     f"模型排 {item.higher_for_model.key} 在前")
        if item.explained:
            verdict = {"model": "模型對", "expert": "人對", "data": "資料不對"}[item.verdict]
            lines.append(f"     結論：{verdict}")
            for line in item.explanation.strip().splitlines():
                lines.append(f"     {line.strip()}")
            if item.follow_up.strip():
                lines.append(f"     後續：{item.follow_up.strip()}")
        else:
            lines.append("     ** 沒有書面解釋 ** —— 分歧沒寫下來，校準就沒有做完")
    return "\n".join(lines)
