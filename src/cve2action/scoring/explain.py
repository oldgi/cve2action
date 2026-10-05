"""Explain：一筆分數的結構化說明。

到 Day 15 為止，理由只存在於一個 `reason` 字串裡。那個字串是計分之後**另外拼**出來的，
於是它有兩個毛病：

1. **它會跟計算漂開。** 改公式要記得同步改字串，沒有任何機制強迫你記得——
   這正是規格文件凍結在 Day 6 的同一種失敗。
2. **它只回答「怎麼算的」，不回答「為什麼排在這裡」。** 排序是比較出來的，
   單看一列的算式永遠答不了「為什麼它在第三名而不是第二名」。

所以今天把順序倒過來：**先產生 Explanation，CSV 的列與人讀的理由都是它的投影。**
這和 Day 7 對快照的處理是同一條紀律——`raw` 是唯一事實，`extracted` 是可重新導出的投影。
字串不可能再跟數字不一致，因為字串是從數字長出來的。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import ADDITIVE, GEOMETRIC, GEOMETRIC_FLOOR

# 符號與顯示順序；與開發規格 §3.1 的公式同序。A 是藍圖 §9.3 的攻擊路徑分數（Day 23）
SYMBOLS = {"severity": "S", "threat": "T", "exposure": "E", "business": "B", "path": "A"}
ORDER = ("severity", "threat", "exposure", "business", "path")


@dataclass(frozen=True)
class Factor:
    """公式裡的一項：它的值、權重、貢獻，以及這個值憑什麼是這個值。"""

    key: str
    value: float
    weight: float
    inputs: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    detail: str = ""

    @property
    def symbol(self) -> str:
        # 查不到就退回首字母大寫。多一個因子不該讓整個 CLI 掛掉——Day 23 加 path
        # 的時候就是這樣掛的，而那是顯示用的查表，不是計算。
        return SYMBOLS.get(self.key, self.key[:1].upper())

    @property
    def contribution(self) -> float:
        """這一項貢獻了幾分（滿分 10）。

        **這個定義只在加權相加的形式下成立。** 幾何平均沒有逐項貢獻可言——
        見 `Explanation.additive` 與 ADR-day-23。
        """
        return round(10.0 * self.weight * self.value, 2)

    def share_of(self, score: float) -> float:
        """佔總分的比例；總分為 0 時回 0，不製造除以零的假精確。"""
        return round(self.contribution / score, 4) if score else 0.0


@dataclass(frozen=True)
class Explanation:
    """一筆 finding 的完整說明。CSV 列與 reason 字串都由它產生。"""

    asset: str
    cve: str
    decision: str
    factors: tuple[Factor, ...] = ()
    score: float | None = None
    band: str = ""
    # 對外的處置層級與建議動作（Day 18）；內部計算一律用 band
    tier: str = ""
    action: str = ""
    gaps: tuple[str, ...] = ()
    # 威脅項缺席、權重退回 severity 時為 True（開發規格 §3.2）
    degraded: bool = False
    # 產生這個分數的合成形式（Day 23）：additive 或 geometric
    form: str = ADDITIVE
    # 重建 reason 字串與輸出列所需、但不屬於任何因子的欄位
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def scored(self) -> bool:
        return self.score is not None

    @property
    def additive(self) -> bool:
        """分數是不是各項貢獻的和。

        只有加權相加的形式答 True。這件事決定了三個投影能不能用：
        `formula` 的算式形狀、`Factor.contribution` 的「貢獻幾分」、
        以及 `gap_to` 的逐項差額——三者都預設「總分 = 各項之和」。
        """
        return self.form != GEOMETRIC

    def factor(self, key: str) -> Factor | None:
        return next((f for f in self.factors if f.key == key), None)

    @property
    def formula(self) -> str:
        """代入數值後的算式，例如 10 × (0.35×1 + 0.15×1 + 0.25×0.6 + 0.25×1) = 9.0。

        算式的**形狀**跟著 `form` 走。Day 16 把理由做成計算的投影，就是為了讓字串
        不可能跟數字不一致；Day 23 加了第二種形式，這裡若還硬寫加號，
        就等於把那條紀律自己打破一次。
        """
        if not self.scored:
            return ""
        if self.additive:
            terms = " + ".join(f"{f.weight:g}×{f.value:g}" for f in self.factors)
            return f"10 × ({terms}) = {self.score:g}"
        terms = " × ".join(
            f"max({f.value:g},{GEOMETRIC_FLOOR:g})^{f.weight:g}" for f in self.factors)
        return f"10 × {terms} = {self.score:g}"

    def gap_to(self, other: Explanation) -> list[tuple[str, float]]:
        """與另一筆的逐項分數差，依絕對值由大到小——回答「為什麼它排在我前面」。

        只比較兩邊都有的因子；一邊有威脅項另一邊沒有時，缺席的那邊以 0 貢獻計入，
        差額才加得起來。
        """
        if not (self.additive and other.additive):
            # 幾何平均的總分差不等於逐項貢獻差之和，報出來的數字會加不回去。
            return []
        keys = {f.key for f in self.factors} | {f.key for f in other.factors}
        deltas = []
        for key in ORDER:
            if key not in keys:
                continue
            mine = self.factor(key)
            theirs = other.factor(key)
            deltas.append((key, round((mine.contribution if mine else 0.0)
                                      - (theirs.contribution if theirs else 0.0), 2)))
        deltas.sort(key=lambda item: abs(item[1]), reverse=True)
        return deltas

    def to_dict(self) -> dict[str, Any]:
        """給機器讀的形狀；CLI 的 --json 與未來的 API 都用這個。"""
        return {
            "asset": self.asset,
            "cve": self.cve,
            "decision": self.decision,
            "score": self.score,
            "band": self.band,
            "tier": self.tier,
            "action": self.action,
            "formula": self.formula,
            "form": self.form,
            "degraded": self.degraded,
            "gaps": list(self.gaps),
            "factors": [
                {
                    "key": f.key,
                    "symbol": f.symbol,
                    "value": f.value,
                    "weight": f.weight,
                    "contribution": f.contribution if self.additive else None,
                    "share": f.share_of(self.score or 0.0) if self.additive else None,
                    "inputs": f.inputs,
                    "source": f.source,
                }
                for f in self.factors
            ],
        }

    def to_reason(self) -> str:
        """單行理由，寫進 ranked_result.csv 的 reason 欄。"""
        if not self.scored:
            return "needs context: " + "; ".join(self.gaps)
        severity = self.factor("severity")
        threat = self.factor("threat")
        exposure = self.factor("exposure")
        business = self.factor("business")
        threat_text = (f"T={threat.value:g} [{threat.source}]; " if threat is not None
                       else "T=n/a [no threat data, weight redistributed]; ")
        path = self.factor("path")
        path_text = f"A={path.value:g} [{path.source}]; " if path is not None else ""
        return (
            f"CVSS {severity.inputs['cvss']:g} [{severity.detail}] (S={severity.value:g}); "
            + threat_text
            + f"{exposure.inputs['reachability']} x {exposure.inputs['control']}"
            + f"{self.extras.get('control_note', '')} -> E={exposure.value:g}; "
            + f"{business.inputs['criticality']} -> B={business.value:g}; "
            + path_text
            + f"score={self.score:g} [{self.band}]"
        )


def explain_row(explanation: Explanation, above: Explanation | None = None) -> str:
    """把 Explanation 排成人讀的多行說明；給了 `above` 就一併解釋與前一名的差距。"""
    lines = [f"{explanation.asset}  {explanation.cve}"]
    if not explanation.scored:
        lines.append(f"  decision : {explanation.decision}")
        for gap in explanation.gaps:
            lines.append(f"    - {gap}")
        lines.append("  未評分不是漏掉，是拒絕在缺資料時猜一個分數。")
        return "\n".join(lines)

    tier = f"  {explanation.tier} {explanation.action}" if explanation.tier else ""
    lines.append(f"  score    : {explanation.score:g}  [{explanation.band}]{tier}")
    lines.append(f"  formula  : {explanation.formula}")
    if explanation.degraded:
        lines.append("             （無威脅資料：該項移除，權重退回 severity）")
    lines.append("")
    third = "貢獻" if explanation.additive else "指數"
    lines.append(f"  {'因子':<10} {'值':>6} {'權重':>6} {third:>6} {'佔比':>6}  來源")
    for factor in explanation.factors:
        if explanation.additive:
            amount = f"{factor.contribution:>6.2f}"
            share = f"{factor.share_of(explanation.score) * 100:.0f}%"
        else:
            # 幾何平均沒有「這一項貢獻幾分」；留白比填一個加不回總分的數字誠實。
            amount = f"{factor.weight:>6.2f}"
            share = "   n/a"
        lines.append(
            f"  {factor.symbol} {factor.key:<8} {factor.value:>6.3g} {factor.weight:>6.2f} "
            f"{amount} {share:>6}  {factor.source}"
        )
    if not explanation.additive:
        lines.append("  （幾何平均：總分不是各項之和，所以沒有逐項貢獻可報）")

    if above is not None and above.scored:
        lines.append("")
        deltas = explanation.gap_to(above)
        if not deltas:
            lines.append(f"  與前一名（{above.cve} on {above.asset}，{above.score:g}）"
                         f"差 {round(explanation.score - above.score, 2):+g} 分；"
                         f"幾何平均無法逐項歸因。")
            return "\n".join(lines)
        total = round(sum(d for _k, d in deltas), 2)
        moved = [(k, d) for k, d in deltas if d != 0]
        header = f"  與前一名（{above.cve} on {above.asset}，{above.score:g}）"
        if not moved:
            lines.append(header + "逐項完全相同——同分不是湊巧，是四個因子都一樣。")
        else:
            lines.append(header + f"差 {total:g} 分：")
            for key, delta in moved:
                lines.append(f"    {SYMBOLS[key]} {key:<9} {delta:+.2f}")
            if total == 0:
                lines.append("  總分相同，但組成不同——上下之差只是排序的先後。")
            else:
                # 最大的「變動項」未必是造成輸贏的那一項：它可能是這一筆贏過對方的地方。
                # 落後就看最大的負項，領先就看最大的正項，不能只報絕對值最大的。
                sign = -1 if total < 0 else 1
                driver = next((k for k, d in moved if d * sign > 0), moved[0][0])
                verb = "被壓在下面" if total < 0 else "排在前面"
                lines.append(f"  讓它{verb}的是 {SYMBOLS[driver]}（{driver}）。")
                helper = next((k for k, d in moved if d * sign < 0), None)
                if helper:
                    lines.append(f"  {SYMBOLS[helper]}（{helper}）反而是它佔優的一項"
                                 f"——總分看不出這件事。")
    return "\n".join(lines)
