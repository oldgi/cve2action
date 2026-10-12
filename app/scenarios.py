"""四個必測情境（藍圖 §8.4，Day 29）：模型真的比 CVSS 排序好嗎？

## 規則先於結果

每個情境寫成一條**查詢規則**，逐字對應 §8.4 的描述，資料裡符合規則的每一筆都要評，
不挑「剛好會過」的那一筆。規則與判準寫在這裡，結果由資料決定。

- **情境一｜高 CVSS、低環境風險**：CVSS ≥ 9 且查無從 Internet 出發的路徑。
  判準：每一筆都落在本專案排序的後四分之一。
- **情境二｜中高 CVSS、極高優先度**：8 ≤ CVSS < 9、KEV、Internet 可達、能通往核心資料庫。
  判準：本專案排名前四分之一。
- **情境三｜控制降低剩餘風險**：同一 CVE、同區域同角色，一台有驗證過的控制、一台沒有。
  判準：有控制的那台排在後面。
- **情境四｜一次措施切斷多條路徑**：關閉一條連線或隔離一台。
  判準：切掉 ≥ 2 條通往 Crown Jewel 的路徑。

判定三態：`PASS`／`PARTIAL`（方向對但沒到判準）／`FAIL`。沒有符合規則的 finding 是
`NO_CASE`——**不是 PASS**，資料裡沒有這種情況就是沒驗證到。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from itertools import combinations

import yaml

from cve2action.attack_graph.paths import find_paths
from cve2action.remediation import roi

PASS, PARTIAL, FAIL, NO_CASE = "PASS", "PARTIAL", "FAIL", "NO_CASE"
CORE_DATABASES = ("customer_database", "billing_database")


@dataclass
class Scenario:
    number: int
    title: str
    rule: str
    criterion: str
    verdict: str = NO_CASE
    cases: list[dict] = field(default_factory=list)
    finding: str = ""      # 一句話：量到什麼
    caveat: str = ""       # 一句話：為什麼不能說得更滿


def _assets(p) -> dict[str, dict]:
    from data import DATA, _read_rows  # 與儀表板同一份資料
    return {a["asset_id"]: a for a in _read_rows(str(DATA / "assets.csv"))}


def scenario_one(p, rows) -> Scenario:
    s = Scenario(1, "高 CVSS、低環境風險", "CVSS ≥ 9 且查無從 Internet 出發的路徑",
                 "每一筆都落在本專案排序的後四分之一")
    n = len(rows)
    cut = math.ceil(n * 0.75)
    for r in rows:
        if r["cvss"] >= 9 and not find_paths(p.graph, r["asset"]):
            s.cases.append({**r, "ok": r["rank"] > cut})
    if s.cases:
        s.verdict = PASS if all(c["ok"] for c in s.cases) else (
            PARTIAL if any(c["ok"] for c in s.cases) else FAIL)
        ranks = sorted(c["rank"] for c in s.cases)
        s.finding = (f"{len(s.cases)} 筆符合，CVSS 名次是並列第 "
                     f"{'／'.join(sorted({str(c['cvss_rank']) for c in s.cases}))}，"
                     f"本專案落在 #{ranks[0]}–#{ranks[-1]}（後四分之一從 #{cut + 1} 起）")
        s.caveat = "查無路徑不是證明不可達（Day 22）；它們沒有消失，只是排在後面。"
    return s


def scenario_two(p, rows) -> Scenario:
    s = Scenario(2, "中高 CVSS、極高優先度",
                 "8 ≤ CVSS < 9、KEV 收錄、Internet 可達、能通往核心資料庫",
                 "本專案排名前四分之一")
    assets = _assets(p)
    databases = [a for a, row in assets.items() if row["business_role"] in CORE_DATABASES]
    top = math.floor(len(rows) * 0.25)
    for r in rows:
        if not (8 <= r["cvss"] < 9 and r["kev"]):
            continue
        if not find_paths(p.graph, r["asset"]):
            continue
        reaches = [d for d in databases
                   if d == r["asset"] or find_paths(p.graph, d, source=r["asset"])]
        if reaches:
            s.cases.append({**r, "reaches": reaches, "ok": r["rank"] <= top})
    if s.cases:
        if all(c["ok"] for c in s.cases):
            s.verdict = PASS
        elif any(c["rank"] < c["cvss_rank"] for c in s.cases):
            s.verdict = PARTIAL
        else:
            s.verdict = FAIL
        c = s.cases[0]
        s.finding = (f"{len(s.cases)} 筆符合：{c['asset']} {c['cve']}，CVSS 並列第 "
                     f"{c['cvss_rank']} → 本專案 #{c['rank']}，層級 {c['tier_before']}→{c['tier']}"
                     f"（前四分之一是 #1–#{top}）")
        s.caveat = ("往前移了，但沒到頂端。升到 P0 靠的是 §9.6 覆寫，而覆寫後 24/40 都是 P0——"
                    "在這份資料上 P0 不構成「極高」。分數上輸在 S（8.8 對 9.8）與 E（DATA 區不面對 "
                    "Internet），而 B 與 T 在頂端沒有鑑別力（全是 CRITICAL、全在 KEV），補不回來。")
    return s


def scenario_three(p, rows) -> Scenario:
    s = Scenario(3, "控制降低剩餘風險", "同一 CVE、同區域同角色；一台有驗證過的控制、一台沒有",
                 "有控制的那台排在後面")
    assets = _assets(p)
    by_key = {(r["asset"], r["cve"]): r for r in rows}
    control = {(e.asset, e.cve): e.factor("exposure").inputs.get("control") for e in p.scored}
    for (a1, cve), r1 in by_key.items():
        for (a2, cve2), r2 in by_key.items():
            if cve != cve2 or a1 >= a2:
                continue
            x, y = assets[a1], assets[a2]
            if (x["zone"], x["business_role"]) != (y["zone"], y["business_role"]):
                continue
            c1, c2 = control[(a1, cve)], control[(a2, cve)]
            if (c1 in ("STRONG", "PARTIAL")) == (c2 in ("STRONG", "PARTIAL")):
                continue
            guarded, open_ = (r1, r2) if c1 in ("STRONG", "PARTIAL") else (r2, r1)
            s.cases.append({"cve": cve, "guarded": guarded["asset"], "open": open_["asset"],
                            "guarded_rank": guarded["rank"], "open_rank": open_["rank"],
                            "control": c1 if guarded is r1 else c2,
                            "ok": guarded["rank"] > open_["rank"]})
    if s.cases:
        s.verdict = PASS if all(c["ok"] for c in s.cases) else FAIL
        s.finding = "；".join(f"{c['cve']}：有 WAF（{c['control']}）#{c['guarded_rank']}、"
                             f"沒有 #{c['open_rank']}" for c in s.cases)
        s.caveat = ("反方向也成立：內網應用的 EDR 證據過期 117 天 → UNKNOWN，不折減（Day 12）。"
                    "控制要有驗證日期才算數。")
    return s


def scenario_four(p, rows) -> Scenario:
    s = Scenario(4, "一次措施切斷多條路徑", "關閉一條連線，或隔離一台",
                 "切掉 ≥ 2 條通往 Crown Jewel 的路徑")
    total = p.roi.paths_total
    best = None
    for node in sorted(n.id for n in p.graph.nodes.values() if n.attrs.get("asset")
                       and n.kind == "service"):
        after = roi.jewel_paths(roi.without_service(p.graph, node))
        if after < total and (best is None or after < best[1]):
            best = (node, after)
    if best:
        s.cases.append({"measure": f"關閉 {best[0]} 的連線", "paths": f"{total} → {best[1]}",
                        "registered": False, "ok": total - best[1] >= 2})
    for o in p.roi.outcomes:
        if o.paths_cut:
            s.cases.append({"measure": f"{o.candidate.remediation_id} "
                                       f"{o.candidate.action} {o.candidate.asset}",
                            "paths": f"{total} → {o.paths_after}", "registered": True,
                            "ok": o.paths_cut >= 2})
    if s.cases:
        s.verdict = PASS if any(c["ok"] for c in s.cases) else FAIL
        c = s.cases[0]
        s.finding = (f"單一連線切最多的是 {c['measure']}：{c['paths']}；"
                     f"清冊裡登記過的措施最多切 "
                     f"{max((o.paths_cut for o in p.roi.outcomes), default=0)} 條")
        s.caveat = ("模型做得到，清冊沒登記。藍圖原文「修補跳板」在這個圖模型裡切 0 條——"
                    "圖不看漏洞（ADR-day-27）。")
    return s


def run_all(p) -> list[Scenario]:
    from data import ranking_rows
    rows = ranking_rows(p)
    return [scenario_one(p, rows), scenario_two(p, rows), scenario_three(p, rows),
            scenario_four(p, rows)]


# --- 對照人工排序：模型 vs CVSS（Day 17 的基準） ---------------------------------

def tau_b(expert: list[int], other: list[float]) -> tuple[float, int, int, int]:
    """Kendall tau-b。`expert` 是人排的名次（小＝先），`other` 是分數（大＝先）。

    回傳 (tau-b, 一致, 分歧, other 的平手數)。平手照 tau-b 的定義進分母修正，
    不是丟掉——CVSS 同分很常見，丟掉平手會讓 CVSS 看起來比實際更有主見。
    """
    concordant = discordant = ties = 0
    for i, j in combinations(range(len(expert)), 2):
        a = expert[i] - expert[j]          # 負：i 在人眼中較先
        b = other[j] - other[i]            # 負：i 在 other 中較先（分數較高）
        if b == 0:
            ties += 1
        elif (a < 0) == (b < 0):
            concordant += 1
        else:
            discordant += 1
    n0 = len(expert) * (len(expert) - 1) // 2
    denominator = math.sqrt(n0 * (n0 - ties))
    return (round((concordant - discordant) / denominator, 4) if denominator else 0.0,
            concordant, discordant, ties)


def versus_expert(p, baseline_path) -> dict:
    with open(baseline_path, encoding="utf-8") as stream:
        baseline = yaml.safe_load(stream)
    scored = {(e.asset, e.cve): e for e in p.scored}
    expert, model, cvss = [], [], []
    for entry in baseline["findings"]:
        e = scored[(entry["asset"], entry["cve"])]
        expert.append(int(entry["rank"]))
        model.append(e.score)
        cvss.append(float(e.factor("severity").inputs["cvss"]))
    return {"n": len(expert), "model": tau_b(expert, model), "cvss": tau_b(expert, cvss),
            "ranked_by": baseline.get("ranked_by", "")}


# --- 差異逐筆說明（藍圖 §10 Day 29、成功標準 #5） -------------------------------

LABELS = {"threat": "T 威脅", "exposure": "E 曝險", "business": "B 業務", "path": "A 路徑"}


def why_moved(p) -> list[dict]:
    """每一筆：CVSS 名次與本專案名次差多少，主要是哪一項造成的。

    CVSS 只看 S。名次會偏離 CVSS，一定是其他四項之一偏離了全體的中位數。
    取「方向與移動一致、偏離最大」的那一項當主因——它是算出來的，不是寫上去的。
    """
    from statistics import median

    from data import ranking_rows

    rows = {(r["asset"], r["cve"]): r for r in ranking_rows(p)}
    medians = {key: median(f.contribution for e in p.scored for f in e.factors if f.key == key)
               for key in LABELS}
    out = []
    for e in p.scored:
        r = rows[(e.asset, e.cve)]
        deltas = {f.key: round(f.contribution - medians[f.key], 2)
                  for f in e.factors if f.key in LABELS}
        sign = 1 if r["move"] > 0 else -1
        aligned = {k: v for k, v in deltas.items() if v * sign > 0}
        if r["move"] == 0 or not aligned:
            if r["move"] == 0:
                reason = "與 CVSS 一致"
            elif r["move"] < 0:
                reason = "沒有一項低於中位數：是別筆往前擠，不是它往後退"
            else:
                reason = "沒有一項高於中位數：是別筆往後退，不是它往前衝"
        else:
            key = max(aligned, key=lambda k: abs(aligned[k]))
            detail = next(f for f in e.factors if f.key == key)
            reason = f"{LABELS[key]} {aligned[key]:+.2f}（{detail.source}）"
        out.append({"rank": r["rank"], "cvss_rank": r["cvss_rank"], "move": r["move"],
                    "asset": e.asset, "cve": e.cve, "cvss": r["cvss"], "score": e.score,
                    "reason": reason})
    return out
