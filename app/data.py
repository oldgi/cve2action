#!/usr/bin/env python
"""儀表板的資料層（藍圖 §12 的 `app/`，Day 28）。

**畫面與資料分開。** 這個檔只把數字查出來，`app/dashboard.py` 才決定怎麼畫。
理由與 Day 16 的 `Explanation` 相同——呈現是投影，投影不該反過來決定資料長什麼樣。

## 與命令列同一條管線

`run()` 不自己組評分：它用 CLI 的同一組輸入、呼叫 CLI 的同一批函式
（`treat`／`candidates`／`roi` 背後那幾個）。**儀表板上的每個數字都必然等於
文章引用的命令列輸出**——不是「應該一樣」，是同一段程式算的。

```bash
uv run python app/data.py            # 四個視圖全跑，輸出 JSON
uv run python app/data.py --view cvss
```

## Day 24 之後驗證時發現的事（保留）

`--view ranking` 把前十名的因子貢獻攤開之後：**B（業務衝擊）十筆全是 2.0、
T（威脅）十筆全是 1.2**，兩個因子在頂端沒有鑑別力，拉開差距的是 E 與 A。
這是畫出來才看到的——看數字看不到。
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cve2action.attack_graph.choke import analyse  # noqa: E402
from cve2action.attack_graph.model import INTERNET_ID  # noqa: E402
from cve2action.attack_graph.paths import find_paths, render_path  # noqa: E402
from cve2action.cli import (  # noqa: E402
    _load_scoring_inputs,
    _plans,
    _read_rows,
    _scorer,
    _treatments,
    build_parser,
)
from cve2action.remediation import roi  # noqa: E402
from cve2action.scoring import explain_row, rank_explained  # noqa: E402

DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPSHOTS = ROOT / "data" / "snapshots"
AS_OF = "2026-09-24"

ACTION_LABEL = {"patch": "Patch", "isolate": "隔離", "disable_service": "關閉服務",
                "config_change": "改設定", "compensating_control": "補償控制"}


def argv(scanner: Path | None = None) -> list[str]:
    """與 CI、測試、文章相同的一組輸入。只有弱掃檔可以換（展示腳本第 1 步）。"""
    d = DATA
    return [
        "roi",
        "--scanner", str(scanner or d / "scanner.csv"),
        "--context", str(d / "asset_context.csv"),
        "--rules", str(ROOT / "config/risk_rules.yaml"),
        "--snapshots", str(SNAPSHOTS / "nvd"),
        "--epss", str(SNAPSHOTS / "epss"),
        "--kev", str(SNAPSHOTS / "kev"),
        "--controls", str(d / "controls.csv"),
        "--evidence", str(d / "version_evidence.csv"),
        "--acceptances", str(d / "risk_acceptances.csv"),
        "--remediations", str(d / "remediations.csv"),
        "--assets", str(d / "assets.csv"),
        "--interfaces", str(d / "asset_interfaces.csv"),
        "--services", str(d / "services.csv"),
        "--network", str(d / "network_edges.csv"),
        "--identity", str(d / "identity_edges.csv"),
        "--policies", str(d / "network_policies.csv"),
        # 建圖用的弱掃檔固定用 Northstar：換掉的是要排序的 findings，不是拓樸
        "--findings", str(d / "scanner.csv"),
        "--as-of", AS_OF,
    ]


@dataclass
class Pipeline:
    args: argparse.Namespace
    ranked: list           # Explanation，依本專案排序
    treatments: dict       # (asset, cve) → Treatment
    plans: dict            # (asset, cve) → Plan
    graph: object
    score: object          # 換一份圖重算分數的函式
    roi: object            # RoiReport
    chokes: object         # ChokeReport
    services: dict

    @property
    def scored(self) -> list:
        return [e for e in self.ranked if e.scored]


def run(scanner: Path | None = None) -> Pipeline:
    args = build_parser().parse_args(argv(scanner))
    ranked = rank_explained(*_load_scoring_inputs(args))
    treatments, code = _treatments(args)
    if treatments is None:
        raise RuntimeError(f"treat 失敗（exit {code}）")
    plans = _plans(args, treatments)
    graph, score = _scorer(args)
    services = {(r["asset"], r["cve"].upper()): r.get("service", "")
                for r in _read_rows(args.scanner)}
    report = roi.evaluate(graph, plans, score, services)
    key = lambda x: (x.asset, x.cve.upper())  # noqa: E731
    return Pipeline(args, ranked, {key(t): t for t in treatments},
                    {key(p): p for p in plans}, graph, score, report, analyse(graph),
                    services)


# --- 排名：CVSS 與本專案並陳（成功標準 #5） ------------------------------------

def ranking_rows(p: Pipeline) -> list[dict]:
    """一列一筆 finding。CVSS 排名與本專案排名同一列，差幾名直接算好。"""
    scored = p.scored
    # CVSS 同分就是並列：比它高的有幾筆、再加一。給同分的排出先後，等於替 CVSS
    # 編一個它沒有的判斷——六筆 10.0 在 CVSS 眼裡就是並列第一。
    values = [_cvss(e) for e in scored]
    cvss_rank = {(e.asset, e.cve): 1 + sum(v > _cvss(e) for v in values) for e in scored}
    out, previous = [], None
    for i, e in enumerate(scored, 1):
        t = p.treatments.get((e.asset, e.cve.upper()))
        plan = p.plans.get((e.asset, e.cve.upper()))
        threat = e.factor("threat")
        out.append({
            "rank": i,
            "cvss_rank": cvss_rank[(e.asset, e.cve)],
            "move": cvss_rank[(e.asset, e.cve)] - i,
            "asset": e.asset, "cve": e.cve,
            "cvss": _cvss(e), "score": e.score, "band": e.band,
            "tie_with_above": previous is not None and previous == e.score,
            "kev": bool(threat and threat.inputs.get("kev_listed")),
            "epss": threat.inputs.get("epss") if threat else None,
            # 已證明不必修的不進層級（Day 25）；顯示成「不必修」，不是空白
            "tier": ("不必修" if t.leaves_queue else t.tier) if t else e.tier,
            "tier_before": e.tier,
            "applicability": t.applicability if t else "",
            "review": bool(t and t.review_required),
            "first": _move(plan.first) if plan else "",
            "close": _move(plan.close) if plan else "",
            "options": len(plan.offered) if plan else 0,
        })
        previous = e.score
    return out


def unscored_rows(p: Pipeline) -> list[dict]:
    """沒有分數的 finding（缺資產脈絡）。不排名，但不能消失。"""
    return [{"asset": e.asset, "cve": e.cve, "decision": e.decision,
             "gaps": "；".join(e.gaps)} for e in p.ranked if not e.scored]


def _cvss(e) -> float:
    f = e.factor("severity")
    return float(f.inputs["cvss"]) if f else 0.0


def _move(cand) -> str:
    if cand is None:
        return ""
    hours = "?" if cand.effort_hours is None else f"{cand.effort_hours:g}h"
    return f"{ACTION_LABEL.get(cand.action, cand.action)}（{hours}）"


def headline(p: Pipeline) -> dict:
    """展示腳本第 2–4 步要講的那句話，從資料算出來，不寫死。"""
    rows = ranking_rows(p)
    top_cvss = min(rows, key=lambda r: r["cvss_rank"])
    top_ours = rows[0]
    riser = max(rows, key=lambda r: r["move"])
    faller = min(rows, key=lambda r: r["move"])
    ten = [r for r in rows if r["cvss"] == 10.0]
    return {
        "top_cvss": top_cvss, "top_ours": top_ours, "riser": riser, "faller": faller,
        "cvss10": len(ten),
        "cvss10_span": (min(r["rank"] for r in ten), max(r["rank"] for r in ten)) if ten else None,
        "scored": len(rows), "total": len(p.ranked),
    }


# --- 單筆說明（展示腳本第 5 步） ---------------------------------------------

def detail(p: Pipeline, asset: str, cve: str) -> dict:
    order = p.scored
    pos = next(i for i, e in enumerate(order) if e.asset == asset and e.cve == cve)
    e = order[pos]
    above = order[pos - 1] if pos > 0 else None
    paths = find_paths(p.graph, asset)
    t = p.treatments.get((asset, cve.upper()))
    plan = p.plans.get((asset, cve.upper()))
    return {
        "explanation": e, "rank": pos + 1, "text": explain_row(e, above),
        "factors": [{"因子": f.symbol, "名稱": f.key, "值": round(f.value, 4),
                     "權重": f.weight, "貢獻（分）": f.contribution, "來源": f.source}
                    for f in e.factors],
        "paths": [render_path(path, p.graph) for path in paths[:3]],
        "path_count": len(paths),
        "treatment": t, "plan": plan,
    }


# --- 措施模擬（展示腳本第 6–7 步） ---------------------------------------------

def measures(p: Pipeline) -> list[dict]:
    out = []
    # 與命令列同一個順序：有 ROI 的依每小時降分，沒有的（待重掃、待驗證）排最後
    ordered = sorted(p.roi.outcomes,
                     key=lambda o: (o.per_hour is None, -(o.per_hour or 0), -o.paths_cut))
    for o in ordered:
        c = o.candidate
        out.append({
            "id": c.remediation_id, "措施": ACTION_LABEL.get(c.action, c.action),
            "資產": c.asset, "CVE": c.cve,
            "工時": c.effort_hours, "停機（分）": c.downtime_minutes,
            "限制": c.constraint or "—",
            "切路徑": o.paths_cut, "降分": o.score_drop, "每小時降分": o.per_hour,
            "狀態": o.status, "說明": o.note,
        })
    return out


def simulate(p: Pipeline, chosen_ids: list[str]) -> dict:
    """同時做這幾項之後的結果。組合一定重算，不把單項加起來（Day 24）。"""
    chosen = [o for o in p.roi.outcomes if o.candidate.remediation_id in chosen_ids]
    paths_after, drop = roi.combined(p.graph, p.score, chosen, p.services)
    hours = [o.candidate.effort_hours for o in chosen]
    pending = [o.candidate.remediation_id for o in chosen if o.status != roi.PROVEN]

    # 每筆 finding 的前後分數：只列有變的
    changed = p.graph
    leaving = set()
    for o in chosen:
        c = o.candidate
        if o.status != roi.PROVEN:
            continue
        if c.action == "isolate":
            changed = roi.without_asset(changed, c.asset)
        elif c.action == "disable_service":
            for node in roi.service_nodes(p.graph, c.asset, p.services.get((c.asset, c.cve), "")):
                changed = roi.without_service(changed, node)
        elif c.action == "patch":
            leaving.add((c.asset, c.cve))
    before, after = p.score(p.graph), p.score(changed)
    moved = []
    for key, value in sorted(before.items(), key=lambda kv: -kv[1]):
        new = 0.0 if key in leaving else after.get(key, value)
        if abs(new - value) > 1e-9:
            moved.append({"資產": key[0], "CVE": key[1], "前": value,
                          "後": "離開佇列" if key in leaving else new,
                          "降": round(value - new, 2)})
    return {
        "paths_before": p.roi.paths_total, "paths_after": paths_after,
        "drop": drop, "queue_total": p.roi.queue_total,
        "hours": sum(h for h in hours if h is not None),
        "hours_unknown": sum(1 for h in hours if h is None),
        "per_hour": round(drop / sum(hours), 2) if hours and None not in hours
        and sum(hours) > 0 else None,
        "pending": pending, "moved": moved,
    }


def what_ifs(p: Pipeline) -> list[dict]:
    targets = roi.choke_targets(p.chokes)
    return [{"資產": w.asset, "路徑": f"{p.roi.paths_total} → {w.paths_after}",
             "降分": w.score_drop, "工時": "清冊沒有登記"}
            for w in roi.what_if(p.graph, p.score, targets)]


# --- 攻擊路徑圖 ---------------------------------------------------------------

def jewel_graph(p: Pipeline, graph=None) -> dict:
    """只收斂到通往 Crown Jewel 的路徑。全圖 58 個節點是毛球，這樣是十幾台。"""
    graph = graph or p.graph
    jewels = {n.id for n in p.graph.crown_jewels}
    zones = {a["asset_id"]: a["zone"] for a in _read_rows(str(DATA / "assets.csv"))}
    findings = Counter(r["asset"] for r in _read_rows(p.args.scanner))
    nodes, edges = set(), {}
    total = 0
    for jewel in sorted(jewels):
        for path in find_paths(graph, jewel):
            total += 1
            nodes.update(path.assets)
            for hop in path.hops:
                edge = edges.setdefault((hop.source, hop.target),
                                        {"kind": hop.kind, "via": hop.via, "paths": 0})
                edge["paths"] += 1
    nodes |= jewels
    return {
        "total_paths": total,
        "nodes": [{"id": a, "zone": "INTERNET" if a == INTERNET_ID else zones.get(a, "?"),
                   "crown_jewel": a in jewels, "findings": findings.get(a, 0)}
                  for a in sorted(nodes)],
        "edges": [{"source": s, "target": t, **e} for (s, t), e in sorted(edges.items())],
    }


def graph_after(p: Pipeline, chosen_ids: list[str]):
    changed = p.graph
    for o in p.roi.outcomes:
        c = o.candidate
        if c.remediation_id not in chosen_ids or o.status != roi.PROVEN:
            continue
        if c.action == "isolate":
            changed = roi.without_asset(changed, c.asset)
        elif c.action == "disable_service":
            for node in roi.service_nodes(p.graph, c.asset, p.services.get((c.asset, c.cve), "")):
                changed = roi.without_service(changed, node)
    return changed


# --- 匯出（展示腳本第 8 步） ---------------------------------------------------

EXPORT_FIELDS = ["rank", "asset", "cve", "cvss", "cvss_rank", "score", "band", "tier",
                 "tier_before", "applicability", "review", "kev", "epss", "first", "close"]


def export_csv(p: Pipeline) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_FIELDS, extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in ranking_rows(p):
        writer.writerow(row)
    return buffer.getvalue()


# --- 舊的四個視圖（Day 24 之後的驗證查詢，保留給 --view） ----------------------

def view_graph(p: Pipeline) -> dict:
    return jewel_graph(p)


def view_ranking(p: Pipeline) -> dict:
    """堆疊長條的輸入。**畫出來才看得到 B 與 T 在頂端沒有鑑別力。**"""
    top = p.scored[:10]
    spread = {key: sorted({round(f.contribution, 2) for e in top
                           for f in e.factors if f.key == key})
              for key in ("severity", "threat", "exposure", "business", "path")}
    return {"rows": [{"asset": e.asset, "cve": e.cve, "score": e.score, "tier": e.tier,
                      "factors": {f.key: round(f.contribution, 2) for f in e.factors}}
                     for e in top],
            "distinct_contributions_in_top10": spread}


def view_cvss(p: Pipeline) -> dict:
    rows = ranking_rows(p)
    ten = [r for r in rows if r["cvss"] == 10.0]
    return {"rows": [{k: r[k] for k in ("cvss", "cvss_rank", "rank", "move", "asset", "cve")}
                     for r in sorted(rows, key=lambda r: r["cvss_rank"])],
            "cvss_10_count": len(ten),
            "cvss_10_rank_span": max(r["rank"] for r in ten) - min(r["rank"] for r in ten)
            if ten else 0}


def view_treatment(p: Pipeline) -> dict:
    ts = list(p.treatments.values())
    order = ("P0", "P1", "P2", "P3")
    return {
        "applicability": dict(Counter(t.applicability for t in ts)),
        "tier_before": dict(Counter(t.tier_before for t in ts if t.tier_before)),
        "tier_after": dict(Counter(t.tier for t in ts if t.tier)),
        # 只算真的往上推的（Day 26 更正：離開佇列不是升級）
        "raised": sum(1 for t in ts if t.tier and t.tier_before
                      and order.index(t.tier) < order.index(t.tier_before)),
        "review_required": sum(1 for t in ts if t.review_required),
        "no_options": sum(1 for t in ts if t.stuck),
    }


VIEWS = {"graph": view_graph, "ranking": view_ranking,
         "cvss": view_cvss, "treatment": view_treatment}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--view", choices=sorted(VIEWS), help="只跑一個視圖")
    args = parser.parse_args()
    pipeline = run()
    wanted = [args.view] if args.view else sorted(VIEWS)
    print(json.dumps({name: VIEWS[name](pipeline) for name in wanted},
                     ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
