#!/usr/bin/env python
"""儀表板的資料層：四個視圖各自的查詢（藍圖 §12 的 `app/`，Day 28）。

Day 24 做完之後，使用者問了一個對的問題：**我們寫的這些東西，看得見嗎？**

那個擔心的位置要先講清楚。攻擊路徑好不好畫不是風險——收斂到「通往 Crown Jewel
的路徑」之後只剩 12 台資產、18 條邊，一眼看得完。真正沒驗證過的是 Day 28 的本體：
40 筆排名帶著因子分解、CVSS 排名與本專案排名並陳（成功標準 #5）、以及處置視圖。

四個都畫出來了，結論是**可行**，所以決定不另外寫一篇「我們的東西畫得出來」的
小結文章——那會偷走 Day 28 的題目。這支腳本把當時的查詢留下來，Day 28 直接接。

```bash
uv run python app/data.py            # 四個視圖全跑，輸出 JSON
uv run python app/data.py --view cvss
```

**畫面與資料分開。** 這個檔只負責把數字查出來，不碰呈現；`app/dashboard.py`
（Day 28）才決定怎麼畫。分開的理由跟 Day 16 的 `Explanation` 一樣——
呈現是投影，投影不該反過來決定資料長什麼樣。

## 驗證時順手發現的一件事

`--view ranking` 把前十名的因子貢獻攤開之後看得很清楚：**B（業務衝擊）十筆全是
2.0、T（威脅）十筆全是 1.2。兩個因子在頂端完全沒有鑑別力**，真正拉開差距的是
E 與 A。

這跟 Day 25 發現「32/40 的 CVE 都在 KEV，所以 KEV 沒有鑑別力」是同一個現象，
但發生在**分數層**，而且是畫出來才看到的——看數字看不到。留給 Day 29 的四情境驗證。
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cve2action.attack_graph.build import build_graph  # noqa: E402
from cve2action.attack_graph.choke import analyse  # noqa: E402
from cve2action.attack_graph.identity import annotate as identity_annotate  # noqa: E402
from cve2action.attack_graph.identity import privilege_obtainable  # noqa: E402
from cve2action.attack_graph.model import ASSET, INTERNET_ID  # noqa: E402
from cve2action.attack_graph.paths import NETWORK, find_paths  # noqa: E402
from cve2action.attack_graph.reachability import annotate  # noqa: E402
from cve2action.collectors.epss import load_snapshots as load_epss  # noqa: E402
from cve2action.collectors.kev import load_catalog  # noqa: E402
from cve2action.collectors.nvd import load_snapshots  # noqa: E402
from cve2action.io import read_asset_context, read_scanner  # noqa: E402
from cve2action.remediation import Facts, treat  # noqa: E402
from cve2action.rules import load_rules  # noqa: E402
from cve2action.scoring import rank_explained  # noqa: E402
from cve2action.scoring.path_score import compute as path_compute  # noqa: E402

DATA = ROOT / "data" / "synthetic" / "northstar"
SNAPSHOTS = ROOT / "data" / "snapshots"
AS_OF = date(2026, 9, 24)


def rows(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def build() -> tuple:
    """建圖、算路徑分數、跑排名。四個視圖共用這一份。"""
    assets, services, scan = rows("assets.csv"), rows("services.csv"), rows("scanner.csv")
    graph = build_graph(assets, rows("asset_interfaces.csv"), services,
                        rows("network_edges.csv"), rows("identity_edges.csv"))
    annotate(graph, rows("network_edges.csv"), rows("network_policies.csv"),
             {a["asset_id"]: a["zone"] for a in assets})
    snapshots = load_snapshots(SNAPSHOTS / "nvd")
    vectors = {}
    for cve, record in snapshots.items():
        chosen = record.cvss.preferred(("3.1", "4.0"))
        if chosen is not None:
            vectors[cve.upper()] = chosen.vector
    identity_annotate(graph, rows("identity_edges.csv"), services, scan, vectors)

    privileges = {a["asset_id"]: privilege_obtainable(a["asset_id"], services, scan, vectors)
                  for a in assets}
    paths = {a: s.value for a, s in path_compute(graph, privileges).items()}
    ranked = rank_explained(
        read_scanner(DATA / "scanner.csv"), read_asset_context(DATA / "asset_context.csv"),
        load_rules(ROOT / "config/risk_rules.yaml"), snapshots,
        load_epss(SNAPSHOTS / "epss"), load_catalog(SNAPSHOTS / "kev"),
        rows("controls.csv"), AS_OF, paths)
    return graph, ranked, snapshots


# --- 視圖一：通往 Crown Jewel 的路徑圖 ----------------------------------------

def view_graph(graph, *_ignored) -> dict:
    """節點與邊，邊帶「幾條路徑走這一段」。

    只收斂到通往 Crown Jewel 的路徑上——全圖 58 個節點畫出來是一團毛球，
    這樣是 12 台。Day 20 立的那句「路徑的數量不是資訊量」在這裡兌現。
    """
    jewels = {n.id for n in graph.crown_jewels}
    zones = {a["asset_id"]: a["zone"] for a in rows("assets.csv")}
    report = analyse(graph)
    counts = {c.asset: (c.on_paths, c.cuts) for c in report.chokes}
    findings: dict[str, int] = Counter(r["asset"] for r in rows("scanner.csv"))

    nodes, edges = set(), {}
    for jewel in jewels:
        for path in find_paths(graph, jewel):
            nodes.update(path.assets)
            for hop in path.hops:
                edge = edges.setdefault((hop.source, hop.target),
                                        {"kind": hop.kind, "via": hop.via, "paths": 0})
                edge["paths"] += 1
    nodes.discard(INTERNET_ID)
    return {
        "total_paths": report.total_paths,
        "nodes": [{"id": a, "zone": zones.get(a, "?"), "crown_jewel": a in jewels,
                   "findings": findings.get(a, 0),
                   "on_paths": counts.get(a, (0, 0))[0], "cuts": counts.get(a, (0, 0))[1]}
                  for a in sorted(nodes)],
        "edges": [{"source": s, "target": t, **e} for (s, t), e in sorted(edges.items())],
    }


# --- 視圖二：前十名的因子分解 --------------------------------------------------

def view_ranking(_graph, ranked, *_ignored) -> dict:
    """堆疊長條的輸入。**畫出來才看得到 B 與 T 在頂端沒有鑑別力。**"""
    top = [e for e in ranked if e.scored][:10]
    spread = {}
    for key in ("severity", "threat", "exposure", "business", "path"):
        values = {round(f.contribution, 2) for e in top
                  for f in e.factors if f.key == key}
        spread[key] = sorted(values)
    return {
        "rows": [{
            "asset": e.asset, "cve": e.cve, "score": e.score, "tier": e.tier,
            "factors": {f.key: round(f.contribution, 2) for f in e.factors},
        } for e in top],
        # 相異貢獻值只有一個 ⇒ 這個因子在前十名裡完全沒有鑑別力
        "distinct_contributions_in_top10": spread,
    }


# --- 視圖三：CVSS 排名 vs 本專案排名（成功標準 #5）-----------------------------

def view_cvss(_graph, ranked, *_ignored) -> dict:
    """同一個 CVSS 分數在本專案排序裡跨了多少名次。

    資料集裡有六筆 CVSS 都是 10.0，散到 #4 到 #32——掉最深的兩筆都是查無路徑。
    這是整個系列的主張壓成一張圖。
    """
    scored = [e for e in ranked if e.scored]
    ours = {(e.asset, e.cve): i + 1 for i, e in enumerate(scored)}
    by_cvss = sorted(scored, key=lambda e: -float(e.factor("severity").inputs["cvss"]))
    out = []
    for i, e in enumerate(by_cvss, 1):
        key = (e.asset, e.cve)
        out.append({"cvss": float(e.factor("severity").inputs["cvss"]),
                    "cvss_rank": i, "our_rank": ours[key], "delta": i - ours[key],
                    "asset": e.asset, "cve": e.cve})
    tied = [r for r in out if r["cvss"] == 10.0]
    return {
        "rows": out,
        "cvss_10_count": len(tied),
        "cvss_10_rank_span": max(r["our_rank"] for r in tied) - min(
            r["our_rank"] for r in tied) if tied else 0,
    }


# --- 視圖四：處置結果 ----------------------------------------------------------

def view_treatment(graph, ranked, _snapshots) -> dict:
    catalog = load_catalog(SNAPSHOTS / "kev")
    reachable = frozenset(n.id for n in graph.of_kind(ASSET) if find_paths(graph, n.id))
    unauthenticated = set()
    for jewel in (n.id for n in graph.crown_jewels):
        for path in find_paths(graph, jewel):
            if all(h.kind == NETWORK for h in path.hops):
                unauthenticated.update(path.assets)
    unauthenticated.discard(INTERNET_ID)

    facts = Facts(
        kev=frozenset(str(c).upper() for c in catalog.entries),
        reachable=reachable, has_path=reachable,
        unauthenticated_jewel=frozenset(unauthenticated),
        evidence={(r["asset_id"], r["cve"]): r for r in rows("version_evidence.csv")},
        acceptances=rows("risk_acceptances.csv"), remediations=rows("remediations.csv"))
    treatments = [treat(e, facts, str(SNAPSHOTS / "nvd"), AS_OF) for e in ranked]
    return {
        "applicability": dict(Counter(t.applicability for t in treatments)),
        "tier_before": dict(Counter(t.tier_before for t in treatments if t.tier_before)),
        "tier_after": dict(Counter(t.tier for t in treatments if t.tier)),
        "raised": sum(1 for t in treatments if t.tier_before and t.tier != t.tier_before),
        "review_required": sum(1 for t in treatments if t.review_required),
        "no_options": sum(1 for t in treatments if t.stuck),
    }


VIEWS = {"graph": view_graph, "ranking": view_ranking,
         "cvss": view_cvss, "treatment": view_treatment}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--view", choices=sorted(VIEWS), help="只跑一個視圖")
    args = parser.parse_args()

    context = build()
    wanted = [args.view] if args.view else sorted(VIEWS)
    print(json.dumps({name: VIEWS[name](*context) for name in wanted},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
