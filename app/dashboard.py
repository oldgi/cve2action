"""儀表板（藍圖 §12 的 `app/dashboard.py`，Day 28）。

```bash
uv run --extra dashboard streamlit run app/dashboard.py
```

六個分頁對應藍圖 §14 的展示腳本八步：

| 分頁 | 展示腳本 |
|---|---|
| ① 排名對照 | 1 上傳弱掃檔、2 CVSS 排名、3–4 加入情境後的排名（成功標準 #5：兩欄並陳） |
| ② 單筆說明 | 5 展開公式、資料來源、攻擊路徑 |
| ③ 措施模擬 | 6 選措施、7 前後分數、切掉的路徑、工時、每工時降分 |
| ④ 攻擊路徑 | 通往 Crown Jewel 的路徑與瓶頸 |
| ⑤ 情境驗證 | §8.4 四個必測情境（Day 29） |
| ⑥ 匯出 | 8 匯出修補優先清單 |

**畫面只負責畫。** 每個數字都來自 `app/data.py`，而 `data.py` 跑的是命令列的同一條管線
——儀表板上的數字與文章、測試、CI 是同一段程式算的。

## 三件刻意不做的事

1. **不拿 P0 筆數當頭條。** 32/40 的 CVE 都在 KEV，覆寫後 24/40 是 P0（Day 25 原記 25，
   Day 26 更正）。輸入飽和時，P0 計數沒有參考價值。
2. **不把降分與切路徑合成一個 ROI。** 兩者給出相反的答案（ADR-day-27）；合成就得
   替「一條路徑值幾分」定一個沒有根據的匯率。
3. **不替 CVSS 同分排先後。** 六筆 10.0 在 CVSS 眼裡就是並列第一。
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data  # noqa: E402
import scenarios  # noqa: E402

st.set_page_config(page_title="CVE2Action", page_icon="🛡️", layout="wide")

# 顏色：dataviz 參考調色盤，亮暗兩組各自驗證過（validate_palette.js 兩種模式皆 PASS；
# 亮色有三格對比低於 3:1，所以每張圖旁邊都有表格可讀）
LIGHT = {"series": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"],
         "up": "#2a78d6", "down": "#e34948", "neutral": "#c3c2b7",
         "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781", "grid": "#e1e0d9",
         "node": "#898781", "removed": "#e1e0d9"}
DARK = {"series": ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"],
        "up": "#3987e5", "down": "#e66767", "neutral": "#4a4a46",
        "ink": "#ffffff", "ink2": "#c3c2b7", "muted": "#898781", "grid": "#2c2c2a",
        "node": "#898781", "removed": "#383835"}


def palette() -> dict:
    theme = getattr(getattr(st, "context", None), "theme", None)
    return DARK if getattr(theme, "type", "light") == "dark" else LIGHT


C = palette()
FACTOR_NAMES = {"severity": "S 嚴重度", "threat": "T 威脅", "exposure": "E 曝險",
                "business": "B 業務", "path": "A 攻擊路徑"}


def base_layout(fig: go.Figure, height: int) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=8, r=8, t=8, b=8),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(family="system-ui, 'Segoe UI', sans-serif", color=C["ink2"]),
                      hoverlabel=dict(font_size=13))
    return fig


@st.cache_resource(show_spinner="跑完整條管線：評分、攻擊圖、處置、措施重算……")
def load(digest: str, content: bytes | None) -> data.Pipeline:
    if content is None:
        return data.run()
    path = Path(tempfile.gettempdir()) / f"cve2action-upload-{digest}.csv"
    path.write_bytes(content)
    return data.run(path)


# --- 側欄：資料來源（展示腳本第 1 步） ------------------------------------------

with st.sidebar:
    st.header("資料來源")
    upload = st.file_uploader("上傳弱掃 CSV（欄位：asset, cve, cvss, service）", type="csv")
    st.caption("不上傳就用 Northstar 的 40 筆。資產脈絡、拓樸與威脅情報快照固定用 "
               "Northstar——換掉的是要排序的弱點，不是公司。")
    content = upload.getvalue() if upload else None
    digest = hashlib.sha256(content).hexdigest()[:12] if content else "northstar"

try:
    P = load(digest, content)
except Exception as error:  # 上傳檔格式錯：講清楚，不要白畫面
    st.error(f"這份弱掃檔跑不動：{error}")
    st.stop()

rows = data.ranking_rows(P)
head = data.headline(P)

with st.sidebar:
    st.divider()
    st.metric("弱點筆數", f"{head['total']}", help="有分數的才排名；缺資產脈絡的列在匯出頁")
    st.metric("有分數", f"{head['scored']}")
    st.metric("Internet → Crown Jewel 路徑", f"{P.roi.paths_total}")
    st.caption(f"證據基準日 {data.AS_OF}。NVD／EPSS／KEV 為固定快照，重跑結果逐位元組相同。")
    st.caption("所有資產與環境均為虛構（Northstar）；CVE、EPSS、KEV、CWE 為公開資料。")

st.title("CVE2Action")
st.markdown("**弱掃告訴我們哪裡有洞；CVE2Action 告訴我們攻擊者可能從哪裡進來、會走到哪裡，"
            "以及現在先做哪一件事最划算。**")

tab_rank, tab_detail, tab_measure, tab_graph, tab_scenario, tab_export = st.tabs(
    ["① 排名對照", "② 單筆說明", "③ 措施模擬", "④ 攻擊路徑", "⑤ 情境驗證", "⑥ 匯出"])


def label(row: dict) -> str:
    return f"#{row['rank']}　{row['asset']}　{row['cve']}"


# --- ① 排名對照（展示腳本第 2–4 步；成功標準 #5） ------------------------------

with tab_rank:
    top_ours, riser, faller = head["top_ours"], head["riser"], head["faller"]
    lo, hi = head["cvss10_span"] or (0, 0)
    c1, c2, c3 = st.columns(3)
    c1.metric("CVSS 10.0 並列第一", f"{head['cvss10']} 筆", help="CVSS 分不出它們的先後")
    c1.caption(f"在本專案排序裡散到 **#{lo} 到 #{hi}**")
    c2.metric("本專案第一名的 CVSS 名次", f"並列第 {top_ours['cvss_rank']}")
    c2.caption(f"**{top_ours['asset']}** {top_ours['cve']}：CVSS {top_ours['cvss']}"
               f"{'、KEV 收錄' if top_ours['kev'] else ''}、分數 {top_ours['score']}"
               + ("（與第二名同分）" if rows[1]["tie_with_above"] else ""))
    c3.metric("往前最多", f"+{riser['move']} 名")
    c3.caption(f"**{riser['asset']}** {riser['cve']}：CVSS {riser['cvss']}（並列第 "
               f"{riser['cvss_rank']}）→ #{riser['rank']}。往後最多："
               f"**{faller['asset']}** {faller['cve']}，並列第 {faller['cvss_rank']} → "
               f"#{faller['rank']}")

    st.subheader("同一筆弱點，兩種排法")
    fig = go.Figure()
    for r in sorted(rows, key=lambda r: abs(r["move"])):
        strong = abs(r["move"]) >= 10
        color = (C["up"] if r["move"] > 0 else C["down"]) if strong else C["neutral"]
        fig.add_trace(go.Scatter(
            x=[0, 1], y=[r["cvss_rank"], r["rank"]], mode="lines+markers",
            line=dict(color=color, width=2.5 if strong else 1.5),
            marker=dict(size=8, color=color),
            hovertemplate=(f"<b>{r['asset']}</b><br>{r['cve']}<br>CVSS {r['cvss']}："
                           f"並列第 {r['cvss_rank']}<br>本專案：#{r['rank']}（{r['score']}）"
                           f"<br>移動 {r['move']:+d} 名<extra></extra>"),
            showlegend=False))
    for r in (top_ours, riser, faller):
        fig.add_annotation(x=1, y=r["rank"], xanchor="left", xshift=10, showarrow=False,
                           text=f"#{r['rank']} {r['asset']} {r['cve']}",
                           font=dict(color=C["ink2"], size=12))
    fig.update_xaxes(tickvals=[0, 1], ticktext=["CVSS 排名（同分並列）", "本專案排名"],
                     range=[-0.15, 1.9], showgrid=False, zeroline=False,
                     tickfont=dict(size=14, color=C["ink"]))
    fig.update_yaxes(autorange="reversed", title="名次", gridcolor=C["grid"], zeroline=False,
                     dtick=5)
    st.plotly_chart(base_layout(fig, 560), width="stretch")
    st.caption("藍：本專案排得比 CVSS 前面 10 名以上；紅：往後 10 名以上；灰：差距較小。"
               "滑過線段看單筆。")

    st.subheader("兩欄並陳")
    show = [{"CVSS 排名": f"並列 {r['cvss_rank']}", "本專案排名": r["rank"],
             "移動": r["move"], "資產": r["asset"], "CVE": r["cve"], "CVSS": r["cvss"],
             "分數": r["score"], "與上一名同分": "＝" if r["tie_with_above"] else "",
             "KEV": "●" if r["kev"] else "", "EPSS": r["epss"], "層級": r["tier"],
             "待複核": "●" if r["review"] else ""} for r in rows]
    st.dataframe(show, hide_index=True, width="stretch", height=420)

    st.subheader("前十名：分數從哪裡來")
    top10 = data.view_ranking(P)
    fig = go.Figure()
    names = [f"#{i} {r['asset']}" for i, r in enumerate(top10["rows"], 1)]
    for i, key in enumerate(FACTOR_NAMES):
        fig.add_trace(go.Bar(
            y=names, x=[r["factors"].get(key, 0) for r in top10["rows"]], orientation="h",
            name=FACTOR_NAMES[key], marker=dict(color=C["series"][i]),
            hovertemplate=f"{FACTOR_NAMES[key]}：%{{x:.2f}} 分<extra>%{{y}}</extra>"))
    fig.update_layout(barmode="stack", bargap=0.35,
                      legend=dict(orientation="h", y=1.08, x=0, traceorder="normal"))
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(title="貢獻（分，滿分 10）", gridcolor=C["grid"])
    st.plotly_chart(base_layout(fig, 420), width="stretch")
    flat = [k for k, v in top10["distinct_contributions_in_top10"].items() if len(v) == 1]
    if flat:
        st.info("前十名裡 **" + "、".join(FACTOR_NAMES[k] for k in flat) +
                "** 每一筆的貢獻都一樣——這幾項在頂端沒有鑑別力，拉開差距的是其他項。")


# --- ② 單筆說明（展示腳本第 5 步） ----------------------------------------------

with tab_detail:
    options = {label(r): r for r in rows}
    default = list(options).index(label(riser))
    pick = options[st.selectbox("選一筆弱點", list(options), index=default)]
    d = data.detail(P, pick["asset"], pick["cve"])
    e, t, plan = d["explanation"], d["treatment"], d["plan"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("分數", f"{e.score}", help="Priority Score 0–10，用來排序，不是機率")
    c2.metric("名次", f"#{d['rank']} / {head['scored']}",
              help=f"CVSS 名次：並列第 {pick['cvss_rank']}")
    c3.metric("層級", ("不必修" if t.leaves_queue else t.tier) if t else e.tier,
              delta=(f"覆寫前 {t.tier_before}" if t and t.tier != t.tier_before else None),
              delta_color="off")
    c4.metric("通往這台的路徑", f"{d['path_count']} 條")

    st.markdown("**公式**")
    st.code(e.formula, language="text")
    st.markdown("**每一項因子與來源**")
    st.dataframe(d["factors"], hide_index=True, width="stretch")
    if e.gaps:
        st.warning("資料缺口：" + "；".join(e.gaps))
    with st.expander("為什麼在這個名次（與上一名逐項比較）", expanded=True):
        st.code(d["text"], language="text")

    st.markdown("**處置判定**")
    if t:
        cols = st.columns(3)
        cols[0].markdown(f"適用性：`{t.applicability}`  \n{t.applicability_reason}")
        cols[1].markdown(f"規則覆寫：{t.override_note or '無'}")
        cols[2].markdown("待人工複核：**是**" if t.review_required else "待人工複核：否")
    if plan and plan.candidates:
        st.markdown("**候選措施**（Day 26：先做的不一定是能結案的）")
        st.dataframe([{"措施": data.ACTION_LABEL.get(c.action, c.action),
                       "工時": c.effort_hours, "停機（分）": c.downtime_minutes,
                       "限制": c.constraint or "—", "做完之後": c.closure,
                       "先做": "●" if c is plan.first else "",
                       "結案": "●" if c is plan.close else "", "備註": c.notes}
                      for c in plan.candidates], hide_index=True, width="stretch")
    else:
        st.caption("清冊裡沒有登記任何處置方案。成本是「不知道」，不是 0。")

    st.markdown(f"**攻擊路徑**（列前 {min(3, d['path_count'])} 條，共 {d['path_count']} 條）")
    if d["paths"]:
        for text in d["paths"]:
            st.code(text, language="text")
    else:
        st.caption("查無從 Internet 出發的路徑——這不是證明不可達，是這份圖上找不到。")


# --- ③ 措施模擬（展示腳本第 6–7 步） ---------------------------------------------

table = data.measures(P)
choices = {f"{m['id']}　{m['措施']}　{m['資產']}　{m['CVE']}": m["id"] for m in table}

with tab_measure:
    picked = st.multiselect("選要做的措施（可以多選；組合會重算，不把單項加起來）",
                            list(choices),
                            default=[k for k in choices if k.startswith("REM-004")])
    ids = [choices[k] for k in picked]
    sim = data.simulate(P, ids)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Crown Jewel 路徑", f"{sim['paths_after']}",
              delta=f"{sim['paths_after'] - sim['paths_before']} 條（原 {sim['paths_before']}）",
              delta_color="inverse")
    c2.metric("佇列降分", f"{sim['drop']}",
              help=f"全部 finding 的分數加總，原為 {sim['queue_total']}")
    c3.metric("投入工時", f"{sim['hours']:g} 小時"
              + (f"＋{sim['hours_unknown']} 項不明" if sim["hours_unknown"] else ""))
    c4.metric("每工時降分", "—" if sim["per_hour"] is None else f"{sim['per_hour']}")
    if sim["pending"]:
        st.warning("這幾項的降幅記 0——" + "、".join(sim["pending"]) +
                   "：改設定要重掃才知道有沒有消失，補償控制要驗證過才折減。")
    st.caption("**降分與切路徑是兩個量，不合成一個分數。** patch 讓一筆整個離開佇列但切不掉"
               "路徑（圖模型不看漏洞）；隔離切得掉路徑，但漏洞還在。")

    left, right = st.columns(2)
    with left:
        st.markdown("**分數有變的弱點**")
        if sim["moved"]:
            st.dataframe(sim["moved"], hide_index=True, width="stretch")
        else:
            st.caption("沒有任何一筆分數改變。")
    with right:
        st.markdown("**每一項措施單獨做**")
        st.dataframe([{k: m[k] for k in ("id", "措施", "資產", "工時", "切路徑", "降分",
                                         "每小時降分", "狀態")} for m in table],
                     hide_index=True, width="stretch")

    st.markdown("**清冊裡沒有、但攻擊圖說最該動的**（隔離試算；工時沒人登記，所以不進 ROI）")
    st.dataframe(data.what_ifs(P), hide_index=True, width="stretch")


# --- ④ 攻擊路徑 -----------------------------------------------------------------

ZONE_X = {"INTERNET": 0, "DMZ": 1, "LAB": 1, "APP": 2, "CORP": 2, "MGMT": 3,
          "DATA": 4, "OT": 4}
ZONE_TITLES = ((0, "Internet"), (1, "DMZ"), (2, "APP／CORP"), (3, "MGMT"), (4, "DATA"))


def graph_figure(view: dict, removed: set) -> go.Figure:
    by_x: dict[int, list] = {}
    for n in view["nodes"]:
        by_x.setdefault(ZONE_X.get(n["zone"], 2), []).append(n)
    pos = {}
    for x, members in by_x.items():
        for i, n in enumerate(sorted(members, key=lambda n: (n["zone"], n["id"]))):
            pos[n["id"]] = (x, (i - (len(members) - 1) / 2) * 1.0)
    fig = go.Figure()
    for edge in view["edges"]:
        (x0, y0), (x1, y1) = pos[edge["source"]], pos[edge["target"]]
        gone = (edge["source"], edge["target"]) in removed
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="skip", showlegend=False,
            line=dict(width=1 + edge["paths"] / 3,
                      color=C["removed"] if gone else C["muted"],
                      dash="dot" if (edge["kind"] != "network" or gone) else "solid")))
    groups = (
        ("Internet", [n for n in view["nodes"] if n["id"] == "internet"],
         C["series"][0], "square", 18),
        ("Crown Jewel", [n for n in view["nodes"] if n["crown_jewel"]],
         C["series"][1], "diamond", 18),
        ("其他資產", [n for n in view["nodes"] if n["id"] != "internet" and not n["crown_jewel"]],
         C["node"], "circle", 14),
    )
    for name, members, color, symbol, size in groups:
        if not members:
            continue
        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in members], y=[pos[n["id"]][1] for n in members],
            mode="markers+text", name=name, text=[n["id"] for n in members],
            textposition="top center", textfont=dict(size=11, color=C["ink2"]),
            marker=dict(size=size, color=color, symbol=symbol),
            customdata=[[n["zone"], n["findings"]] for n in members],
            hovertemplate="<b>%{text}</b><br>區域 %{customdata[0]}<br>弱點 %{customdata[1]} 筆"
                          "<extra></extra>"))
    fig.update_xaxes(visible=False, range=[-0.5, 4.7])
    fig.update_yaxes(visible=False)
    fig.update_layout(legend=dict(orientation="h", y=1.08, x=0))
    for x, zone in ZONE_TITLES:
        fig.add_annotation(x=x, y=0, yref="paper", text=zone, showarrow=False,
                           font=dict(color=C["muted"], size=12), yshift=-2)
    return base_layout(fig, 560)


with tab_graph:
    view = data.jewel_graph(P)
    st.markdown(f"**通往 Crown Jewel 的 {view['total_paths']} 條路徑**收斂成 "
                f"{len(view['nodes'])} 個節點、{len(view['edges'])} 條邊。"
                "線愈粗，走這一段的路徑愈多；虛線是帳號權限的一跳。")
    sel = st.multiselect("套用措施後再看一次（只有隔離與關服務改得動圖）",
                         [k for k in choices if ("隔離" in k or "關閉服務" in k)])
    removed: set = set()
    if sel:
        after = data.jewel_graph(P, data.graph_after(P, [choices[k] for k in sel]))
        kept = {(e["source"], e["target"]) for e in after["edges"]}
        removed = {(e["source"], e["target"]) for e in view["edges"]} - kept
        st.metric("剩下的路徑", f"{after['total_paths']}",
                  delta=f"{after['total_paths'] - view['total_paths']} 條",
                  delta_color="inverse")
    st.plotly_chart(graph_figure(view, removed), width="stretch")
    st.markdown("**共同瓶頸**（每一個 Crown Jewel 的最小切割都少不了它）："
                f"{'、'.join(P.chokes.universal) or '無'}")
    st.dataframe([{"資產": c.asset, "出現在幾條路徑": c.on_paths, "移除後切掉": c.cuts,
                   "可處置": "是" if c.actionable else "否（Crown Jewel）"}
                  for c in sorted(P.chokes.chokes, key=lambda c: (-c.cuts, c.asset))],
                 hide_index=True, width="stretch")


# --- ⑤ 情境驗證（Day 29，藍圖 §8.4） --------------------------------------------

BADGE = {scenarios.PASS: "✅ 通過", scenarios.PARTIAL: "⚠️ 部分", scenarios.FAIL: "❌ 未過",
         scenarios.NO_CASE: "— 資料裡沒有這種情況"}

with tab_scenario:
    st.markdown("**模型真的比 CVSS 排序好嗎？** 四個情境各寫成一條查詢規則，"
                "資料裡符合的每一筆都評，不挑會過的那一筆。")
    for item in scenarios.run_all(P):
        with st.container(border=True):
            number = "一二三四"[item.number - 1]
            st.markdown(f"#### 情境{number}：{item.title}　{BADGE[item.verdict]}")
            st.markdown(f"規則：{item.rule}　｜　判準：{item.criterion}")
            st.markdown(f"**量到**：{item.finding}")
            if item.caveat:
                st.caption(item.caveat)
            st.dataframe([{k: v for k, v in c.items() if not isinstance(v, (list, dict))}
                          for c in item.cases], hide_index=True, width="stretch")
    vs = scenarios.versus_expert(P, data.ROOT / "data/calibration/day-17-expert-ranking.yaml")
    c1, c2 = st.columns(2)
    c1.metric("與人工排序的一致度（本專案）", f"τ-b {vs['model'][0]}",
              help=f"一致 {vs['model'][1]}、分歧 {vs['model'][2]}")
    c2.metric("與人工排序的一致度（只看 CVSS）", f"τ-b {vs['cvss'][0]}",
              help=f"一致 {vs['cvss'][1]}、分歧 {vs['cvss'][2]}、CVSS 平手 {vs['cvss'][3]}")
    st.caption(f"只有 {vs['n']} 筆，而且排序者就是模型作者——這是自我一致性檢查，不是獨立驗證。")


# --- ⑥ 匯出（展示腳本第 8 步） ---------------------------------------------------

with tab_export:
    st.markdown("**修補優先清單**——同一台設備的多個介面已歸併，一筆就是一項工作。")
    st.dataframe([{k: r[k] for k in data.EXPORT_FIELDS} for r in rows],
                 hide_index=True, width="stretch", height=420)
    st.download_button("下載 CSV", data.export_csv(P).encode("utf-8-sig"),
                       file_name="cve2action-priority.csv", mime="text/csv")
    missing = data.unscored_rows(P)
    if missing:
        st.markdown(f"**沒有分數的 {len(missing)} 筆**（不排名，但不能消失）")
        st.dataframe(missing, hide_index=True, width="stretch")
