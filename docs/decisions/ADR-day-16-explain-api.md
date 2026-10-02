# ADR-day-16：理由是計分的產物，不是計分之後的字串

- 狀態：Accepted
- 日期：2026-10-01
- 影響：新增 `src/cve2action/scoring/` 套件（`engine` 由套件根目錄移入）、`scoring/explain.py`、CLI `cve2action explain`
- 相關：[ADR-day-05](ADR-day-05-decision-engine-v01.md)（每筆必附理由）、[ADR-day-07 的快照投影紀律](../architecture/decision-engine-v0.1-spec.md)

## 背景

Day 5 就定下「每一列都要附理由」。實作方式是在計分之後，用 f-string 把數值拼成一行 `reason`：

```python
row["reason"] = (
    f"CVSS {cvss:g} [{cvss_label}] (S={severity:g}); " + threat_text +
    f"{context['reachability']} x {control_label} -> E={exposure:g}; ..."
)
```

這樣做有兩個毛病。

**一、它會跟計算漂開。** 字串是另外拼的，改公式時沒有任何機制強迫你同步改它。Day 14 加入威脅項、Day 15 改寫控制來源，兩次都得手動補這段字串——補對了是因為記得，不是因為有東西擋著。這與規格文件凍結在 Day 6 是同一種失敗模式。

**二、它只回答「怎麼算的」，不回答「為什麼排在這裡」。** 排序是**比較**出來的。單看一列的算式，永遠答不了「為什麼它在第 33 名而不是第 32 名」——那個答案存在於兩列之間，不在任何一列裡面。

## 決策

### 1. Explanation 是計分的第一級產物

`explain_finding()` 回傳 `Explanation`；`ranked_result.csv` 的列與 `reason` 字串都是它的**投影**：

```text
explain_finding() → Explanation ─┬→ row_from()      → CSV 的一列
                                 ├→ .to_reason()    → reason 欄
                                 ├→ .to_dict()      → JSON / 未來的 API
                                 └→ explain_row()   → 人讀的多行說明
```

這與 Day 7 處理快照的紀律相同：`raw` 是唯一事實，`extracted` 是可重新導出的投影。字串不可能再跟數字不一致，因為字串是從數字長出來的。

排序也只實作一次：`rank_explained()` 排序 Explanation，`rank()` 是它的列投影，兩者不可能排出不同順序。

### 2. 每一項因子都帶著它的來歷

`Factor` 記錄 `value`、`weight`、`contribution`、`share`、`inputs`（原始輸入）與 `source`（出處）。Day 12–15 建立的 `*_source` 至此全部串起來：讀者看到的不只是 `E=0.4`，而是 `0.4` 來自 `control:waf@2026-08-14 (applies to AV:NETWORK)`。

### 3. 比較是說明的一部分

`Explanation.gap_to(other)` 把兩筆的分差拆成逐項貢獻差，加總必等於總分差（有回歸測試）。

輸出時的措辭要分清楚**最大變動項**與**造成輸贏的項**——兩者常常不同。RC4（CVE-2013-2566）落後前一名 0.41 分，變動最大的是業務衝擊 +1.50，但那是它**贏**的地方；真正把它壓下去的是嚴重度 −1.36。只報絕對值最大的那一項會說出相反的結論。

### 4. 未評分也要解釋

`NEEDS_CONTEXT` 的 Explanation 沒有分數、沒有因子，只有 `gaps`。輸出明說「未評分不是漏掉，是拒絕在缺資料時猜一個分數」。

### 5. 程式搬家：`scoring/` 套件

`engine.py` 移入 `src/cve2action/scoring/`，與 `explain.py` 同層，對齊藍圖 §12。Day 17 的校準與 Day 18 的門檻會再加兩個模組，現在搬只動 5 行 import。`models.py`、`rules.py`、`io.py` 留在套件根目錄——攻擊路徑與修補建議也要用，放進 `scoring/` 會製造錯誤的從屬關係。

舊路徑保留相容層：`from cve2action.engine import rank` 仍可運作。

## 替代方案

- **只加一個 `--verbose` 讓 reason 更長**：解決不了漂開，也解決不了比較。
- **用 LLM 生成說明**：違反「LLM 不進決策流程」；而且會把可驗證的算式換成不可驗證的敘述。
- **把 Explanation 存成第四個 CSV**：目前沒有消費者需要它落地；Day 28 的 Dashboard 會用 `to_dict()`，屆時再決定格式。

## 後果

- 新增 15 個測試。其中最關鍵的一個會把每一列 `reason` 裡的數字全部抓出來，逐一比對它是否存在於 Explanation 的欄位中——字串說了 Explanation 裡沒有的數字就會紅。
- `cve2action explain --cve ... [--json]` 可逐筆說明，並自動附上與前一名的逐項差距。
- 所有既有輸出完全不變：255 個測試全綠，`ranked_result.csv` 逐欄相同。
- 尚未做到：**反事實**（「要怎樣才會變」）。`gap_to` 回答的是「和它比差在哪」，不是「我改什麼能降幾分」。後者要有成本模型才有意義，留給 Day 26–27。
