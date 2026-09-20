# Decision Engine v0.1 開發規格

| 欄位 | 內容 |
|---|---|
| 規格版本 | 0.1.0 |
| 狀態 | Frozen for Day 6（變更須新增/更新 ADR） |
| 依據 | [Day 5 文章](../articles/day-05.md)、[ADR-day-05](../decisions/ADR-day-05-decision-engine-v01.md) |
| 實作 | `src/cve2action/`（`rules.py`、`engine.py`、`io.py`、`cli.py`） |

## 1. 目的與定位

Decision Engine v0.1 是整個系列的第一條 Vertical Slice：

```text
scanner.csv + asset_context.csv + risk_rules.yaml
                    ↓
            Decision Engine
                    ↓
            ranked_result.csv
```

它回答的問題是「**誰先處理**」，輸出可解釋的處置優先順序。分數只用於排序與驗證，
不宣稱事故機率或財務損失；LLM 不參與任何決策計算。

## 2. 輸入契約

### 2.1 `scanner.csv`（弱掃結果）

| 欄位 | 必要 | 說明 |
|---|---|---|
| `asset` | ✔ | 資產識別（v0.1 以字串精確比對 asset_context） |
| `cve` | ✔ | CVE 編號，v0.1 不驗證格式 |
| `cvss` | ✔ | CVSS Base Score，必須是 0–10 的數字 |
| `service` | — | 僅用於定位與解釋，不進公式 |

### 2.2 `asset_context.csv`（Minimum Context）

| 欄位 | 必要 | 值域 |
|---|---|---|
| `asset` | ✔ | 唯一，不得重複（重複即拒載） |
| `environment` | ✔（僅解釋用） | `PROD` / `NON_PROD` |
| `reachability` | ✔ | `INTERNET` / `INTERNAL` / `ISOLATED` |
| `control_effectiveness` | ✔ | `NONE` / `PARTIAL` / `STRONG` / `UNKNOWN` |
| `business_criticality` | ✔ | `CRITICAL` / `IMPORTANT` / `NORMAL` |

### 2.3 `risk_rules.yaml`（Decision Rules，外部化）

基準檔：[`config/risk_rules.yaml`](../../config/risk_rules.yaml)。載入時強制驗證，違反即拒載：

1. `weights` 只能有 `severity` / `exposure` / `business` 三鍵，且總和 = 1。
2. 三組值域映射的鍵必須與 §2.2 值域完全一致（不得增刪），數值皆在 0–1。
3. `control_effectiveness.UNKNOWN >= NONE`（**UNKNOWN 不得降低曝險**）。
4. `priority_bands` 必須不重疊且涵蓋 0–10。

## 3. 計分模型（v0.1 baseline）

```text
S = CVSS / 10
E = Reachability × Control Effectiveness   （Effective Exposure）
B = Business Impact

Priority Score = 10 × (0.50×S + 0.25×E + 0.25×B)   （四捨五入至小數 2 位）
```

v0.1 數值映射（來自 risk_rules.yaml，非程式碼常數）：

| Reachability | 值 | Control | 值 | Business | 值 |
|---|---:|---|---:|---|---:|
| INTERNET | 1.0 | NONE | 1.0 | CRITICAL | 1.0 |
| INTERNAL | 0.6 | PARTIAL | 0.7 | IMPORTANT | 0.7 |
| ISOLATED | 0.2 | STRONG | 0.4 | NORMAL | 0.4 |
| | | UNKNOWN | 1.0 | | |

分級（`priority_bands`）：

| Priority | 分數 |
|---|---|
| Critical | 9.0–10.0 |
| High | 7.0–8.9 |
| Medium | 4.0–6.9 |
| Low | 0–3.9 |

**50/25/25 是 v0.1 起始假設，不是標準答案**；EPSS、KEV、攻擊路徑與更完整的控制/衝擊
模型於 Day 7+ 逐步加入並重新校準，任何權重或門檻變更必須留下 ADR。

## 4. NEEDS_CONTEXT 規則

符合下列任一條件的 finding **不評分、不猜預設值**，`decision = NEEDS_CONTEXT`，
`reason` 逐項列出缺口，並固定排在 `ranked_result.csv` 最後（不隱藏）：

- `asset` 在 asset_context.csv 找不到。
- `cvss` 缺值、非數字或超出 0–10。
- `reachability` / `control_effectiveness` / `business_criticality` 缺值或不在值域。

注意：`control_effectiveness = UNKNOWN` **不是** NEEDS_CONTEXT——它是合法值，
代表「有登錄但無法證明有效」，以最保守係數 1.0 計分。

## 5. 輸出契約：`ranked_result.csv`

欄位順序固定：

```text
asset, cve, cvss, environment, effective_exposure, business_criticality,
priority_score, priority, decision, reason
```

- `decision`：`SCORED` 或 `NEEDS_CONTEXT`。
- 排序：`SCORED` 依 `priority_score` 降冪；`NEEDS_CONTEXT` 全部列在最後。
- `reason`：每列必附，列出 S/E/B 三因子的輸入、數值與公式代入結果。

## 6. 驗收案例（回歸基準，tests/ 已覆蓋）

| 案例 | 輸入 | 期望 |
|---|---|---|
| Case A | CVSS 9.8、ISOLATED、PARTIAL、NORMAL | **6.25 / Medium** |
| Case B | CVSS 8.8、INTERNET、STRONG、CRITICAL | **7.90 / High** |
| Case B 無控制 | CVSS 8.8、INTERNET、NONE、CRITICAL | **9.40 / Critical** |
| 排序翻轉 | A + B 同時輸入 | B 排在 A 前 |
| UNKNOWN 控制 | UNKNOWN vs NONE 同條件 | 分數相同（不降曝險） |
| 缺 context | scanner 有、context 無的資產 | NEEDS_CONTEXT、列於最後 |

執行方式：

```bash
uv run cve2action rank --scanner data/synthetic/day-06-scanner.csv --context data/synthetic/day-06-asset-context.csv --rules config/risk_rules.yaml --out ranked_result.csv
```

## 7. 非目標（v0.1 明確不做）

- EPSS、KEV、NVD 補充（Day 7–10）。
- 資產歸併（多 IP → 同一 asset）、漏洞適用性閘門（藍圖 §9.0；此版假設 scanner.csv 已是歸併後結果）。
- 攻擊路徑、圖形模型、Choke Point（Day 19–24）。
- 修補建議與 What-if（Day 25–27）。
- Dashboard、API（Day 16、28）。
- 自動修補、Ticket 整合、LLM 決策。
