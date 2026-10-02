# Decision Engine 開發規格

| 欄位 | 內容 |
|---|---|
| 規格版本 | 0.3.1（`config/risk_rules.yaml` 仍為 `0.3.0`——Day 16 沒有動規則，只動了結構） |
| 狀態 | Live——隨 ADR 更新；每次改動都要在 §8 留下一行 |
| 依據 | [Day 5 文章](../articles/day-05.md)、[ADR-day-05](../decisions/ADR-day-05-decision-engine-v01.md) 起的 ADR 鏈（見 §8） |
| 實作 | `src/cve2action/`：`rules.py`、`io.py`、`models.py`、`cli.py`、`collectors/`、`normalization/`、`scoring/` |

> v0.1 的 Vertical Slice 已在 Day 6 跑通，這份文件自此改為**追蹤現況**而非凍結快照。
> 凍結在 Day 6 當下的那一版見 git 歷史：`git show e9c4fe4:docs/architecture/decision-engine-v0.1-spec.md`。

## 1. 目的與定位

```text
scanner.csv + asset_context.csv + risk_rules.yaml          （Day 6 的最小輸入）
  + data/snapshots/{nvd,epss,kev}                          （Day 7–10，可選）
  + controls.csv                                           （Day 15，可選）
                    ↓
            Decision Engine
                    ↓
            ranked_result.csv
```

它回答的問題是「**誰先處理**」，輸出可解釋的處置優先順序。分數只用於排序與驗證，
不宣稱事故機率或財務損失；LLM 不參與任何決策計算。

**所有可選輸入都可以不給。** 不給時對應的項目不是補零，而是整個移除或退回更保守的
假設（見 §3.2）；公式會精確退化為 Day 5 的三項版本，先前建立的回歸基準不受影響。

## 2. 輸入契約

### 2.1 `scanner.csv`（弱掃結果）

| 欄位 | 必要 | 說明 |
|---|---|---|
| `asset` | ✔ | 資產識別（v0.1 以字串精確比對 asset_context） |
| `cve` | ✔ | CVE 編號，v0.1 不驗證格式 |
| `cvss` | ✔ | CVSS Base Score，0–10；有快照時以快照為準，不一致會記在 `reason` |
| `service` | — | 僅用於定位與解釋，不進公式 |

### 2.2 `asset_context.csv`（Minimum Context）

| 欄位 | 必要 | 值域 |
|---|---|---|
| `asset` | ✔ | 唯一，不得重複（重複即拒載） |
| `environment` | ✔（僅解釋用） | `PROD` / `NON_PROD` |
| `reachability` | ✔ | `INTERNET` / `INTERNAL` / `ISOLATED` |
| `control_effectiveness` | ✔ | `NONE` / `PARTIAL` / `STRONG` / `UNKNOWN` |
| `business_criticality` | ✔ | `CRITICAL` / `IMPORTANT` / `NORMAL` |
| `reachability_source`、`control_source`、`business_source` | — | Day 12/13 起由推導流程寫入 |

**這個檔自 Day 12 起不該手寫**，而是由 `cve2action derive-context` 從三份事實檔推導：

```text
assets.csv + controls.csv + business_context.csv  →  asset_context.csv
```

- `assets.csv`：`asset_id, hostname, zone, environment, business_role, declared_criticality, crown_jewel, owner_team`
  （`declared_criticality` 僅供對照，**不進公式**；Day 13 起 criticality 一律推導）
- `controls.csv`：`asset_id, control_type, effectiveness, evidence, verified_at`
- `business_context.csv`：`asset_id, data_class, rto_hours, customer_facing`

### 2.3 `risk_rules.yaml`（Decision Rules，外部化）

基準檔：[`config/risk_rules.yaml`](../../config/risk_rules.yaml)。載入時強制驗證，違反即拒載：

1. `weights` 只能有 `severity` / `threat` / `exposure` / `business` 四鍵，且總和 = 1。
2. 三組值域映射的鍵必須與 §2.2 值域完全一致（不得增刪），數值皆在 0–1。
3. `control_effectiveness.UNKNOWN >= NONE`（**UNKNOWN 不得降低曝險**）。
4. `priority_bands` 必須不重疊且涵蓋 0–10。
5. `cvss.version_preference` 非空、無重複，且只含支援的版本。
6. `exposure.zone_reachability` 的值必須都在 `reachability` 值域內；`control_evidence_max_age_days` 為正整數。
7. `business_impact` 推導出的 criticality 必須都在 `business_criticality` 值域內。
8. `threat.epss_log_base` 為正數、`threat.kev_listed_value` 在 0–1。
9. `controls.applicability` 每項的 `attack_vectors` 非空，且只含 `NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL`。

## 3. 計分模型

### 3.1 公式

```text
S = CVSS / 10                              嚴重度
T = max(EPSS 對數轉換, KEV)                 威脅（Day 14）
E = Reachability × Control Effectiveness   有效曝險
B = Business Impact                        業務衝擊

Priority Score = 10 × (0.35×S + 0.15×T + 0.25×E + 0.25×B)   （四捨五入至小數 2 位）
```

數值映射（來自 risk_rules.yaml，非程式碼常數）：

| Reachability | 值 | Control | 值 | 證據門檻 | Business | 值 |
|---|---:|---|---:|---|---|---:|
| INTERNET | 1.0 | NONE | 1.0 | 無控制，或現有控制不適用 | CRITICAL | 1.0 |
| INTERNAL | 0.6 | PARTIAL | 0.7 | 只有偵測／規則未調校 | IMPORTANT | 0.7 |
| ISOLATED | 0.2 | STRONG | 0.4 | 有針對此攻擊類別的阻擋證據 | NORMAL | 0.4 |
| | | UNKNOWN | 1.0 | 有控制但拿不出證據 | | |

分級（`priority_bands`）：

| Priority | 分數 |
|---|---|
| Critical | 9.0–10.0 |
| High | 7.0–8.99 |
| Medium | 4.0–6.99 |
| Low | 0–3.99 |

**0.35/0.15/0.25/0.25 是起始假設，不是標準答案**；Day 17 以人工排序校準、Day 18 定門檻，
任何權重或門檻變更必須留下 ADR。

### 3.2 缺資料時的退化行為（不補零）

| 缺什麼 | 怎麼做 | 為什麼 |
|---|---|---|
| EPSS 與 KEV 都沒有 | 移除 `T` 項，**權重退回 `severity`** | CVSS 的可利用性指標本來就兼著回答「會不會被利用」；公式退回 Day 5 的 50/25/25 |
| 只有其中一個 | 用有的那個，另一邊記在 `threat_source` | 兩者回答不同問題，取大不取平均 |
| 控制證據過期 | 降為 `UNKNOWN`（係數 1.0），不是 `NONE` | 過期不代表失效，但不能再拿它打折 |
| 控制攔不到這類攻擊 | 降為 `NONE`，`control_source` 註明不適用 | 這是事實，不是未知 |
| 讀不到 CVSS 向量 | 不折減，記為 `UNKNOWN` | 不能證明攔得到，就不能拿它打折 |
| 任何必要 context 缺值 | `NEEDS_CONTEXT`，不評分 | 見 §4 |

### 3.3 控制適用性（Day 15）

一項控制要參與折減，攔截點必須落在這條攻擊路徑上。判斷只讀 CVSS 向量既有的兩格：
`AV`（攻擊從哪裡來）與 `PR`（路徑上有沒有驗證這一關）。結果三態：
`APPLICABLE` / `NOT_APPLICABLE`（事實）/ `UNDECIDABLE`（未知），後兩者都不折減但理由不同。

折減上限 0.4 受一條可測性質約束，並有回歸測試守著：

> **單一控制最多讓一筆 finding 往下移一個分級。**
> 最大折減 `10 × 0.25 × 1.0 × 0.6 = 1.5` 分 < 跨兩級所需的 `9.0 − 6.99 = 2.01` 分。

## 4. NEEDS_CONTEXT 規則

符合下列任一條件的 finding **不評分、不猜預設值**，`decision = NEEDS_CONTEXT`，
`reason` 逐項列出缺口，並固定排在 `ranked_result.csv` 最後（不隱藏）：

- `asset` 在 asset_context.csv 找不到。
- `cvss` 缺值、非數字或超出 0–10，且快照也沒有可用分數。
- `reachability` / `control_effectiveness` / `business_criticality` 缺值或不在值域。

注意：`control_effectiveness = UNKNOWN` **不是** NEEDS_CONTEXT——它是合法值，
代表「有登錄但無法證明有效」，以最保守係數 1.0 計分。威脅資料缺席同理（見 §3.2）。

## 5. 輸出契約：`ranked_result.csv`

欄位順序固定（16 欄）：

```text
asset, cve, cvss, cvss_version, cvss_source,
threat, threat_source,
environment, control_effectiveness, control_source,
effective_exposure, business_criticality,
priority_score, priority, decision, reason
```

- `decision`：`SCORED` 或 `NEEDS_CONTEXT`。
- 排序：`SCORED` 依 `priority_score` 降冪；`NEEDS_CONTEXT` 全部列在最後。
- **每個推導值都帶一個 `*_source`**：分數從哪個版本、哪個評分者來；威脅從 EPSS 還是 KEV
  勝出、落敗的一方是什麼；控制從哪一項、證據哪一天、適不適用。
- `reason`：每列必附，把四個因子的輸入、數值與公式代入結果寫成一句話。

## 5.1 Explanation：輸出的來源（Day 16）

`ranked_result.csv` 的列與 `reason` 字串都不是各自拼出來的，而是同一份 `Explanation` 的投影：

```text
explain_finding() → Explanation ─┬→ row_from()      → CSV 的一列
                                 ├→ .to_reason()    → reason 欄
                                 ├→ .to_dict()      → JSON
                                 └→ explain_row()   → 人讀的多行說明
```

排序同理只實作一次：`rank_explained()` 排 Explanation，`rank()` 是它的列投影。

`Explanation` 帶四樣東西：代入數值的 `formula`、每一項的 `Factor`（值、權重、貢獻、佔比、
原始輸入、來源）、`degraded`（威脅項是否缺席）、以及未評分時的 `gaps`。

`Explanation.gap_to(other)` 把兩筆的分差拆成逐項貢獻差，加總等於總分差——這是回答
「為什麼它排在這裡」的唯一方式，因為那個答案存在於兩列之間，不在任何一列裡面。

```bash
uv run cve2action explain --cve CVE-2020-1472   --scanner ... --context ... --rules ... --snapshots ... --epss ... --kev ... --controls ...
```

加 `--json` 輸出機器可讀格式，`--top N` 說明前 N 名，`--asset` 限定資產。


## 6. 驗收案例（回歸基準，tests/ 已覆蓋）

### 6.1 無威脅資料（Day 5 基準，退化路徑）

| 案例 | 輸入 | 期望 |
|---|---|---|
| Case A | CVSS 9.8、ISOLATED、PARTIAL、NORMAL | **6.25 / Medium** |
| Case B | CVSS 8.8、INTERNET、STRONG、CRITICAL | **7.90 / High** |
| Case B 無控制 | CVSS 8.8、INTERNET、NONE、CRITICAL | **9.40 / Critical** |
| 排序翻轉 | A + B 同時輸入 | B 排在 A 前 |
| UNKNOWN 控制 | UNKNOWN vs NONE 同條件 | 分數相同（不降曝險） |
| 缺 context | scanner 有、context 無的資產 | NEEDS_CONTEXT、列於最後 |

### 6.2 Northstar 全鏈（40 findings / 20 assets）

| 輸入 | 分級分布（Critical/High/Medium/Low） |
|---|---|
| 快照（Day 11–13） | 7 / 23 / 8 / 0 |
| ＋ EPSS、KEV（Day 14） | 8 / 25 / 5 / 0 |
| ＋ 控制適用性（Day 15） | **9 / 24 / 5 / 0** |

兩筆 NEEDS_CONTEXT 固定為 `NS-SHADOW-NAS-02`（清冊外的機器）與
`NS-MAIL-GW-01 / CVE-2011-3389`（NVD 無 v3.1，掃描器也沒給值）。

**Low 恆為 0 是已知缺口**，留給 Day 18 校準。

## 7. 完整流程重現

```bash
uv sync

# 1. 從三份事實檔推導 asset_context（不要手寫這個檔）
uv run cve2action derive-context \
  --assets data/synthetic/northstar/assets.csv \
  --controls data/synthetic/northstar/controls.csv \
  --business data/synthetic/northstar/business_context.csv \
  --rules config/risk_rules.yaml --as-of 2026-09-24 \
  --out data/synthetic/northstar/asset_context.csv

# 2. 全鏈評分（快照全部離線，不需要網路）
uv run cve2action rank \
  --scanner data/synthetic/northstar/scanner.csv \
  --context data/synthetic/northstar/asset_context.csv \
  --rules config/risk_rules.yaml \
  --snapshots data/snapshots/nvd --epss data/snapshots/epss --kev data/snapshots/kev \
  --controls data/synthetic/northstar/controls.csv --as-of 2026-09-24 \
  --out ranked_result.csv
```

Day 6 的最小示範（只有三個輸入）：

```bash
uv run cve2action rank --scanner data/synthetic/day-06-scanner.csv \
  --context data/synthetic/day-06-asset-context.csv \
  --rules config/risk_rules.yaml --out ranked_result.csv
```

## 8. 變更歷程

| 版本 | Day | 變更 | ADR |
|---|---|---|---|
| 0.1.0 | 5–6 | 三項公式 50/25/25、NEEDS_CONTEXT、值域外部化 | [ADR-day-05](../decisions/ADR-day-05-decision-engine-v01.md) |
| 0.1.1 | 8 | CVSS 版本偏好 + NVD 自評優先；輸出加 `cvss_version` / `cvss_source` | [ADR-day-08](../decisions/ADR-day-08-cvss-version-preference.md) |
| 0.2.0 | 12 | Reachability 由 Zone 推導、控制證據 90 天過期降 UNKNOWN、多控制取最強 | [ADR-day-12](../decisions/ADR-day-12-effective-exposure.md) |
| 0.2.0 | 13 | criticality 改由三項業務事實推導，取最嚴重；`declared_criticality` 僅供對照 | [ADR-day-13](../decisions/ADR-day-13-business-impact.md) |
| 0.2.0 | 14 | 加入第四項 `T`，權重改 0.35/0.15/0.25/0.25；無資料時退回 severity | [ADR-day-14](../decisions/ADR-day-14-threat-enrichment.md) |
| 0.3.0 | 15 | 控制適用性先於強度；輸出加 `control_effectiveness` / `control_source` | [ADR-day-15](../decisions/ADR-day-15-control-calibration.md) |
| 0.3.1 | 16 | Explanation 成為計分的第一級產物，列與理由改為其投影；`engine` 移入 `scoring/` | [ADR-day-16](../decisions/ADR-day-16-explain-api.md) |

## 9. 非目標（目前明確不做）

- 反事實（「我改什麼能降幾分」）。`gap_to` 回答的是「和它比差在哪」，
  不是「改了會變成多少」；後者要有成本模型才有意義，留給 Day 26–27。
- 評分門檻與人工排序校準（Day 17–18）。
- 資產歸併（多 IP → 同一 asset）、漏洞適用性閘門（藍圖 §9.0；目前假設 scanner.csv 已是歸併後結果）。
- 控制與弱點類別的對應（目前 AV/PR 判斷不了協定層，例如 WAF 對 TLS 層的 RC4 降級）。
- 攻擊路徑、圖形模型、Choke Point（Day 19–24）。
- 修補建議與 What-if（Day 25–27）。
- Dashboard（Day 28）。
- 自動修補、Ticket 整合、LLM 決策。
