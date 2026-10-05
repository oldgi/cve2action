# Decision Engine 開發規格

| 欄位 | 內容 |
|---|---|
| 規格版本 | 0.4.0（`config/risk_rules.yaml` 為 `0.4.0`、`config/acceptance.yaml` 為 `0.2.0`） |
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

1. `weights` 必須有 `severity` / `threat` / `exposure` / `business` 四鍵，`path` 可選
   （Day 23 起 production 使用它；`risk_rules.v0.1.yaml` 沒有，所以它是可選而非必填），總和 = 1。
2. `form` 只能是 `additive` 或 `geometric`，省略時為 `additive`（見 §3.3）。
3. 三組值域映射的鍵必須與 §2.2 值域完全一致（不得增刪），數值皆在 0–1。
4. `control_effectiveness.UNKNOWN >= NONE`（**UNKNOWN 不得降低曝險**）。
5. `priority_bands` 必須不重疊且涵蓋 0–10。
6. `cvss.version_preference` 非空、無重複，且只含支援的版本。
7. `exposure.zone_reachability` 的值必須都在 `reachability` 值域內；`control_evidence_max_age_days` 為正整數。
8. `business_impact` 推導出的 criticality 必須都在 `business_criticality` 值域內。
9. `threat.epss_log_base` 為正數、`threat.kev_listed_value` 在 0–1。
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

| Priority（內部） | 分數 | Tier（對外） | 處置原則 |
|---|---|---|---|
| Critical | 9.0–10.0 | P0 | 緊急評估與處理 |
| High | 7.0–8.99 | P1 | 納入下一個修補窗口 |
| Medium | 4.0–6.99 | P2 | 排程處理或補強控制 |
| Low | 0–3.99 | P3 | 監控、接受或定期複核 |

`label` 是 0–10 內部刻度（所有回歸基準都用它），`tier` 是對外的處置層級，語彙與藍圖 §9.5 一致。
門檻沿用 9.0／7.0／4.0，**未採用藍圖為 CRPS 乘法模型訂的 80/60/35**——實測套用後 38 筆中
有 21 筆 P0，與 P0「緊急評估與處理」的定義矛盾。見
[ADR-day-18（二）](../decisions/ADR-day-18-crps-tier-mapping.md)。

**權重是起始假設，不是標準答案**；Day 17 以人工排序校準、Day 18 定門檻，
任何權重或門檻變更必須留下 ADR。Day 23 起為 `0.28/0.12/0.20/0.20/0.20`（含第五項 `path`）；
Day 5–18 的已發表數字以 [`config/risk_rules.v0.1.yaml`](../../config/risk_rules.v0.1.yaml)
（`0.3.0`，四項）重現。

### 3.3 第五項 `A`（攻擊路徑分數）與合成形式（Day 23）

`A` 照藍圖 §9.3 拆四項，由 Day 19–22 建好的圖算出，不新增人工輸入：

```text
A = 0.40·A_Reachability + 0.25·A_Privilege + 0.25·A_CrownJewel + 0.10·A_Hops
```

| 項 | 來源 | 定義 |
|---|---|---|
| `A_Reachability` | 路徑搜尋 | 有 Internet 可達路徑＝1.0，查無＝**0.05**（下限，非 0） |
| `A_Privilege` | Day 21 `privilege_obtainable` | 權限等級正規化到 0–1 |
| `A_CrownJewel` | 路徑搜尋 | 自己是或走得到 Crown Jewel＝1.0，否則 0 |
| `A_Hops` | 最短路徑長度 | `1 / 跳數` |

合成形式由 `form` 決定，兩種都已實作：

| `form` | 公式 | 狀態 |
|---|---|---|
| `additive` | `10 × Σ wᵢvᵢ` | **production**（`config/risk_rules.yaml`） |
| `geometric` | `10 × Π max(vᵢ, 0.05)^wᵢ` | 保留對照（`config/risk_rules.geometric.yaml`），CI 不跑、測試跑 |

幾何平均的指數和為 1，所以它是**加權幾何平均而非連乘**；下限 0.05 與藍圖 §9.5 的
`max(A, 0.05)` 取同一個數，路徑項最差只能把分數打到約一半，不是一票否決。

採用加法的依據是 `acceptance` 的 `attributable` 門檻（加權相加 37/37、幾何平均 0/37）：
幾何平均下總分不是各項之和，`Explanation.gap_to()` 答不出「為什麼它排在我前面」。
兩種形式的 tau 與分歧清單完全相同，所以校準量不出形式的好壞。
重新打開這個決定的條件見 [ADR-day-23](../decisions/ADR-day-23-formula-form.md)。

### 3.2 缺資料時的退化行為（不補零）

| 缺什麼 | 怎麼做 | 為什麼 |
|---|---|---|
| EPSS 與 KEV 都沒有 | 移除 `T` 項，**權重退回 `severity`** | CVSS 的可利用性指標本來就兼著回答「會不會被利用」；公式退回 Day 5 的 50/25/25 |
| 只有其中一個 | 用有的那個，另一邊記在 `threat_source` | 兩者回答不同問題，取大不取平均 |
| 控制證據過期 | 降為 `UNKNOWN`（係數 1.0），不是 `NONE` | 過期不代表失效，但不能再拿它打折 |
| 控制攔不到這類攻擊 | 降為 `NONE`，`control_source` 註明不適用 | 這是事實，不是未知 |
| 讀不到 CVSS 向量 | 不折減，記為 `UNKNOWN` | 不能證明攔得到，就不能拿它打折 |
| 沒有攻擊圖資料 | 移除 `A` 項，**權重退回 `exposure`** | 補零等於宣告「走不到」，而我們只是沒查 |
| 有圖但查無路徑 | `A_Reachability` 取下限 0.05 | Day 22：六台查無路徑沒有一台是被擋住的 |
| 權限無法證明 | 移除 `A_Privilege`，權重退回可達性 | 不猜中間值；可達性是唯一一定知道的項 |
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

欄位順序固定（17 欄）：

```text
asset, cve, cvss, cvss_version, cvss_source,
threat, threat_source,
environment, control_effectiveness, control_source,
effective_exposure, business_criticality,
priority_score, priority, priority_tier, decision, reason
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

**Low 恆為 0 不是公式缺陷**（Day 18 更正）：合成探針顯示四個分級都構造得出來，
例如 `CVSS 5.5 / ISOLATED / STRONG / NORMAL → 3.95 Low`。Northstar 沒有 Low，
是因為它沒有「低嚴重度 × 隔離 × 不重要」的組合。詳見 [ADR-day-18](../decisions/ADR-day-18-scoring-acceptance.md)。

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
| 0.3.2 | 17–18 | 校準基準與分歧解釋；八條評分門檻與豁免機制，v0.1 baseline 凍結 | [ADR-day-17](../decisions/ADR-day-17-calibration-test.md)、[ADR-day-18](../decisions/ADR-day-18-scoring-acceptance.md) |
| 0.3.3 | 18 | 對外新增 P0–P3 處置層級；CRPS 乘法模型延後至 Day 23 決定 | [ADR-day-18（二）](../decisions/ADR-day-18-crps-tier-mapping.md) |
| 0.4.0 | 23 | 第五項 `A`（§9.3）進入公式，權重 `0.28/0.12/0.20/0.20/0.20`；`form` 支援 `additive`／`geometric`，**採用 additive**；門檻第九條 `attributable`；豁免到期日改 ISO 並強制比對 | [ADR-day-23](../decisions/ADR-day-23-formula-form.md) |

## 8.1 評分門檻

「可用」的定義在 [`config/acceptance.yaml`](../../config/acceptance.yaml)，**九條**，分兩種：

- **structural**（3 條）——公式本身的性質，用合成探針驗證，與資料集無關：
  四個分級都構造得出來、缺資料不得讓分數變低、任一因子單獨變大分數不得下降。
- **empirical**（6 條）——在 Northstar 上量：完整可解釋性、**逐項歸因**、分辨力、
  分級平衡、值域利用、頂端飽和。

Day 23 的現況（rules `0.4.0`）：7 通過、2 豁免（`band_balance` 0.5263、`range_coverage` 0.443）、
0 阻擋。Day 18 發表的 6/8（`0.6316`／`0.44`）以
[`config/acceptance.v0.1.yaml`](../../config/acceptance.v0.1.yaml) 重現。

Day 23 修掉門檻自己的三個缺陷：

1. `explainable` 只數因子個數與來源，**從不檢查分解加不加得回分數**——所以它給
   幾何平均滿分。已補上重建檢查。
2. 新增 `attributable`（§3.3）。Day 16 做 `gap_to` 是這個專案最核心的對外承諾，
   Day 18 的八條沒有一條看守它。
3. `revisit_on` 原本接受 `Day 20` 這種字串，程式只檢查非空——那是**永久豁免**。
   現在必須是 ISO 日期，過期即阻擋（`--today` 可指定判斷日，預設今天）。

```bash
uv run cve2action acceptance --scanner ... --context ... --rules ... --criteria config/acceptance.yaml
```

沒過又沒有**有效** waiver 即 exit 1；CI 每次都跑。`waivers` 缺 `reason`、`revisit_on`，
或 `revisit_on` 不是 ISO 日期，會被拒絕載入。報表會印出實際載入的 rules 版本，
與門檻檔宣告的 `applies_to_rules_version` 不符時出聲——否則量的是上一版的標準。

CI 的 `calibrate` 與 `acceptance` 都必須餵攻擊圖輸入（`--assets/--interfaces/--services/
--network/--identity/--policies/--findings`）。不給，引擎會移除 `A` 項，量到的是上一版的模型。

## 9. 非目標（目前明確不做）

- 反事實**分數**（「我改什麼能降幾分」）。Day 24 已經有反事實**路徑**
  （`find_paths(without=)`、`choke.analyse`）：移除一台之後還剩幾條路徑算得出來，
  但分數不會跟著重算。那要有成本模型才有意義，留給 Day 26–27。
- 評分門檻與人工排序校準（Day 17–18）。
- 資產歸併（多 IP → 同一 asset）、漏洞適用性閘門（藍圖 §9.0；目前假設 scanner.csv 已是歸併後結果）。
- 控制與弱點類別的對應（目前 AV/PR 判斷不了協定層，例如 WAF 對 TLS 層的 RC4 降級）。
- ~~攻擊路徑、圖形模型、Choke Point（Day 19–24）~~ **已完成**。
  路徑分數 `A` 已進公式（§3.3）；瓶頸分析見
  [ADR-day-24](../decisions/ADR-day-24-choke-point.md)。
- 修補建議與 What-if（Day 25–27）。
- Dashboard（Day 28）。
- **CRPS 乘法模型**（藍圖 §9.5 的 `100 × L^0.45 × I^0.35 × A^0.20 × (1−0.6C)`）。
  對外層級 P0–P3 已接上，但分數仍是 0–10 的加法 baseline；`L`／`I` 的子因子
  （`E_CVSS`、`B_CIA`、`B_Blast`）目前沒有資料來源，硬做就是補零。
- **§9.6 的規則覆寫**（「KEV ＋ Internet 可達 ＋ 存在有效攻擊路徑 → 至少 P0」）。
  三個輸入從 Day 23 起**全部都有了**（KEV 在 `threat_source`、可達性與有效路徑在
  `A_Reachability`），ADR-day-18（二）當時也說接上 `tier` 就是為了讓這條寫得出來。
  但它至今沒有實作，而且 §10 的 Day 25–30 沒有任何一天負責它——
  這是一個**已知且尚未排程**的缺口，不是刻意的非目標。待排。
- 自動修補、Ticket 整合、LLM 決策。
