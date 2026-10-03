# CVE2Action

> 從 CVE 堆到修補優先序：教弱掃工具算出真實風險的 30 天

弱掃報告告訴你哪裡有洞，不告訴你先修哪一個。CVE2Action 接收弱掃、資產、威脅情報與控制措施資料，
算出**可解釋的**修補優先序：每一筆都說得出為什麼排在這裡、每個數字從哪來、哪裡還不知道。

這個儲存庫同時是 2026 iThome 鐵人賽系列的程式與文章來源。

## 目前狀態

| 項目 | 內容 |
|---|---|
| 版本 | `0.2.0`（已發行 `v0.2.0-data`）；`v0.3.0-scoring` 門檻已通過（Day 18） |
| 進度 | Day 1–16 已發表，17–18 待發；做評分階段（Day 11–18）完成 |
| Decision Rule | `config/risk_rules.yaml` 版本 `0.3.0` |
| 規模 | 318 個測試、Northstar 模擬資料 20 資產 / 40 findings / 25 連線 |
| 最近修訂 | 2026-10-03 |

施工五階段：定邊界（Day 1–5）→ 接資料（6–10）→ **做評分（11–18）** → 畫攻擊路徑（19–24）→ 給修補建議（25–30）

## 快速開始

需求：Python 3.12+ 與 [uv](https://docs.astral.sh/uv/)。

```bash
uv sync
uv run pytest
```

最小示範（Day 6 的三個輸入，六筆 finding）：

```bash
uv run cve2action rank \
  --scanner data/synthetic/day-06-scanner.csv \
  --context data/synthetic/day-06-asset-context.csv \
  --rules config/risk_rules.yaml \
  --out ranked_result.csv
```

完整流程（Northstar 虛構企業，含 NVD 快照、EPSS、KEV 與控制適用性；全部離線，不需網路）：

```bash
# 1. 從三份事實檔推導 asset_context——這個檔不該手寫
uv run cve2action derive-context \
  --assets data/synthetic/northstar/assets.csv \
  --controls data/synthetic/northstar/controls.csv \
  --business data/synthetic/northstar/business_context.csv \
  --rules config/risk_rules.yaml --as-of 2026-09-24 \
  --out data/synthetic/northstar/asset_context.csv

# 2. 全鏈評分
uv run cve2action rank \
  --scanner data/synthetic/northstar/scanner.csv \
  --context data/synthetic/northstar/asset_context.csv \
  --rules config/risk_rules.yaml \
  --snapshots data/snapshots/nvd --epss data/snapshots/epss --kev data/snapshots/kev \
  --controls data/synthetic/northstar/controls.csv --as-of 2026-09-24 \
  --out ranked_result.csv
```

輸出 `ranked_result.csv` 每列附 Priority Score、分級與可解釋的 `reason`，且**每個推導值都帶一個
`*_source`**。缺少必要企業脈絡的項目標為 `NEEDS_CONTEXT`，不評分也不猜預設值，固定列在最後。

## 設計原則

1. **UNKNOWN 不得降低風險。** 不知道不等於沒有；缺資料時移除該項或退回更保守的假設，絕不補零。
2. **每個推導值都要說得出來源。** 分數從哪個 CVSS 版本、哪個評分者；威脅從 EPSS 還是 KEV 勝出；
   控制從哪一項、證據哪一天、適不適用。
3. **權重與值域外部化。** 全部在 `risk_rules.yaml`，程式裡沒有魔術數字；改動必須留下 ADR。
4. **分數只用於排序。** 不宣稱事故機率或財務損失。LLM 不參與任何決策計算。
5. **宣告值不進公式。** 人工標記的 `declared_criticality` 只供對照，進公式的一律是推導值。

## 文件入口

**規格與決策**

- [30 天總體施工藍圖](CVE2Action-30天總體施工藍圖.md)（根目錄這份是現行版）
- [Decision Engine 開發規格](docs/architecture/decision-engine-v0.1-spec.md)——公式、I/O 契約、退化行為、變更歷程
- [資料契約](data/schemas/README.md)——六份 CSV 的欄位、值域與缺值語意
- [版本紀錄](CHANGELOG.md)

**架構決策（ADR）**

| ADR | 主題 |
|---|---|
| [ADR-0001](docs/decisions/ADR-0001-專案定位.md) | 專案定位 |
| [ADR-0002](docs/decisions/ADR-0002-評分前置閘門.md) | 評分前置閘門 |
| [ADR-0003](docs/decisions/ADR-0003-條件式行動決策.md) | 決策輸出區分修補、緩解、審查與條件式暫緩 |
| [ADR-day-05](docs/decisions/ADR-day-05-decision-engine-v01.md) | Decision Engine v0.1 與 Minimum Context |
| [ADR-day-08](docs/decisions/ADR-day-08-cvss-version-preference.md) | CVSS 版本偏好與評分者取用順序 |
| [ADR-day-12](docs/decisions/ADR-day-12-effective-exposure.md) | 有效曝險：Zone 推導與證據有效期 |
| [ADR-day-13](docs/decisions/ADR-day-13-business-impact.md) | 業務衝擊由可查證事實推導 |
| [ADR-day-14](docs/decisions/ADR-day-14-threat-enrichment.md) | EPSS 與 KEV 進入公式，取大不取平均 |
| [ADR-day-15](docs/decisions/ADR-day-15-control-calibration.md) | 控制措施的適用性先於強度 |
| [ADR-day-16](docs/decisions/ADR-day-16-explain-api.md) | 理由是計分的產物，不是計分後的字串 |
| [ADR-day-17](docs/decisions/ADR-day-17-calibration-test.md) | 校準的產出是分歧清單，不是相關係數 |
| [ADR-day-18](docs/decisions/ADR-day-18-scoring-acceptance.md) | v0.1 評分門檻與明確不修的部分 |
| [ADR-day-18（二）](docs/decisions/ADR-day-18-crps-tier-mapping.md) | 對外用 P0–P3，CRPS 乘法模型延後 |

**文章**（`docs/articles/`，Day 01–15 皆在此）

| 階段 | 文章 |
|---|---|
| 定邊界 | [Day 1](docs/articles/day-01.md)・[2](docs/articles/day-02.md)・[3](docs/articles/day-03.md)・[4](docs/articles/day-04.md)・[5](docs/articles/day-05.md) |
| 接資料 | [Day 6](docs/articles/day-06.md)・[7](docs/articles/day-07.md)・[8](docs/articles/day-08.md)・[9](docs/articles/day-09.md)・[10](docs/articles/day-10.md) |
| 做評分 | [Day 11](docs/articles/day-11.md)・[12](docs/articles/day-12.md)・[13](docs/articles/day-13.md)・[14](docs/articles/day-14.md)・[15](docs/articles/day-15.md)・[16](docs/articles/day-16.md)・[17](docs/articles/day-17.md)・[18](docs/articles/day-18.md) |

**番外篇**：[風險公式不是找出來的，是長出來的](docs/articles/extra-01-formula-evolution.md)——公式為何會演化，以及加法／幾何平均之外還有哪些形式。

**研究備忘**：[Day 2 案例設計](docs/research/day-02-case-design.md)、[Day 3 概念與邊界](docs/research/day-03-concepts-and-boundaries.md)

## 專案結構

```text
src/cve2action/
├── collectors/      NVD、EPSS、KEV——一律落成帶日期的快照，可離線重跑
├── normalization/   cvss、exposure、business、threat、control——把事實變成可進公式的值
├── engine.py        評分與排序
├── rules.py         載入並驗證 risk_rules.yaml，違反即拒載
├── io.py / models.py / cli.py
config/risk_rules.yaml    權重、值域、分級、控制適用範圍
data/schemas/             資料契約（CI 強制驗證）
data/snapshots/           NVD / EPSS / KEV 的固定快照
data/synthetic/northstar/ 虛構企業資料集，可由 scripts/build_northstar.py 重建
  資產 20／findings 40／控制 8／Crown Jewel 4／網路連線 25／帳號關係 10／候選措施 15
  介面 30（併成 20 台）／服務 28／ACL 政策 16
```

兩處與藍圖 §12 的命名差異，是刻意保留的既成事實，改名會打斷既有連結：
`docs/research/`（藍圖寫 `docs/methodology/`）、`ADR-0001`～`0003` 採中文檔名
（Day 5 之後改為 `ADR-day-NN-english-slug`）。

## 檢查與重現

```bash
uv run ruff check .                        # 風格
uv run pytest                              # 測試
uv run python scripts/validate_day02.py    # Day 2 靜態案例契約（版本 0.2.0，獨立計算）
uv run python scripts/validate_schemas.py  # 資料契約
uv run python scripts/build_northstar.py   # 重建模擬資料集，輸出應逐位元組相同
```

CI 每次 push 都會跑上述全部，另外加跑完整流程並以 `git diff --exit-code` 確認
重跑結果與版控完全一致。

## 版本管理方式

- `main`：可回顧的穩定基線。
- `feature/day-NN-*`：每日文章或功能；`chore/*`、`fix/*` 用於維護性變更。
- Commit 採 Conventional Commits，一次只表達一個可說明的改變。
- 重要取捨以 ADR 記錄，不只記錄改了什麼，也保留當時為什麼這樣決定。

| Tag | 內容 | 狀態 |
|---|---|---|
| `v0.1.0-blueprint` | 總體施工藍圖 | ✅ |
| `v0.1.1-context-gates` | 資產歸併、適用性及可達性閘門 | ✅ |
| `v0.1.2-day1-release` | Day 1 定稿與文章主視覺 | ✅ |
| `v0.2.0-data` | 資料管線與模擬資料（Day 11） | ✅ |
| `v0.3.0-scoring` | 可解釋風險評分（Day 18） | 進行中 |
| `v0.4.0-attack-graph` | 攻擊路徑分析（Day 24） | — |
| `v0.5.0-remediation` | 修補決策與 What-if（Day 27） | — |
| `v1.0.0-ironman` | 30 天文章與完整展示（Day 30） | — |

## 聲明

CVE2Action 不重新掃描主機，也不取代既有弱點掃描產品。

Northstar Digital Services 與其所有資產、網段、業務設定**全部虛構**，不含任何真實企業資訊。
CVE、CVSS、EPSS、KEV 為公開資料，以帶日期的快照保存於 `data/snapshots/`。

授權：[MIT](LICENSE)。
