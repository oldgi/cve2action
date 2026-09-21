# 版本紀錄

本專案採用 [Semantic Versioning](https://semver.org/)；重要設計異動另以 ADR 保存原因。

## [Unreleased]

### Added

- 統一 CVSS 模型（`normalization/cvss.py`）：v3.1 與 v4.0 並存，每筆分數保留版本、vector、評分者與 Primary/Secondary，不做跨版本換算；版本偏好外部化至 `risk_rules.yaml`（`cvss.version_preference`），變更記錄於 ADR-day-08。
- `cve2action rank --snapshots`：以 NVD 快照的分數取代掃描器手填值，輸出新增 `cvss_version`、`cvss_source`；不一致時 `reason` 註明 `scanner said`，NVD 未評分時退回掃描器值，皆無則 `NEEDS_CONTEXT`。
- 快照改從 `raw` 重新解析，`fetch-cve --reparse` 可不重抓即更新投影；新增 CVE-2025-21590（v3.1/v4.0 並存）與 CVE-2024-6242（僅 v4.0）快照、Day 8 模擬資料與 36 個測試。
- 新增 NVD Collector（`cve2action fetch-cve`）：快照同時保存抽取欄位與原始回應，附來源網址與取得時間；預設讀快照可離線重跑，缺 v3.1 分數維持 UNKNOWN 不填零。
- 新增 5 份帶日期的 NVD 快照（Day 6 模擬資料所用 CVE）與 12 個離線測試；實測發現 CVE-2022-41082 手填 8.8 與 NVD 8.0（AV:A/PR:L）不符，留待 Day 8 統一 CVSS 模型後修正。
- 建立 Python 專案骨架：`pyproject.toml`（uv 管理相依）、`src/cve2action/` 套件、pytest 測試、Ruff 設定與 GitHub Actions CI。
- 實作 Decision Engine v0.1 Vertical Slice：`scanner.csv + asset_context.csv + risk_rules.yaml → ranked_result.csv`，含 CLI（`cve2action rank`）。
- 權重與值域映射外部化至 `config/risk_rules.yaml`；載入時驗證權重和為 1、值域完整，且 `UNKNOWN` 控制不得降低曝險。
- 缺少必要企業脈絡的 finding 標為 `NEEDS_CONTEXT`，不評分、不猜預設值，固定列於輸出最後。
- 新增 Day 6 模擬資料（Northstar 虛構環境）與 22 個回歸測試，涵蓋 Day 5 Case A（6.25/Medium）、Case B（7.90/High）與無控制版（9.40/Critical）的排序翻轉基準。
- 新增《Decision Engine v0.1 開發規格》（docs/architecture/decision-engine-v0.1-spec.md），凍結 I/O 契約、公式、值域與驗收案例。

- 加入新版 Day 2 封面及使用者提供的重新排序內文圖，更新文章引用並說明圖中條件式排序的前提；保留原有主視覺以利回顧。
- 新增 Day 2 固定歷史情境設定、CSV 一致性檢查與手動更新說明。
- 新增 ADR-0003：決策輸出區分修補、緩解、審查與條件式暫緩。
- 新增 Day 2「CVSS 9.8，真的就該第一個修嗎？」研究型草稿。
- 新增 Day 2 案例設計與查核備忘錄，保存公開事實、虛構條件及推論邊界。
- 新增 Day 2 資產與弱點發現模擬資料。
- 新增 Day 2 的 16:9 情境式修補優先序主視覺，保存高畫質 PNG 與文章上傳用 JPEG。

### Changed

- 依使用者修訂納入資產負責團隊、相容性限制、控制驗證日期、SLA、風險接受與重評條件。
- Day 2 結論改為「B 先緩解、A 同步審查」；不再預設 B 可零衝擊升級，或 A 已獲批准暫緩。
- Day 2 資料契約升為 0.2.0：移除 exploitation_scale，拆分利用／針對性／掃描證據；區分當日行動期限與正式修補期限。
- 補上共用跳板與受限掃描關係、歷史情境時點及未知值邊界，更新文章、備忘錄與總體施工藍圖。
- 案例比較改為「兩者均有實際利用訊號」，以有效可達性、資產角色、控制證據、條件式攻擊路徑與修補成本說明排序可能翻轉。
- 明確區分 CVSS Base Score、CVSS 環境指標與企業修補優先序，避免將 CVSS 描述成完全不含環境情境。

## [0.1.2] - 2026-09-16

### Added

- 新增 Day 1「弱掃清單與修補決策困境」16:9 文章主視覺。
- 保存高畫質 PNG 與文章上傳用 JPEG。

### Changed

- Day 1 結尾明確標示 Day 2 將採用真實 CVE 公開資料與完全虛構的企業情境。
- Day 2 預告案例確認為 CVE-2022-26134 與 CVE-2020-6820。

## [0.1.1] - 2026-09-15

### Added

- 新增 Day 1 可發布草稿，改以企業真實決策困難建立系列問題意識。
- 新增 ADR-0002，定義風險評分前的資產歸併、漏洞適用性與有效可達性閘門。
- 模擬資料加入多 IP 資產、掃描觀測、版本證據、服務狀態與網路政策。

### Changed

- 處理流程由「Finding 直接評分」改為「觀測資料正規化與驗證後再評分」。
- 未知版本或關鍵情境資料改標示為 `REVIEW_REQUIRED`，不得自動視為低風險。

## [0.1.0] - 2026-09-15

### Added

- 建立 CVE2Action 專案定位與邊界。
- 建立 30 天文章與系統開發雙軌施工計畫。
- 定義最終系統架構與技術選型。
- 定義可公開模擬資料集與四個驗證情境。
- 建立 Contextual Remediation Priority Score 初版公式。
- 建立 GitHub 專案結構、里程碑、驗收條件與風險清單。
- 建立 ADR-0001，確認本專案是弱掃後處理決策引擎，而非新弱掃器。
