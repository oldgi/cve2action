# 版本紀錄

本專案採用 [Semantic Versioning](https://semver.org/)；重要設計異動另以 ADR 保存原因。

## [Unreleased]

### Added

- 新增 `src/cve2action/scoring/` 套件與 `scoring/explain.py`：`Explanation` 成為計分的第一級產物，`ranked_result.csv` 的列、`reason` 欄、JSON 與人讀說明全是它的投影——與快照 `raw`／`extracted` 同一條紀律，字串不可能再與數字不一致。每個 `Factor` 帶值、權重、貢獻、佔比、原始輸入與來源；`gap_to()` 把兩筆的分差拆成逐項貢獻差，加總等於總分差。新增 CLI `cve2action explain`（`--cve`／`--asset`／`--top`／`--json`，自動附上與前一名的差距）與 15 個測試，其中一個會把每一列 `reason` 裡的數字全部抓出來逐一驗證它存在於 Explanation 中。ADR-day-16 記錄規則。
- 新增 `data/schemas/`：六份 CSV 的資料契約（欄位、值域、缺值語意、誰寫誰讀），以 `scripts/validate_schemas.py` 強制驗證並納入 CI。附四個反向測試證明契約抓得到違規——欄位值超出值域、該填未填、多出未宣告欄位、少掉必要欄位。
- CI 新增三個步驟守住「文件寫的完整流程真的跑得起來」：Northstar 的 `derive-context`、含快照與威脅情報與控制的全鏈 `rank`，以及 `git diff --exit-code` 確認離線重跑與版控結果完全相同。
- 新增 `LICENSE`（MIT），對齊 `pyproject.toml` 既有的授權宣告。
- README 全面更新：目前狀態與進度、設計原則五條、完整流程指令、ADR 與文章總表、專案結構，以及與藍圖 §12 兩處刻意保留的命名差異（`docs/research/`、`ADR-0001`～`0003` 中文檔名）。
- 新增 `normalization/control.py`：控制措施的**適用性先於強度**。一項控制要參與折減，得先證明攔截點落在這條攻擊路徑上，判斷只讀 CVSS 向量既有的 AV（攻擊從哪來）與 PR（路徑上有沒有驗證這一關），不新增人工欄位。結果採三態：APPLICABLE（套用強度）、NOT_APPLICABLE（已知攔不到，是事實）、UNDECIDABLE（讀不到向量，是未知）；後兩者都不折減但 `control_source` 記錄不同理由。適用範圍外部化於 `controls.applicability`，新增 `rank --controls/--as-of` 與 31 個測試，ADR-day-15 記錄規則。
- 新增 `normalization/threat.py`：Threat 由 EPSS 與 KEV 推導——EPSS 先做對數轉換（`ln(1+99p)/ln(1+99)`）把偏斜的低端拉開，再與 KEV（收錄＝1.0）**取最大值**而非平均，因為兩者回答的不是同一個問題（EPSS 預測未來三十天的廣度，KEV 記錄過去已確認的事實）；`threat_source` 記錄勝出來源與落敗的一方（例 `kev:LISTED (over epss:0.0171)`）。完全沒有威脅資料時不補零，威脅項整個移除。ADR-day-14 記錄規則。
- 新增 `normalization/business.py` 與 `business_context.csv`：Business Criticality 改由三項可查證事實推導（`data_class`、`rto_hours`、`customer_facing`），多維度取最嚴重者而非平均，缺事實則報錯；輸出新增 `business_source` 說明哪個維度勝出。ADR-day-13 記錄規則。
- 新增 `normalization/exposure.py`：Reachability 由 Zone 推導（`risk_rules.yaml` 的 `exposure.zone_reachability`，可被觀測值覆寫）、Control Effectiveness 由 `controls.csv` 推導並套用證據有效期；每個值附 `reachability_source`／`control_source` 說明來源。新增 CLI `cve2action derive-context` 與 23 個測試，ADR-day-12 記錄規則。

### Removed

- 刪除 `docs/images/day-12-evidence-typo-unkrown.png`（UNKROWN 拼錯、發表前已被取代）與五個 CVE 的九份快照（`CVE-2016-2183`、`CVE-2019-11510`、`CVE-2022-1388`、`CVE-2023-27997`、`CVE-2024-3400`）——Day 11 裁減 Northstar findings 後的殘留，repo 內無任何引用。

### Fixed

- `docs/articles/day-04.md` 引用三張從未產出的圖（`day-04-visible-vs-context`／`-context-rabbit-hole`／`-v01-portrait`）：Day 4 最後改用一張八格長圖 `day04-infographic.png`，文章沒跟著改，repo 版本破圖至今（已發表版不受影響）。現改為引用長圖，並補上一直存在卻沒被引用的封面 `day04-fig1-cover.png`；另外兩處的圖說保留原文、改為引言樣式。`day-04-visual-captions.md` 標註為規劃稿並記錄實際落點。
- `cve2action derive-context` 自 Day 13 起產出的 `business_criticality` 整欄為空：Day 13 把 criticality 移出 `assets.csv`（更名 `declared_criticality`）改由 `business_context.csv` 推導，但 `derive_asset_context` 仍讀舊欄位，CLI 也沒有對應輸入。照文件流程產出的 context 接回 `rank` 會整批變成 NEEDS_CONTEXT。當時測試只覆蓋函式層且自行補上 criticality，因此未被發現。現已新增三個走 CLI 的測試，其中一個斷言輸出與版控中的 `asset_context.csv` 逐位元組相同。

### Changed

- `engine.py` 移入 `scoring/`（藍圖 §12），與 `explain.py` 同層；`models.py`、`rules.py`、`io.py` 留在套件根目錄，因為攻擊路徑與修補建議也要用。舊路徑 `from cve2action.engine import rank` 保留相容層。排序只實作在 `rank_explained()` 一次，`rank()` 是它的列投影，兩者不可能排出不同順序。輸出內容完全不變。
- **破壞性變更**：`cve2action derive-context` 新增必填參數 `--business`（業務脈絡 CSV），輸出新增 `business_source` 欄；某資產缺業務事實時以 exit code 2 中止，不再靜默產出空值。
- 施工藍圖收斂為根目錄一份：`docs/` 底下那份停留在 Day 5 之前，Day 6 起日程整個錯開一天，而 README 的文件入口正指向它。其獨有的第 20 節（Day 2 設計修訂，含 Day 10/18/24/30 補充驗收）先併入現行版後才刪除。
- 《Decision Engine 開發規格》由凍結在 Day 6 的狀態更新為追蹤現況：四項公式、16 欄輸出、缺資料退化行為表、`derive-context` 流程、對照 ADR 的變更歷程，以及先前未寫在任何地方的完整流程重現指令。
- Control Effectiveness 由資產層改為逐筆推導：Northstar 38 筆評分中 9 筆維持折減、5 筆撤銷（3 筆網段隔離對 `AV:L`、2 筆驗證類控制對 `PR:N`），分布由 8/25/5 變 9/24/5；Zerologon 由 8.10 High 回到 9.00 Critical，同一台 AD DC 上的 PrintNightmare 仍保有折減（7.68 High）。`derive-context` 產出的資產層視圖維持 Day 12 行為不變。
- 折減上限 0.4 綁定一條可測性質並加上回歸測試：單一控制最多讓一筆 finding 往下移一個分級（最大折減 1.5 分 < 跨兩級所需的 2.01 分）。`control_effectiveness` 四級改以證據門檻定義，不再只是三個數字。
- `ranked_result.csv` 新增 `control_effectiveness` 與 `control_source` 兩欄。
- 評分公式加入威脅項：`Priority = 10 × (0.35·S + 0.15·T + 0.25·E + 0.25·B)`。權重從 severity 挪出 0.15，曝險與業務不動——拆的是「漏洞本身」那一半裡「多嚴重」與「多可能」。無威脅資料時該權重**退回 severity**（非按比例重分配），公式精確退化為 Day 5 的 50/25/25，先前所有基準不變。
- 補抓五筆弱掃雜訊 CVE 的 EPSS 快照後結論反轉：Logjam（CVSS 3.7、EPSS 0.9997）6.85→7.79 升 High、RC4 6.45→7.01 升 High、OpenSSL padding 7.20→7.78。優先序分布由 7/23/8 變為 8/25/5，四筆跨分級。缺資料不會報錯，只會給出看起來合理的錯答案。
- `assets.csv` 的 `criticality` 更名為 `declared_criticality`，僅作對照；引擎改用推導值。二十台資產中四台不一致（郵件閘道 CRITICAL→IMPORTANT、內部 wiki IMPORTANT→NORMAL、檔案伺服器 NORMAL→IMPORTANT、機房環控 PLC IMPORTANT→CRITICAL），優先序分布由 8/22/8 變為 7/23/8。
- 控制證據超過 `exposure.control_evidence_max_age_days`（v0.1 為 90 天）即不可用於折減，該控制降為 `UNKNOWN` 而非 `NONE`；多個控制取效果最強者，不相乘。`asset_context.csv` 新增兩個來源欄位，推導結果與 Day 11 手寫版的四個決策欄位完全相同。

## [0.2.0] - 2026-09-23

資料管線與模擬資料（藍圖 §13.3 的 `v0.2.0-data` 里程碑）：Day 6 的第一條 Vertical Slice、Day 7–10 的三個 Collector、Day 11 的 Northstar 模擬資料集，以及 Day 2 案例的修訂。

### Added

- 新增 Northstar Digital Services 模擬資料集（藍圖 §8.2 規模：20 資產、40 findings、8 控制、4 Crown Jewel）與建置腳本 `scripts/build_northstar.py`；CVSS 全部取自 NVD 快照而非手填，離線重建輸出逐位元組相同，並以 17 個測試涵蓋規模、值域、無真實企業資訊與四個必測情境。
- 新增 CISA KEV Collector（`cve2action fetch-kev`）：一次下載完整目錄（1,721 筆）並在本地查表，狀態採三態——`LISTED`／`NOT_LISTED`（兩者皆為事實）／`UNKNOWN`（僅在未取得目錄時）；比對目錄宣告的 `count` 與實際筆數，殘缺即整批拒收，`knownRansomwareCampaignUse` 的 Unknown 映射為 None 而非 False。新增目錄快照與 22 個離線測試；KEV 尚未進入評分公式（留待 Day 14）。
- 新增 EPSS Collector（`cve2action fetch-epss`）：批次查詢 FIRST EPSS，快照記錄 `model_date` 與取得時間；查無資料視為正常答案並寫入快照，逾時與 HTTP 錯誤拋 `EpssUnavailable` 不寫檔。新增 7 份 EPSS 快照與 17 個離線測試；EPSS 尚未進入評分公式（留待 Day 14）。
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

- NVD collector 請求間隔由 6.5 秒調整為 7.5 秒，並在遭遇 429 時退避重試一次——6.5 秒仍會觸發「30 秒 5 次」的滾動窗限制。
- CVSS 同版本多評分者的取用順序補上第二層「NVD 自評優先」（ADR-day-08 已更新）：NVD 偶爾把自評標成 Secondary，原規則讓 CVE-2020-1472 取到廠商的 5.5 而非 NVD 的 10.0。
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
