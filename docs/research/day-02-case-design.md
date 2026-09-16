# Day 2 案例設計與查核備忘錄

修訂日：2026-09-16。狀態：可審稿；尚未宣告發文、實機驗證或完成修補。

## 1. 教學目標與時間邊界

本案例不證明「8.1 永遠比 9.8 優先」，也不以兩筆資料校準風險公式。目標是區分技術嚴重度、環境暴露、修補限制與可交辦行動。

權威情境時點定義於 `data/synthetic/day-02-scenario.json`：2022-06-03 23:00 PDT（UTC−07:00）。選擇此時點是因為 Atlassian 於同日 10:00 PDT 更新修正版；若設定成臺灣 6/3 晚間，反而會早於該次公布。

這是 2026 年編寫的歷史教學重建，不是封存於 2022 年的完整情資快照。CVSS 分數及向量採所列公開資料整理，不聲稱重建每個欄位當年首次公布的時間。不得把 6/10 新增的公告內容當成 6/3 已知條件。主文只用 CVSS v3.1，不混入當時尚未發布的 v4.0。

所有主機、團隊、清冊、ACL 測試、代理伺服器紀錄、EDR 查核、期限及接受單號均為虛構；資料包沒有附真正的測試日誌或簽核證據。

## 2. 公開事實及來源

### 2.1 CVSS

CVSS v3.1 有 Base、Temporal、Environmental 指標，不能把它說成完全不認識環境。主文比較的是 Base Score，不是完整企業風險。[FIRST 指南](https://www.first.org/cvss/v3.1/user-guide)

### 2.2 案例 A：CVE-2022-26134

- Confluence Server／Data Center 未授權 RCE；Atlassian 公告含當時主動利用的描述。
- 模擬版本 7.13.6，該分支歷史修正版 7.13.7。
- CVSS v3.1：9.8；`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`。
- KEV 加入日期 2022-06-02。
- 不把 KEV 與主動利用描述擴張為已證實的大規模成功入侵。

來源：[Atlassian 2022-06-02 公告及更新紀錄](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html)、[CISA 2022-06-02 公告](https://www.cisa.gov/news-events/alerts/2022/06/02/cisa-adds-one-known-exploited-vulnerability-cve-2022-26134-catalog)、[NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-26134)。

### 2.3 案例 B：CVE-2020-6820

- Firefox ReadableStream 競爭條件可造成 Use-after-free；Mozilla 曾報告針對性利用。
- 模擬 Firefox 74.0；74.0.1 修正此 CVE，ESR 當時修正版為 68.6.1。此案例不是 ESR 安裝。
- CVSS v3.1：8.1；`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`。
- KEV 加入日期 2021-11-03。
- 針對性攻擊描述不是攻擊頻率、規模或企業受害機率。

來源：[Mozilla MFSA 2020-11，2020-04-03](https://www.mozilla.org/en-US/security/advisories/mfsa2020-11/)、[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2020-6820)、[NVD](https://nvd.nist.gov/vuln/detail/CVE-2020-6820)。

以上修正版只說明當年的特定 CVE 邊界，不能作為今天的部署建議；跨產品、分支、ESR、廠商回補版本不可只做數字大小比較。

## 3. 虛構資產與控制假設

### 3.1 A：隔離測試主機

`AST-LAB-001`／`LAB-CONFLUENCE-01` 由 platform-lab-team 負責。Confluence TCP/8090 仍啟用；整合測試進行中，中斷需重跑。僅使用測試資料與獨立測試帳號，模型假設沒有正式憑證或整合關係。

入口只允許跳板與弱掃主機。出口拒絕往 PROD、MGMT 的新連線；不宣稱封鎖所有既有允許連線的回應。所謂隔離是分段及政策控制，不是實體斷網。

`negative_reachability_test` 與 2022-06-01 是虛構測試中繼資料，尚不足以證明完整覆蓋。正式系統需保存來源、目的、埠、協定、方向、規則版本、允許／拒絕預期與結果及證據識別碼。來源遭入侵、規則異動或證據過期時，必須重評。

### 3.2 B：一般維運端點

`AST-OPS-007`／`OPS-WS-07` 由 ops-team 負責，不是專用特權存取工作站（PAW）。代理紀錄「近 30 天有外部瀏覽」是情境輸入，不是實際交付的日誌，也不證明每日流量或惡意內容必然抵達。

Firefox 被舊管理介面相容性政策鎖版。尚未驗證升級衝擊，因此不能推定零成本升級。EDR 存在、6/3 曾進行紀錄覆核，不等於已確認防利用有效。

此端點可以發起 MFA 跳板登入，但授權者的正常登入能力不是攻擊者的登入能力。

### 3.3 共用資產與信任邊界

- `ADMIN-JUMP-01`：接受 B 發起的條件式登入，並能連 A 的 TCP/8090；前往核心系統仍須授權身分。A 的可信來源並非與 B 無關。
- `VULN-SCANNER-01`：可對跨區核准目標及埠／協定執行認證掃描，不是無限制的萬能路徑。掃描憑證的權限、保管、重用與網段隔離需另行查核。
- `CORE-SERVICE-01`：管理入口經跳板與授權身分；另有受限掃描例外，不能把掃描能力等同管理能力。
- 資產 CSV 是關係摘要，不是完整防火牆規則集。未知埠／協定不能臆填成 any/any。

## 4. 攻擊路徑的推論邊界

### 4.1 A 的「未找到」不是「不存在」

`NO_PATH_FOUND_IN_MODEL` 只表示在目前模型與假設下未找到有效核心資產路徑。它不證明網路圖完整，也不排除本機資料外洩、破壞、回應流量或其他未建模管道。

### 4.2 B 的條件式路徑

外部內容接觸、漏洞適用性、成功利用、可用權限、端點隔離突破（若需要）、取得或濫用身分／工作階段、跳板 MFA 與授權、正式系統授權，均需逐段驗證。

不假定單一 Firefox CVE 自動包含沙箱逃逸或管理權限。不以多個自行猜測的成功率相乘，產生貌似精準的攻擊機率。網路可達、身分可用及漏洞可利用是不同類型的邊。

### 4.3 交叉案例與反向重評

B 若有入侵跡象，需要覆核其身分及跳板；若跳板受到影響，A 原本依賴的可信入口假設也需重評。核心系統已有跳板管理關係，因此 A 並不是 B 到核心的必經中繼站，修 A 也不等於切斷 B 的管理路徑。

B 遭利用的證據是 A 的重評觸發器，不是「跳板必定已失守」的證明。出現入侵證據時要啟動事件應變；重評不等於所有案件自動變成最高優先。

## 5. 可交辦決策與尚缺資料

| 項目 | A | B |
|---|---|---|
| 決策狀態 | REVIEW_REQUIRED | MITIGATE_NOW_PATCH_PENDING |
| 當日動作 | 保持隔離，審查控制與接受提案 | 限制外部瀏覽、安排乾淨且受支援的替代環境、查閱端點與身分紀錄 |
| 當日目標 | 2022-06-03；這是提案要求，不是完成紀錄 | 2022-06-03；這是緩解目標，不是完成紀錄 |
| 正式修補期限 | 2022-06-16，虛構內部 SLA；暫緩未核准 | 未設定；由 ops-team 在相容性評估與變更安排時補上 |
| 風險接受 | RA-2022-0603-01，PENDING；核准者與到期日未設定 | NOT_APPLICABLE：本情境尚未提出接受申請，不表示不存在風險 |
| 阻礙 | 整合測試中斷成本 | 舊管理介面相容性未驗證 |
| 結案條件 | 修補及版本驗證，若曾入侵須另行處置 | 同左；緩解或完成相容性測試都不是修補結案 |

不能因為 A 有接受單號就自動核准。若將來要允許暫緩，至少需要：明確權責者核准、有效期、證據範圍與時效、修補責任與期限，以及未觸發撤銷條件。控制時效或接受期限中的任何一項失效，都不能繼續依賴原決策。

6/1 到 6/3 是兩個日曆日；案例上限七天，6/8 為七天、6/9 為八天。此政策僅作離線測試。即使日期合格，缺乏範圍或核准仍須審查；未來到 6/16 前需再驗證，不能視作核准到期日。

若 B 無可用替代環境，需升級處理隔離與業務連續性取捨，不可默認繼續外部瀏覽。文章未聲稱緩解方案已部署、沒有業務代價，或兩案已獲企業批准。

## 6. CSV 契約與修訂對照

資產表 5 筆、12 欄；finding 表 2 筆、33 欄。ID 保持不變，finding.asset_id 必須指向資產表唯一主鍵。CSV 為 UTF-8，首列欄名；本版是靜態測試資料，不是自動運算引擎輸出。

| 欄位／變更 | 定義與未知處理 |
|---|---|
| owner_team | 行動負責團隊；不是風險核准者 |
| prod_reachability | 保留原欄名；字串列舉 true／false／conditional／unknown，表示來源資產往正式區的模型關係，不可做一般布林轉換 |
| inbound_allowlist | 人可讀關係摘要；分號分項；n/a 不是 deny all，也不是 allow all |
| exploitation_scale → 三個欄位 | exploitation_status 表示已知遭利用；targeting_evidence 表示針對性證據；scanning_activity 表示掃描活動。避免 MASS 與 TARGETED 混為互斥尺度 |
| exploitation_status | 兩案 KNOWN_EXPLOITED；不是本企業已遭入侵 |
| targeting_evidence | A UNKNOWN；B TARGETED_REPORTED；未知不等於沒有 |
| scanning_activity | 兩案 UNKNOWN；未提供可引用掃描證據，刪除無來源的廣泛掃描斷言 |
| source_urls | 公開 CVE 來源，以分號分項；不作為虛構內部控制的證據 |
| control_evidence_type／control_verified_on | 保留類型與日期；不是實際原始證據附件；EDR 覆核日期不證明 exploit 阻擋成功 |
| risk_acceptance_status | A PENDING、B NOT_APPLICABLE；不能從單號推成 APPROVED |
| risk_acceptance_approver／valid_until | 對應完整欄名 risk_acceptance_approver／risk_acceptance_valid_until；本版空白，不能解讀為永久有效 |
| sla_deadline | 正式修補目標；A 保留 6/16，B 留空，因原 6/3 轉為當日緩解目標 |
| immediate_action_deadline | 當日行動目標；不代表已執行、不代表修補結案 |
| compatibility_status | A INTEGRATION_TEST_IN_PROGRESS；B VALIDATION_PENDING |
| decision_status／provisional_action | 本案例的待辦決策及文字理由；不是模型已完成計算或工具已操作 |
| path_status | A 改 NO_PATH_FOUND_IN_MODEL；B 保留 CONDITIONAL_TO_ADMIN_PATH |
| recalc_triggers | 必須觸發重評的條件，不預先固定重評結果 |

空白表示未知或未設定；日期欄使用 ISO YYYY-MM-DD。共同時點及日曆日期政策只在 scenario JSON 定義，不用系統今天日期取代。欄位新增及 exploitation_scale 移除屬 schema 0.2.0 變更；任何舊匯入器須依欄名適配。

## 7. 驗收與發表檢查

- 使用 `python scripts/validate_day02.py` 檢查 CSV 寬度、ID 關聯、日期、核准狀態、緩解／修補分離及本案例的回歸斷言。
- 該檢查只驗證資料一致性，不驗證真實控制、利用成功率或排序正確性。沒有動態風險引擎，不宣稱改 CSV 會自動重算文章。
- 主圖改用 `day-02-cover-v2.png`，原有 PNG／JPEG 保留。連線視為概念關係；兩個分數不能取代本文的條件與未知標記。
- 內文保留使用者提供的 `day-02-rerank-styleB-r2.png` 原圖。P0／P3 不是已實作的引擎分級；圖說明列 A 進入正常週期所需的核准與控制前提，目前仍待審。B 的優先行動是緩解，不表示完成修補。
- iT 邦幫忙發文前，上傳新封面與內文圖，保留內文圖說，將文章尾端相對檔案路徑替換為實際 GitHub 網址。
- 發表前確認願意公開的主張是「B 先緩解、A 同步審查」，而非「核准暫緩 A」或「已確認 B 能入侵核心」。
