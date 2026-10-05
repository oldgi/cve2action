# 版本紀錄

本專案採用 [Semantic Versioning](https://semver.org/)；重要設計異動另以 ADR 保存原因。

## [Unreleased]

### Added

- 新增 `src/cve2action/remediation/`（Day 25）：適用性閘門 `applicability.py`、§9.6 規則覆寫 `overrides.py`、處置結果 `treatment.py`，以及 CLI `cve2action treat`。**最便宜的處置是證明它根本不必修**——40 筆跑完，證明不必修的只有 1 筆。`NOT_APPLICABLE` 只有一種掙法：宣告的 `cpe_product` 不在該 CVE 的受影響清單裡，**而且那份清單不是空的**。窄得刻意，因為版本比對在真實資料上會以兩種方式騙人：Exchange 裝的 `15.2.792` 對上 CPE 的 `2013`／`2016`／`2019`，兩邊都是數字、比得出大小、答案毫無意義（純數字比對會說「24 條都沒命中」，而「沒命中」若能推出「不受影響」，這台對外的 Exchange 就從佇列裡消失）；`CVE-2024-6242` 的 `configurations` 整個是空的，「不在清單裡」只代表清單沒東西。因此閘門從不用「已修到更新版本」放行。`UNDECIDABLE` **照常評分**、只標記 `REVIEW_REQUIRED`——Day 15／21／22 同一條紀律的第四次套用：不能證明它不適用，就得當它適用；把分數拿掉等於讓「不知道」換來比較安全的名次。證不出來 30 筆，其中 26 筆根本沒有版本證據。§9.6 三條覆寫**只升不降**（會降級的覆寫規則實質上是沒有核准人的例外），「可無需既有權限」取最窄讀法＝整條路徑都是網路跳。被閘門清掉的不再進覆寫——跳板那筆同時滿足 KEV、可達、有路徑，不短路就會被推成 P0，把剛證明出來的東西丟掉。19 個測試，ADR-day-25。
- 新增 `data/synthetic/northstar/version_evidence.csv`（14 列）與契約：Day 25 適用性閘門的輸入。一列＝「針對這一筆 finding，我們憑什麼說裝的是這一版」。**鍵是 `(asset_id, cve)` 而不是服務名**——Day 21 已經證明名字 join 只對得上 15/40，「這個 CVE 該看哪個產品的版本」是人的判斷，寫進資料裡看得見、審得到，比埋在比對規則裡安全。因此 `product` 可以不等於 `services.csv` 的 `service`：`CVE-2019-0708` 要看的是作業系統版本，而 `services.csv` 記的是 `rdp 10.0`，協定版本答不了那個問題。`source` 分五級且強弱有別，**`banner` 不能定案**——發行版回溯修補後服務自報的版本不會變，看起來中招其實已經修了。每一列宣稱的版本關係都對照過 `data/snapshots/nvd/` 裡真實的 CPE：Northstar 的資產是虛構的，漏洞事實不是。資料集刻意只覆蓋 40 筆裡的 14 筆——另外 26 筆連「裝的是哪一版」都答不出來，而那正是 Day 25 的題目。三種結局都構造得出來：版本在範圍內（apache 2.4.49，CPE 只列這一版）、版本在範圍外（跳板是 Server 2019，CVE-2019-0708 的 CPE 只到 2008）、判不了（`CVE-2024-6242` 的 `configurations` 是空的、MOVEit 與 Exchange 的編號體系與 CPE 對不上、openssh 7.4p1 只有 banner）。
- 新增 `data/synthetic/northstar/risk_acceptances.csv`（4 列）與契約：藍圖 §9.6「任何 P0/P1 降級都必須留下原因、核准人與有效期限」的載體。沿用 Day 2 `risk_acceptance_*` 的欄位語意，但獨立成檔——掃描器不知道誰簽核了什麼，把核准人塞進掃描結果等於宣稱那是掃出來的事實。只有 `APPROVED` 且 `valid_until` 未過期才算數；資料集含一筆過期（ACC-003，狀態還掛 `APPROVED`，與 Day 23 的豁免到期同一條紀律）與一筆已撤銷（ACC-004，KEV 收錄後撤回）。核准人必須具名到人，「資安部門」不是核准人。
- 新增 `tests/test_applicability_inputs.py`（19 個測試）：不測閘門（那是 Day 25 的程式），只鎖兩件事——資料對得上真實 CPE，以及三種判定都構造得出來。
- 新增 `src/cve2action/attack_graph/choke.py`：共同瓶頸分析（Day 24）。**瓶頸的定義改成反事實的**——把節點當成不存在、重算一次、看還剩幾條——而不是 Day 22 `shared_hops()` 數的出現頻率。那個 docstring 當時寫著「Day 24 的 choke point 就是這個數字」，今天推翻它：兩種排法在 Northstar 上的第一名不是同一台（頻率 `NS-APP-ORDER-01` 16/30；切斷 `NS-DB-CUSTOMER-01` 切 22/30 而只出現在 11 條上，因為它是通往備份主機的唯一一跳）。三件頻率看不出來的事：切得掉的路徑可以多於它出現的路徑、**切斷數不可相加**（`NS-VPN-GW-01` 切 15 與 `NS-JUMP-01` 切 15 在同一條串聯上，一起修還是 15）、**單點瓶頸不存在**（四個 Crown Jewel 各需至少兩台，全部一起斷掉要四台）。切得最多的那台是 Crown Jewel，所以反事實必須知道哪些節點可以動：`protect` 預設把 Crown Jewel 標為不可處置，仍然列出但不進最小切割候選——一個算得很漂亮卻沒人能執行的答案不是答案。共同瓶頸定義為**出現在每一個最小切割集合裡**的節點（`NS-JUMP-01`，只排頻率第三），這同時落實藍圖 §17「共用跳板狀態改變會使相關決策失效」。25 個測試，ADR-day-24 記錄依據。
- `find_paths` 新增 `without=`：把指定資產當成不存在再搜一次。CLI `path --choke`（瓶頸報告）與 `path --without ASSET`（可重複，印出「N 條剩 M 條」）。
- 路徑呈現補上權限：§16 的 Day 24 門檻要求「能呈現入口、弱點、權限與 Crown Jewel 的有效路徑」，而 Day 22 只做到三樣——權限一直只進了分數、沒進呈現。現在每一跳附「取得權限：`local_admin`（CVE-2016-5195 為本機提權）」，證不出來就寫「證不出來——不代表拿不到」，不猜中間值。
- 新增 `src/cve2action/scoring/path_score.py`：藍圖 §9.3 的攻擊路徑分數 `A`，四項（可達性 0.40、可得權限 0.25、通往 Crown Jewel 0.25、跳數倒數 0.10）全部從 Day 19–22 建好的圖算出，不新增人工輸入。兩個刻意不補零的地方：查無路徑時可達性取下限 **0.05 而非 0**（Day 22 已證明那六台查無路徑沒有一台是被擋住的，給 0 等於宣告「證明不可達」），權限無法證明時整項移除、權重退回可達性（不猜中間值，與 Day 14 缺威脅資料同一招）。`A` 以第五項進入公式，權重改為 `0.28/0.12/0.20/0.20/0.20`；沒有攻擊圖資料時該項整個移除、權重退回 `exposure`。11 個測試。
- `risk_rules.yaml` 新增 `form`，支援 `additive` 與 `geometric` 兩種合成形式，兩者都已實作並各跑一次（藍圖 §10 Day 23 的要求）。**採用 `additive`**，依據是 `acceptance` 的門檻而非論述：兩種形式的 Kendall tau-b 與分歧清單完全相同（0.6、兩組），幾何平均在 `discrimination`（0.9211 對 0.8421）與 `range_coverage`（0.578 對 0.443）上勝出，但在新增的 `attributable` 上 0/37 對 37/37——幾何平均下總分不是各項之和，`gap_to()` 答不出「為什麼它排在我前面」，而那是 Day 16 建 `Explanation` 的全部理由。幾何平均保留於 `config/risk_rules.geometric.yaml`（CI 不跑、測試跑）：否決一個選項不等於把它刪掉。17 個測試，ADR-day-23 記錄依據與重新打開這個決定的三個條件。
- 評分門檻新增第九條 `attributable`：每組相鄰名次都要能逐項說明誰贏在哪一項，且逐項差額加得回總分差。Day 16 把 `gap_to` 做成可交付成果、Day 17 的分歧判決直接引用它的輸出，而 Day 18 定八條門檻時沒有一條看守它——這個專案最核心的對外承諾，是唯一沒有門檻的一條。
- `acceptance` 新增 `--today`：判斷豁免是否到期的日期，與 `--as-of`（資料基準日）分開。
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

- **一個被防禦性預設藏起來的 bug。** `treat` 第一版用 `getattr(catalog, "cves", ())` 取 KEV 清單，屬性名是錯的，於是它安靜地回空集合——§9.6 第一條一次都沒觸發，而輸出看起來完全正常。改成直接讀 `catalog.entries`，載入後是空的就 exit 2。**接錯要出聲，不要安靜地少做事。**
- **`revisit_on` 寫的是 `Day 20` 這種字串，等於永久豁免。** Day 18 的豁免機制要求寫下重新量測的日子，但驗證只檢查該欄非空，沒有任何程式判斷得出它過了沒有——所以兩條豁免從 Day 18 一路有效到 Day 23，發現的方式是我自己回來重新量，不是系統提醒我。現在 `revisit_on` 必須是 ISO 日期，載入時驗證格式，過期的豁免視為不存在並阻擋（`EXPIRED`）。
- **`explainable` 門檻從不檢查分解加不加得回分數**，只數因子個數與來源——所以 Day 23 加入幾何平均之後，它照樣給 38/38 滿分，一個加不回總分的分解也算「可解釋」。門檻量錯東西比沒有門檻更危險，因為它會發綠燈。已補上重建檢查（依 `form` 判斷：加法比貢獻之和，幾何比乘冪之積）。
- **`acceptance` 報表把門檻檔宣告的 `applies_to_rules_version` 當成實際載入的版本印出**，所以用 Day 18 的門檻量 Day 23 的規則時，報表會說「rules 0.3.0」而毫無異狀。現在兩個版本都印，不符時出聲；頁尾也不再硬寫「v0.1」。
- **`degradation_safe` 探針寫死加號**，在幾何平均下比的是一個不存在的數字，而且照樣 PASS。改為依 `form` 合成。
- **`explain` 碰到新因子直接 `KeyError`**：`SYMBOLS` 是顯示用的查表，查不到卻讓整個 CLI 掛掉。加入 `path` 的符號 `A`，並讓查不到時退回首字母。
- **`Explanation` 的三個投影在幾何平均下會悄悄說錯話**：`formula` 硬寫加號、`Factor.contribution` 加不回總分、`gap_to()` 的逐項差額加不回分差。Day 16 的紀律是「字串是從數字長出來的，不可能不一致」，加第二種形式時我自己把它打破了。現在算式形狀跟著 `form` 走，幾何形式下不報逐項貢獻（`to_dict` 回 `None`、人讀版留白並說明原因）、`gap_to()` 回空集合而不是一組加不回去的數字。
- **CI 的 `calibrate` 與 `acceptance` 沒有餵攻擊圖輸入**，所以路徑項被整個移除，兩個 gate 量的是**上一版的模型**——而且是綠的（tau 0.8、只有一組分歧，而真正的 production 是 0.6、兩組）。兩個步驟都補上圖資料。
- `test_rebuilding_from_snapshots_is_byte_identical` 原本會**實際改寫版控裡的資料檔**，與其他正在讀同一批檔的測試偶發干擾（本次開發中真的紅了一次）。改為透過 `NORTHSTAR_OUT` 建到暫存目錄再與版控比對——不動工作區，驗證強度不變。
- `docs/articles/day-04.md` 引用三張從未產出的圖（`day-04-visible-vs-context`／`-context-rabbit-hole`／`-v01-portrait`）：Day 4 最後改用一張八格長圖 `day04-infographic.png`，文章沒跟著改，repo 版本破圖至今（已發表版不受影響）。現改為引用長圖，並補上一直存在卻沒被引用的封面 `day04-fig1-cover.png`；另外兩處的圖說保留原文、改為引言樣式。`day-04-visual-captions.md` 標註為規劃稿並記錄實際落點。
- `cve2action derive-context` 自 Day 13 起產出的 `business_criticality` 整欄為空：Day 13 把 criticality 移出 `assets.csv`（更名 `declared_criticality`）改由 `business_context.csv` 推導，但 `derive_asset_context` 仍讀舊欄位，CLI 也沒有對應輸入。照文件流程產出的 context 接回 `rank` 會整批變成 NEEDS_CONTEXT。當時測試只覆蓋函式層且自行補上 criticality，因此未被發現。現已新增三個走 CLI 的測試，其中一個斷言輸出與版控中的 `asset_context.csv` 逐位元組相同。

### Changed

- 藍圖 §10 新增一列「25＋ 番外篇二：控制擋得住這一類弱點嗎？」，與 Day 25 同日發表，用來兌現 [Day 15 文章](docs/articles/day-15.md) 對讀者許下、而 Day 25 沒有兌現的承諾。放番外篇而不占用施工日，因為它補的是一條**軸線**不是一天的產出；承諾是文章對讀者許的，用文章還最誠實。範圍與五條驗收寫在藍圖 §9.6 註記：缺的那條軸線（CWE）已經在 NVD 快照的 `raw.weaknesses` 裡（30 個 CVE 有 26 個），`extracted` 投影從來沒取出來——與 Day 25 發現 CPE 的形狀相同。已量到的實況：9 筆 finding 實際拿到控制折減，其中 **2 筆站不住**，都是 WAF 對 TLS 層（`CVE-2013-2566` CWE-326/327、`CVE-2016-2107` CWE-310）。第五條驗收特別註明風險：撤回折減會讓分數上升，而 Day 15 的已發表文章引用過那些數字，動手前要先確認動到哪幾篇。
- 一致性盤點記下第三種缺口來源：**已發表文章許下的承諾**。[Day 15 文章](docs/articles/day-15.md) 寫「控制與弱點類別的對應留給 Day 25」，但 Day 25 做的是 §9.0 閘門 2 的**版本**適用性，兩者是不同的問題——那句承諾沒有兌現。實測確認問題仍在：`waf` 對 `CVE-2013-2566`（TLS 層 RC4 降級）至今仍判為 `APPLICABLE`。已記入藍圖 §5 盤點與規格的非目標清單，標為「已知且尚未排程」，建議排 Day 26。文章是對讀者的契約，而它不在任何一張表裡。
- 規格的非目標清單更正：漏洞適用性閘門（§9.0 閘門 2）已於 Day 25 完成，不再是非目標；資產歸併仍是。
- `version_evidence.csv` 新增 `cpe_product` 欄：我們認定這台裝的東西在 NVD 的 CPE 裡叫什麼。必須明寫，不能靠名字比對猜——apache-httpd 在 CPE 裡叫 `http_server`、Confluence 分 `confluence_server` 與 `confluence_data_center`、windows-server 要連版號變成 `windows_server_2019`。猜錯的後果不是漏判，是誤判成不必修。
- 藍圖 §10 的 Day 25 增列 **§9.6 的三條規則覆寫**（①KEV＋Internet 可達＋有效攻擊路徑 → 至少 P0；②可無需既有權限通往 Crown Jewel → 至少 P1；③關鍵輸入缺失 → `REVIEW_REQUIRED`）。Day 24 的一致性盤點查出這三條**都沒有實作，而且 §10 原本沒有任何一天負責前兩條**——第三條只是靠成功標準 #3 間接排進了 Day 25。三條都是 `tier` 層的結論、共用同一套機制，所以排同一天。驗收明訂：覆寫只能升級不得降級、每次覆寫要留下觸發哪一條與憑哪些事實、P0/P1 降級須有原因／核准人／有效期限的載體。同時記下兩個前置缺口：「可無需既有權限」的定義要先寫清楚（Day 21 的 `UNPROVEN` 會讓判斷偏保守，而偏保守在這裡是往上覆寫），以及降級記錄**目前沒有載體**（`day-02-findings.csv` 有現成的 `risk_acceptance_*` 欄位契約，但現行 Northstar 的 `scanner.csv` 只有四欄）。
- 這次盤點的教訓記在藍圖 §5 盤點註記：**只盤成功標準盤不到規格裡的規則。** 成功標準寫「做得到什麼」，§9 寫「必須怎麼算」，兩者不互相涵蓋——Day 18 那次盤點只對照了十一條成功標準，所以漏掉 §9.6。
- 三處把 §9.6 說成「尚未實作」或暗示已經可用的文件已更正並指向 Day 25：規格的非目標清單（從「待排」改為已排程，並列出三條的個別狀態）、[ADR-day-14](docs/decisions/ADR-day-14-threat-enrichment.md)（加上後記：輸入齊了但規則仍未實作）、[ADR-day-18（二）](docs/decisions/ADR-day-18-crps-tier-mapping.md)（原文說接上 `tier` 就「在 Day 22 之後寫得出來」——兌現了一半，寫得出來但沒有寫）。三處都明寫同一件事：**`priority_tier` 目前純粹是分數的投影，不是規則的結論**，一筆 KEV ＋ 對外 ＋ 有路徑的 finding 現在仍有可能不落在 P0。
- `paths.shared_hops()` 的 docstring 原本宣告自己就是 Day 24 的 choke point，已改為明寫「**這不是 choke point**」並指向 `choke.py`。出現頻率回答「它在多少條路上」，不回答「修掉它能擋掉多少條」。
- `config/acceptance.yaml` 升到 `0.2.0`、`applies_to_rules_version` 改 `0.4.0`；兩條豁免以今天的量測重新說明，到期日 `2026-10-12`。其中 `range_coverage` 必須承認 Day 18 的預測落空：當時押「Day 20 的可達性引擎會讓 `E` 變寬，跨距自然拉開」，實測從 0.44 變成 **0.443**——錯在前提，Day 20 之後我們沒把觀測連線塞回 `E`，而是另開了第五項，`E` 的值域一個都沒變。
- 新增 `config/acceptance.v0.1.yaml`：Day 18 發表時的八條門檻凍結檔。已發表文章引用的 6/8、`0.6316`、`0.44` 必須永遠重現得出來，與 Day 23 凍結 `risk_rules.v0.1.yaml` 同一個理由。Day 5–18 的門檻測試全部指向它。
- `data/calibration/day-17-expert-ranking.yaml` 新增第二組分歧的書面判決（LAB-CONFLUENCE vs PLC-DC-ENV，判給模型）。錯誤形狀與第一組相同：我排第 4、第 5 的依據兩邊都一樣（兩台都查無路徑），回頭看自己寫的理由，兩段都在跟第 1 名比，那兩台之間誰該在前面從頭到尾沒寫下判準。差距只有 0.08 分，已記為 Day 28 的待辦（模型需要「這兩筆分不出來」這個答案）。
- **更正一個從 Day 11 延續到 Day 17 的錯誤說法**：「v0.1 公式產不出 Low」是錯的。合成探針顯示四個分級都構造得出來（`CVSS 5.5 / ISOLATED / STRONG / NORMAL → 3.95 Low`）；Northstar 沒有 Low，是因為沒有「低嚴重度 × 隔離 × 不重要」的組合。測試註解與規格文件已更正。
- `test_dataset_matches_blueprint_scale` 補齊檢查：藍圖 §8.2 有七項規模，原本只檢查建好的四項，缺的三項因此一直沒被發現。
- 未採用藍圖為 CRPS 乘法模型訂的 P0–P3 門檻 80/60/35：套到加法分數上會產生 38 筆中 21 筆 P0，與 P0「緊急評估與處理」的定義矛盾。沿用 9.0/7.0/4.0，量測結果有回歸測試釘住。
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
