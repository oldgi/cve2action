# Day 2 案例設計與查核備忘錄

- 狀態：Draft reviewed
- 日期：2026-09-15
- 對應文章：`docs/articles/day-02.md`
- 目的：保存案例事實、虛構條件、推論邊界與後續實作需求，避免文章為了戲劇效果做出超出證據的結論。

## 1. 教學命題

Day 2 要證明的是：

> 公開 CVSS Base Score 衡量技術嚴重度；企業修補優先序還需要漏洞適用性、威脅訊號、有效可達性、資產角色、控制有效性、攻擊路徑與修補成本。

不應宣稱：

- CVSS 完全沒有環境指標。
- 低分漏洞一律比高分漏洞重要。
- 有 ACL 就可以不修 Critical CVE。
- 單一瀏覽器漏洞必然直接攻陷 Crown Jewel。
- CISA KEV 代表任何部署環境都有相同風險。

## 2. 公開事實查核

### 2.1 CVSS 的使用邊界

FIRST CVSS v3.1 User Guide 明確說明 CVSS 衡量 Severity，而不是 Risk；Base Score 應搭配環境情境與可能隨時間變動的屬性。CVSS v4.0 將指標分為 Base、Threat、Environmental 與 Supplemental，並說明公開資料提供者通常只提供 Base Score，Threat 與 Environmental 多由使用者組織評估。

結論：文章應批評「把 Base Score 直接當修補優先序」的流程，而不是批評 CVSS 標準沒有考慮情境。

### 2.2 CVE-2022-26134

可公開確認：

- 產品：Atlassian Confluence Server／Data Center。
- 類型：未授權遠端程式碼執行，與 OGNL injection 有關。
- NVD CVSS v3.1：9.8 Critical。
- 向量：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`。
- CISA 在 2022-06-02 因主動利用證據加入 KEV。
- 修正版本依 Atlassian 公告列示；實務判斷必須以實際產品線與完整子版本比對，不能只看 Banner。

不能由 CVE 本身推得：

- 特定企業是否對 Internet 開放。
- ACL 是否存在或有效。
- 該主機是否含正式資料或共用憑證。
- 成功利用後能否連到其他主機。

### 2.3 CVE-2020-6820

可公開確認：

- 產品：Firefox、Firefox ESR，另有 Thunderbird 受影響版本。
- 類型：處理 ReadableStream 時的競爭條件造成 Use-after-free。
- NVD CVSS v3.1：8.1 High。
- 向量：`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`。
- Mozilla 表示曾觀察到針對性攻擊。
- CISA KEV Catalog 收錄此 CVE。
- Mozilla 修正版本：Firefox 74.0.1、Firefox ESR 68.6.1；Thunderbird 另依對應公告確認。

推論限制：

- Use-after-free 與高 CIA impact 不足以證明單靠此漏洞就取得整部端點的完整控制。
- 瀏覽器程序、沙箱逃逸、EDR、權杖取得、登入關係與後段網路可達性應拆成不同條件。
- 案例的攻擊路徑必須標成條件式，不可以把 CVE 到 Crown Jewel 畫成無條件直達。

## 3. 虛構環境設計

### 3.1 案例 A：隔離測試 Confluence

| 欄位 | 設計值 | 設計理由 |
|---|---|---|
| asset_id | `LAB-CONFLUENCE-01` | 明確表達非正式用途 |
| zone | `ISOLATED_LAB` | 測試有效可達性而非只看 AV:N |
| software evidence | Confluence 7.13.6；已驗證 Build 與套件清冊 | Atlassian 公告列 7.13.7 為該分支修正版 |
| service | TCP/8090，運作中 | 保持網路弱掃能發現服務的合理性 |
| inbound | 僅 `VULN-SCANNER-01`、`ADMIN-JUMP-01` | 使用正向列表，不宣稱完全不可達 |
| outbound | 禁止到 `PROD` 與 Crown Jewel | 阻斷後續正式區路徑 |
| data | 僅虛構測試資料 | 降低企業衝擊，但不改變 CVE Base Score |
| identity | 獨立測試服務帳號；不得與正式環境共用 | 避免以憑證重用形成隱藏路徑 |
| control evidence | ACL 最近 7 日內驗證 | 控制必須有時效，不能永久相信 CMDB 欄位 |
| decision | 延至下一窗口；修補前禁止放寬控制 | 表達延後不是接受永久不修 |

必須觸發優先序重算的事件：

- ACL 驗證逾期或規則改變。
- 主機加入正式資料、正式帳號或正式整合。
- 新增到 Internal／DMZ／Prod 的網路路徑。
- 弱掃找到第二個可與本 CVE 串接的弱點。
- 測試服務準備轉正式。

### 3.2 案例 B：維運工作站 Firefox

| 欄位 | 設計值 | 設計理由 |
|---|---|---|
| asset_id | `OPS-WS-07` | 表達日常維運用途，不冒充標準 PAW |
| zone | `USER_LAN` | 端點可接觸外部內容 |
| software evidence | 端點清冊確認 Firefox 74.0 | 不能只靠遠端 Banner 判定瀏覽器子版本 |
| internet relation | 可主動瀏覽外部網站 | 表示入口活躍，不等於任意 Internet 主機可反向連入 |
| identity relation | 使用者可登入 `ADMIN-JUMP-01` | 權限關係與漏洞利用分開保存 |
| endpoint control | EDR 已啟用，效果未知 | 有控制不代表自動免疫；未知不能當作 100% 有效 |
| path status | `CONDITIONAL` | 後段需要額外證據與前置條件 |
| remediation | 升級 Firefox 並檢查端點及身分紀錄 | 同時處理 Vulnerability 與可能已利用的情境 |

禁止把 `OPS-WS-07` 描述成正式 Privileged Access Workstation。標準 PAW 原則上不應用於一般 Internet 瀏覽；本案例刻意呈現的是企業常見但需要改善的日常維運工作站與管理登入關係。

## 4. 條件式攻擊路徑

案例 B 的路徑模型應拆成：

1. 外部內容抵達受影響 Firefox。
2. CVE-2020-6820 利用成功。
3. 攻擊者突破或繞過瀏覽器／作業系統的其他限制。
4. EDR 未阻擋或未及時隔離。
5. 取得可用的使用者權杖、憑證或互動式工作階段。
6. `OPS-WS-07` 可連到 `ADMIN-JUMP-01`。
7. 取得的身分確實被允許登入管理跳板。
8. 從管理跳板存在到 Crown Jewel 的網路及身分路徑。

第 2 步有公開利用證據，不代表第 3 至第 8 步自動成立。MVP 應讓每條 Edge 保存 `confirmed`、`conditional`、`unknown` 與證據時間。

## 5. 決策設計

案例排序翻轉依靠以下組合，不依靠任意調低 CVSS：

- A 的 CVE 技術嚴重度較高，利用複雜度較低。
- A 的有效來源被限制，資產與正式區隔離，且控制有近期證據。
- B 的入口軟體持續使用並接觸外部內容。
- B 位於具有管理登入關係的端點，潛在後續衝擊較大。
- B 的修補成本低，可立即升級並驗證版本。
- A 的延後附帶期限與控制失效條件，不代表解除修補責任。

Day 2 不計算 CRPS 數字。若現在硬塞分數，讀者會把討論焦點放在權重，而不是看見資料閘門。量化應留到後續評分章節。

## 6. 人工覆核問題

在案例進入正式評分前，分析人員至少要問：

### 案例 A

- Confluence 完整版本與 Build 為何？證據來源是什麼？
- ACL 是設定值還是實際流量測試結果？
- 是否存在反向代理、NAT、VPN 或其他未納管入口？
- 主機上是否有正式資料、API Token、SSH Key 或共用服務帳號？
- 出站限制是否同時涵蓋 IPv4、IPv6 與管理網路？

### 案例 B

- Firefox 完整版本與安裝來源為何？
- 使用者是否真的以該瀏覽器處理外部內容？
- EDR 對瀏覽器利用、程序注入與憑證存取有哪些阻擋及偵測能力？
- 工作站連管理跳板是否需要 MFA、裝置憑證與再次驗證？
- 是否已有可疑程序、網路、登入或權杖使用紀錄？

## 7. 來源

- https://www.first.org/cvss/v3.1/user-guide
- https://www.first.org/cvss/v4.0/specification-document
- https://nvd.nist.gov/vuln/detail/CVE-2022-26134
- https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html
- https://www.cisa.gov/news-events/alerts/2022/06/02/cisa-adds-one-known-exploited-vulnerability-cve-2022-26134-catalog
- https://nvd.nist.gov/vuln/detail/CVE-2020-6820
- https://www.mozilla.org/en-US/security/advisories/mfsa2020-11/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2020-6820
