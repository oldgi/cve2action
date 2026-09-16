# Day 2｜CVSS 9.8，真的就該第一個修嗎？

> 本文使用兩筆真實 CVE 的公開資料，但資產名稱、網路區域、控制措施、帳號權限與攻擊路徑均為虛構情境，不對應任何真實企業。

星期五晚上，維運團隊只排得到一個修補窗口。

弱掃報告上有兩筆待處理項目：第一筆是 CVSS 9.8 的 Critical；第二筆是 CVSS 8.1 的 High。如果我們只看分數，答案似乎毫無懸念：先修 9.8。

但資產管理員補上了一句話：

> 9.8 位於隔離測試區，只允許弱掃主機與管理跳板連入；8.1 則出現在維運人員每天使用的工作站，而且這部工作站可以登入管理跳板。今晚只能先處理一個，你選哪一個？

這不是要證明 8.1 一定比 9.8 危險，而是要問：**漏洞的技術嚴重度，能不能直接等同企業的修補優先序？**

## 先看弱掃報告上的兩個案例

| 比較項目 | 案例 A：9.8 的隔離測試主機 | 案例 B：8.1 的維運工作站 |
|---|---|---|
| CVE | CVE-2022-26134 | CVE-2020-6820 |
| 公開 CVSS v3.1 Base Score | 9.8 Critical | 8.1 High |
| 漏洞本身 | Confluence Server／Data Center 未授權遠端程式碼執行 | Firefox／Firefox ESR 處理 ReadableStream 時的 Use-after-free |
| 公開利用訊號 | CISA KEV；曾有主動利用 | CISA KEV；Mozilla 曾觀察到針對性攻擊 |
| 虛構資產 | `LAB-CONFLUENCE-01` | `OPS-WS-07` |
| 虛構 Zone | 隔離測試區 | 使用者辦公區 |
| 使用狀態 | 服務運作中，但不是正式營運服務 | 每日使用 Firefox 瀏覽外部網站 |
| 有效可達性 | Internet 與一般內網皆不可達；僅弱掃主機及管理跳板可連 TCP/8090 | 可主動連往 Internet，也可登入管理跳板 |
| 既有控制 | 正向列表 ACL、非正式資料、獨立服務帳號、禁止連往正式區 | EDR 啟用，但瀏覽器版本已確認落在受影響範圍 |
| 後續攻擊路徑 | 未找到通往 Crown Jewel 的有效路徑 | Internet 內容 → 工作站 → 維運人員既有登入關係 → 管理跳板；後段仍須逐項驗證 |
| 今晚暫定決策 | 保留隔離措施，列入下一修補窗口；修補前不得放寬 ACL 或轉正式 | 優先升級 Firefox，並檢查端點告警及可能的入侵跡象 |

只看最上面的分數，案例 A 排第一；加入最下面的企業情境後，今晚的處理順序可能翻轉。

不過，在接受這個結論以前，我們得先把兩件事講清楚。

## CVSS 沒有算錯，是我們問錯了問題

[FIRST 的 CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide)直接指出：CVSS 衡量的是 Severity，而不是 Risk。Base Score 描述漏洞本身相對穩定的技術特性；要反映利用狀態與部署環境，還需要 Temporal／Environmental Metrics，甚至搭配 CVSS 以外的組織風險因子。

到了 [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)，指標分成 Base、Threat、Environmental 與 Supplemental 四組。FIRST 也說明，NVD 等公開資料提供者通常只提供 Base Score；Threat 與 Environmental 資訊多半要由使用漏洞資訊的組織自己補上。

所以真正的問題不是「CVSS 沒有用」，而是許多弱掃流程只拿得到公開的 Base Score，接著就把它當成修補優先序。

9.8 能告訴我們：如果 CVE-2022-26134 出現在受影響版本，而且攻擊者能碰到該服務，這是一個不需要帳號、不需要使用者互動、攻擊複雜度低，成功後可能造成高度機密性、完整性與可用性衝擊的漏洞。

但 9.8 不會自動告訴我們：

- 這個 IP 對應哪一部資產？
- 掃描到的版本是否真的落在受影響範圍？
- 服務目前是否啟用？誰能連到它？
- ACL 是否真的阻擋 Internet 與一般內網？最後一次驗證是什麼時候？
- 主機上有沒有正式資料、共用帳號或可供橫向移動的憑證？
- 攻擊成功後，能否繼續走到重要資產？

這些才是修補決策會用到的環境事實。

## 案例 A：9.8 很危險，但今晚不一定排第一

[Atlassian 公告](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html)將 CVE-2022-26134 描述為 Confluence Server 與 Data Center 的 Critical 未授權遠端程式碼執行漏洞；[CISA 也因主動利用證據將它加入 KEV](https://www.cisa.gov/news-events/alerts/2022/06/02/cisa-adds-one-known-exploited-vulnerability-cve-2022-26134-catalog)。公開 CVSS v3.1 向量為：

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

換成人話就是：可以從網路發動、利用複雜度低、不需要既有權限，也不需要使用者配合；一旦成功，可能對機密性、完整性與可用性造成高度影響。

這樣的漏洞當然不能放著不管。但在虛構環境中，`LAB-CONFLUENCE-01` 安裝 Confluence 7.13.6；依 Atlassian 公告，7.13 分支要到 7.13.7 才修正，因此適用性已經確認。主機位於隔離測試區，入口 ACL 只允許弱掃主機與管理跳板連到 TCP/8090，出口也不能通往正式區。它使用獨立測試帳號，沒有正式資料，且 ACL 驗證紀錄仍在有效期限內。

因此，CVE 的嚴重度沒有改變；改變的是攻擊者抵達它的機會，以及成功後能繼續走到哪裡。

今晚不先修它，是一個有條件、可撤銷的暫定決策：隔離控制必須持續有效、不得變更用途、不得放寬 ACL，而且仍要排入最近的修補窗口。只要其中一項條件失效，優先序就要立刻重算。

## 案例 B：只有 8.1，卻可能更急

[Mozilla 公告](https://www.mozilla.org/en-US/security/advisories/mfsa2020-11/)指出，CVE-2020-6820 是 Firefox 處理 ReadableStream 時的競爭條件，可能造成 Use-after-free；Mozilla 當時已觀察到利用此漏洞的針對性攻擊。它也被列入 [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2020-6820)。公開 CVSS v3.1 Base Score 為 8.1，向量為：

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

它與案例 A 的主要分數差異之一，是 Attack Complexity 被評為 High。因此只照 Base Score 排序，它自然落在 9.8 後面。

但虛構資產 `OPS-WS-07` 是維運人員每天使用的工作站。Firefox 版本已由端點軟體清冊確認落在受影響範圍；工作站可以瀏覽 Internet，也具有登入管理跳板的既有關係。這讓它不只是一個「工作站上的瀏覽器漏洞」，而可能成為攻擊路徑的入口。

這裡必須很克制：Firefox 漏洞成立，不代表攻擊者就必然取得整部工作站、憑證與正式系統控制權。從瀏覽器漏洞一路走到管理跳板，中間還有沙箱逃逸、端點防護、權杖或憑證取得、身分驗證與網路政策等條件。每一段都需要證據，不能用一條箭頭帶過。

然而，修補優先序也不能等到整條攻擊鏈百分之百被證明才開始動作。當入口軟體正在被使用、已有實際利用訊號、資產又位於具有後續管理關係的位置時，先升級瀏覽器是一項成本低、風險降低立即，而且容易驗證的措施。

所以今晚先處理案例 B，不是宣布「8.1 比 9.8 更危險」，而是判斷：**在現有控制仍有效的前提下，先修 B 能更快移除目前較活躍、較接近重要管理路徑的入口。**

## 同一份 CVE 清單，加入情境後才成為決策資料

| 判斷層次 | 案例 A | 案例 B | 對決策的影響 |
|---|---|---|---|
| 技術嚴重度 | 9.8 Critical | 8.1 High | 單看這層，A 優先 |
| 漏洞適用性 | Confluence 7.13.6，已確認 | Firefox 74.0，已確認 | 兩者都不是誤報 |
| 威脅訊號 | KEV、曾遭利用 | KEV、針對性攻擊 | 兩者都不能因年代久遠而忽略 |
| 有效可達性 | 僅兩個正向列表來源可達 | 日常接觸外部內容 | B 的入口更活躍 |
| 資產與資料 | 測試用途、無正式資料 | 維運人員每日使用 | B 的資產角色較敏感 |
| 攻擊路徑 | 無正式區出口 | 具有管理跳板登入關係 | B 需要優先切斷入口並查證後段 |
| 控制信心 | ACL 有近期驗證紀錄 | EDR 存在，但不等於漏洞已消失 | A 可短期依賴控制；B 直接升級較有效率 |
| 修補成本 | 需安排服務停機與驗證 | 瀏覽器可快速升級 | 同一窗口下，B 的風險降低／成本比更好 |

弱掃工具如果只有 CVE 與 CVSS，只能完成第一列。剩下的每一列，才是企業要建立、維護與驗證的情境資料。

## 今晚的答案不是排名，而是一組決策條件

在這個虛構案例裡，我會先升級 `OPS-WS-07` 的 Firefox，同時檢查 EDR、瀏覽器與身分驗證紀錄；`LAB-CONFLUENCE-01` 則維持隔離、建立禁止放寬控制的限制，並排入下一個修補窗口。

這個答案不是永久的。如果發現 ACL 已失效、測試主機其實存有正式資料，或它能連到正式區，案例 A 必須立刻升到最高優先。如果案例 B 經確認根本沒有安裝受影響版本，也應退出修補排序，而不是因為它位於敏感路徑就硬修。

因此，Day 2 真正得到的不是一條新公式，而是三項規則：

1. **Severity 不等於 Priority。** CVSS Base Score 是重要輸入，但不是完整答案。
2. **控制措施只能降低風險，不能抹除漏洞。** 而且必須附驗證時間、適用範圍與失效條件。
3. **未知不是低風險。** 版本、可達性或攻擊路徑缺乏證據時，應標記 `REVIEW_REQUIRED`，交由人工確認。

明天，我們再把經常混在一起的三個詞拆開：**嚴重度、威脅與風險，到底有什麼不同？**

## 資料來源

- [FIRST：CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide)
- [FIRST：CVSS v4.0 Specification Document](https://www.first.org/cvss/v4.0/specification-document)
- [NVD：CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134)
- [Atlassian：Confluence Security Advisory 2022-06-02](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html)
- [CISA：CVE-2022-26134 加入 KEV 公告](https://www.cisa.gov/news-events/alerts/2022/06/02/cisa-adds-one-known-exploited-vulnerability-cve-2022-26134-catalog)
- [NVD：CVE-2020-6820](https://nvd.nist.gov/vuln/detail/CVE-2020-6820)
- [Mozilla Foundation Security Advisory 2020-11](https://www.mozilla.org/en-US/security/advisories/mfsa2020-11/)
- [CISA KEV：搜尋 CVE-2020-6820](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2020-6820)
