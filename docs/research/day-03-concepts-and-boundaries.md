# Day 3｜概念、案例邊界與來源

整理日期：2026-09-17。狀態：可審稿，未確認發布。

## 接續依據

- 使用本工作副本的 Day 2 最終文章、ADR-0003 與使用者已確認的發布／推送紀錄。
- Day 2 公開網址：https://ithelp.ithome.com.tw/articles/10412142 。本次未成功取得線上頁面全文，不能聲稱已比對網站現行版本。
- 使用者回報 GitHub main 已推送至 `48db22b`。工作副本的本機提交歷史不同，不能當作遠端同步證明。
- Day 3 接續藍圖的嚴重度、威脅、風險；Day 4 接「一個漏洞要加入哪些企業情境？」。

## 官方來源

查閱日期：2026-09-17。

| 來源 | 本文使用範圍 |
|---|---|
| [FIRST CVSS v3.1 User Guide](https://www.first.org/cvss/v3.1/user-guide) | CVSS 衡量嚴重度；Base、Temporal、Environmental 的區別。Base 包含利用條件與技術衝擊，不等於企業入侵機率。 |
| [FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) | 三組指標定義；Environmental 仍屬嚴重度調整，不能當成完整企業風險。 |
| [FIRST CVSS v3.1 §3.4](https://www.first.org/cvss/v3.1/user-guide#3-4-vulnerability-chaining) | 已有漏洞串接指引，但不是企業資產與路徑的自動盤點系統。 |
| [FIRST CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide) | Temporal 改名與調整為 Threat；不能據此將三把尺與三組指標一對一等同。 |
| [Volexity 原始調查](https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/) | 2022-06-02 發布 Confluence 實際入侵調查；未用來宣稱特定日期的全球攻擊量。 |
| [Mozilla MFSA 2020-11](https://www.mozilla.org/en-US/security/advisories/mfsa2020-11/) | 2020-04-03 公告中的針對性利用紀錄；不能與另一年代、另一觀測範圍的報告直接排威脅強弱。 |
| [NIST Glossary: Threat](https://csrc.nist.gov/glossary/term/threat) | 可能造成不利影響的情況或事件。本文收斂到利用漏洞的攻擊情境，但不將全部威脅限縮為駭客活動。 |
| [NIST Glossary: Risk](https://csrc.nist.gov/glossary/term/risk) | 風險通常涉及不利影響及發生可能性。本文並未引用特定量化公式。 |

NIST 詞彙頁彙整多份文件的定義，應依採用框架及情境閱讀。本文是概念教學，不宣稱建立完整 NIST 風險評估流程。

## 圖解設計

1. 嚴重度、威脅與企業情境共同進入成立條件查核，再評估可能性及損失。
2. 不畫成「Severity × Threat = Risk」，也不把 CVSS 分數解讀為百分比。
3. 威脅線索及企業情境可能同時影響可能性與損失，不硬性各自只接一條分支。
4. 損失包含直接影響與後續擴散；每段路徑都要查核身分、權限及其他前提。
5. 箭頭是資訊與評估關係，不是已成功利用的攻擊鏈。
6. 門鎖圖只做類比。警衛存在不證明控制有效；一般備品也可能有營運價值。

## 不可混淆的邊界

- 兩個延伸結果都是虛構分支，沒有將 Day 2 的 `REVIEW_REQUIRED` 改寫成已核准。
- WAF、Firewall、RBAC 不必然涵蓋特定漏洞；需確認範圍、部署狀態、驗證證據與有效期。
- 「未發現路徑」不等於「證明不存在」；未知不直接等於低風險。
- 直接可達、能登入、擁有管理權限是不同條件；連線圖不可代替授權查核。
- 替代控制可能改變剩餘風險，但不修復漏洞本身，也不保證過去未被入侵。
- 修補成本影響處理方式，不是降低風險的證據。
- 必須開放服務功能，不等於必須容忍軟體漏洞。
- 暫緩須有責任人、核准、期限、複核及撤銷條件；本文不給通用寬限天數。
- 例外表是專案設計要求，不是法律或個別企業合規核准意見。工具不取代權責者的決定。

## 本次合併與後續治理章

- 採使用者修稿的敘事方向：三把尺套用 Day 2、CVSS 已有欄位、接到企業路徑及工具定位。
- 前段新增記憶圖，中段新增會議辨認圖，結尾加入三十秒練習；原流程圖移到延伸閱讀。
- 例外／豁免移出本文，留給治理章：保留必要性與範圍、替代方案、替代控制、剩餘風險與核准、有效期與退出條件。必要服務功能不等於漏洞豁免，工具不取代核准權限。
- 保留有期限、有證據的暫緩修補；案例 A 尚待審查，不事先標記低風險。
- 修改 Day 3 文章與相關交付檔，未修改 Day 2、藍圖或 ADR；沒有實作新公式，也沒有對外發布或推送。
