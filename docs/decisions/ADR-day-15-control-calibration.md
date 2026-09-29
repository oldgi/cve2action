# ADR-day-15：控制措施的適用性先於強度

- 狀態：Accepted
- 日期：2026-09-30
- 影響版本：`risk_rules.yaml` 0.2.0 → 0.3.0
- 相關：[ADR-day-05](ADR-day-05-decision-engine-v01.md)（UNKNOWN 不得降低風險）、[ADR-day-12](ADR-day-12-effective-exposure.md)（控制強度的推導與證據有效期）

## 背景

Day 12 讓 Control Effectiveness 變成可推導的值：證據太舊就不能再拿來打折，多個控制取最強不相乘。但推導出來的結果掛在**資產**上——一台機器一個係數，套用到這台機器上的每一筆 finding。

這在 Northstar 資料集上產生了明顯錯誤的折減：

| 資產 | 控制 | finding | CVSS 向量 | 折減是否合理 |
|---|---|---|---|---|
| NS-DB-CUSTOMER-01 | network_segmentation STRONG | CVE-2016-5195（Dirty COW） | AV:L | 否，網段控制看不到本機提權 |
| NS-DB-CUSTOMER-01 | network_segmentation STRONG | CVE-2021-3156（sudo） | AV:L | 否，同上 |
| NS-DB-BILLING-01 | network_segmentation STRONG | CVE-2022-0847（Dirty Pipe） | AV:L | 否，同上 |
| NS-AD-DC-01 | mfa_admin_tiering STRONG | CVE-2020-1472（Zerologon） | AV:N / PR:N | 否，攻擊不需要驗證 |
| NS-AD-DC-01 | mfa_admin_tiering STRONG | CVE-2021-34527（PrintNightmare） | AV:N / PR:L | 是，路徑上有帳號 |
| NS-JUMP-01 | mfa PARTIAL | CVE-2019-0708（BlueKeep） | AV:N / PR:N | 否，pre-auth RDP |

同一台 AD DC、同一項控制，兩筆 finding 的答案不同。**控制效果不是資產的屬性，是「資產 × 漏洞」的屬性。**

## 決策

### 1. 折減資格先看適用性，再看強度

一項控制要參與折減，必須先證明它的攔截點落在這條攻擊路徑上。判斷只用 CVSS 向量裡兩個既有且可查證的欄位，不新增需要人工填寫的資料：

- **AV（Attack Vector）**——攻擊從哪裡來。網路型控制對 `AV:L` 不適用。
- **PR（Privileges Required）**——路徑上有沒有「驗證」這一關。`PR:N` 代表攻擊者不必先是誰就能打，驗證類控制（MFA）沒有位置可站。

適用範圍外部化於 `risk_rules.yaml` 的 `controls.applicability`，不寫死在程式裡。

### 2. 三態，兩種都不折減但意義不同

沿用 Day 10 KEV 的三態紀律：

- **APPLICABLE**——套用該控制的強度係數。
- **NOT_APPLICABLE**——這是**事實**：我們知道網段隔離攔不到本機提權。折減撤銷，`control_effectiveness` 記為 `NONE`。
- **UNDECIDABLE**——讀不到向量，或該控制類型未宣告適用範圍。這是**未知**：不能證明攔得到，就不能拿它打折，記為 `UNKNOWN`。

兩者的係數都是 1.0，但 `control_source` 寫的不是同一句話。這個區別在 Day 16 的 Explain API 與 Day 25 的處置建議會用到：不適用的控制該換一種控制，未知的控制該去補證據。

### 3. 網段隔離對 AV:L 不適用，不是說隔離沒用

常見反駁是「隔離讓攻擊者根本上不了這台機器」。這件事為真，但它已經算在 **Reachability** 裡了——`E = R × C` 的 `R` 就是在回答「誰到得了這台機器」。再從 `C` 扣一次，是同一項控制在同一條公式裡算兩次。`C` 要回答的是另一個問題：**攻擊真的打進來時，這項控制攔不攔得住。**

### 4. 1.0 / 0.7 / 0.4 綁定證據門檻，並受一條可測性質約束

三個係數是**殘餘攻擊面的序**，不是攔截成功率；沒有人能宣稱一個 WAF 攔得下六成攻擊。每一級對應可查證的證據門檻：

| 值 | 係數 | 證據門檻 |
|---|---:|---|
| STRONG | 0.4 | 有針對此攻擊類別的阻擋證據（negative test、bypass test） |
| PARTIAL | 0.7 | 只有偵測、或規則未針對此應用調校，無阻擋證據 |
| NONE | 1.0 | 沒有控制，或現有控制對這條攻擊路徑不適用 |
| UNKNOWN | 1.0 | 有控制但拿不出證據 |

折減上限刻意壓在 0.4，使下面這條性質成立並以回歸測試守著：

> **單一控制最多讓一筆 finding 往下移一個分級。**

最大折減量為 `10 × w_exposure × R × (1.0 − 0.4) = 10 × 0.25 × 1.0 × 0.6 = 1.5` 分；跨兩個分級最少需要 `9.0 − 6.99 = 2.01` 分。因此補償控制可以改變相鄰名次，但不可能單靠一項控制把 Critical 壓成 Medium。

三個數字本身仍是假設，Day 17 以人工排序校準，調整須更新本 ADR。

### 5. 資產層推導維持不變

`cve2action derive-context` 產出的 `asset_context.csv` 仍是資產層的視圖（不看適用性），作為對照與 Day 12 相容。適用性只在逐筆評分時計算：`cve2action rank --controls controls.csv --as-of YYYY-MM-DD`。沒給 `--controls` 時行為與 Day 14 完全相同。

## 後果

- Northstar 38 筆評分中，9 筆維持折減、5 筆折減被撤銷（3 筆網段隔離對 `AV:L`、2 筆驗證類控制對 `PR:N`）。
- 分布由 8/25/5 變為 9/24/5；Zerologon 由 8.10 High 回到 9.00 Critical，與同一台 AD DC 上仍保有折減的 PrintNightmare（7.68 High）拉開。
- 「向量讀不到 → 不折減」目前只有單元測試守著：資料集裡唯一沒有向量的 CVE-2011-3389 本來就是 NEEDS_CONTEXT，走不到控制推導。
- 輸出新增 `control_effectiveness` 與 `control_source` 兩欄。
- 尚未處理：AV/PR 只能判斷「攔截點在不在路徑上」，判斷不了「這項控制懂不懂這個協定層」——WAF 對 TLS 層的 RC4 降級（CVE-2013-2566）仍被判為適用。這需要控制與弱點類別的對應，留待 Day 25 的處置模型。
