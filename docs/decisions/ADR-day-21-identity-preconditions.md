# ADR-day-21：前提是記錄的事實，不是從分數推出來的

- 狀態：Accepted
- 日期：2026-10-05
- 影響：新增 `attack_graph/identity.py`；`services.csv` 加 `runs_as`、`identity_edges.csv` 加 `credential_source` 與 `requires_privilege`
- 相關：藍圖 §10 Day 21（權限前置條件明確）、[ADR-day-19](ADR-day-19-graph-model.md)、[ADR-day-20](ADR-day-20-reachability.md)

## 背景

Day 19 把帳號畫成節點，`asset --uses--> account --grants--> asset`。那條邊當時是**無條件可走的**，背後藏了三個沒講出來的假設：攻擊者拿得到憑證、他在來源端的權限足以拿到它、沒有控制擋住。

Day 20 把網路那一半的「憑什麼」講清楚了。今天輪到身分這一半。

## 決策

### 1. 「打完拿到什麼權限」不能用推的

最想推導的就是這一項，而它推不出來：

> **CVSS 的 `PR` 說的是「需要什麼權限才能打」，不是「打完拿到什麼權限」。**

兩者方向相反。一個 `PR:N` 的漏洞（不需要任何權限）可能讓你直接拿到 SYSTEM，也可能只讓你讀一個檔案——CVSS 不區分。

試過的另一條路也不通：把 finding 的 `service` 欄接到服務清冊去查身分。**40 筆 finding 只有 15 筆對得上**（`nginx-http2` 對不到 `nginx`、`log4j2` 根本不是服務名）。用名稱 join 會在 25 筆上猜錯。

所以權限記在服務上：`services.runs_as`——攻下這個服務會取得什麼身分。這是清冊答得出來的事實。

### 2. 前提也記在邊上

`identity_edges.csv` 增加兩欄：

- `credential_source`——憑證放在來源機器的哪裡（`config_file`／`memory`／`agent_token`／`sealed_credential`／`interactive_only`）
- `requires_privilege`——在來源端要有什麼權限才拿得到

### 3. 憑證不在機器上，權限再高也沒用

`sealed_credential` 代表憑證**離線保管，不在那台機器上**。這種情況**不比較權限等級**，直接 `BLOCKED`——本機管理員權限不會讓保險箱打開。

這條規則是 `credential_source` 這一欄存在的理由。沒有它，那一欄就只是裝飾：權限排序會讓 `local_admin ≥ interactive_logon` 自動滿足 break-glass 的前提，而那是錯的。

### 4. 三態，而且 UNPROVEN 不擋路

`SATISFIED`／`BLOCKED`／`UNPROVEN`。最後一種發生在「無法確定來源端能取得什麼權限」時（例如 finding 對不到任何已登錄服務）。

**UNPROVEN 的邊照走。** 不能證明走不通，就得當它走得通——Day 5 以來同一條規則。

### 5. BLOCKED 的邊留在圖上

標記為不可走，但節點與邊都保留。它記錄的是一個**真實存在的權限關係**，只是攻擊者目前走不過去。拿掉它，之後這台機器多一個提權漏洞時，就沒有人會想起這條路曾經存在。

## 實測結果

10 條身分邊：**SATISFIED 5、UNPROVEN 4、BLOCKED 1。**

那條 BLOCKED 是 `break_glass` 的封緘憑證。而把它堵掉之後，路徑從 31 條只掉到 **30 條**——因為旁邊還有一條 `adm_domain`，憑證就放在**記憶體裡**，通往同一台網域控制器。

**把最嚴格的那條鎖好，不會讓隔壁那條變安全。** 更諷刺的是 Day 12 讀到的控制證據：`NS-JUMP-01` 的 MFA 被註記為「session recording gaps on break-glass account」——那份證據擔心的正是被我們判定為走不通的那一條。

通往網域管理員的那條鏈，每一步都有記錄支撐：

```text
internet → NS-VPN-GW-01 → NS-JUMP-01 → NS-AD-DC-01
                          BlueKeep 打 RDP，RDP 的 runs_as = local_admin
                          adm_domain 憑證在記憶體，requires local_admin → 成立
```

## 誠實的限制

- **25/40 的 finding 對不到已登錄服務**，所以多數資產的「可取得權限」是 `UNPROVEN`。這不是模型的保守，是資料的缺口：要補就得在 finding 與服務之間建立穩定的對應（藍圖 §8.3 的 `version_evidence.csv` 是其中一部分）。
- 權限等級用的是一條**粗糙的線性序**。真實權限是偏序（能讀資料庫不代表能登入主機），v0.1 用線性序換取可檢驗性。
- 控制（MFA）還沒進入身分前提的判定。Day 15 的適用性框架可以套，但那會動到已凍結的評分 baseline，留待 Day 23 一併處理。
