# Day 29 測試報告：四個必測情境

- 證據基準日：2026-09-24（NVD／EPSS／KEV 固定快照）
- 資料集：Northstar（虛構），40 筆 finding，38 筆有分數
- 產生方式：`uv run python scripts/scenario_report.py`（產出物，不手改）

## 總表

| 情境 | 判定 | 量到 |
|---|---|---|
| 1．高 CVSS、低環境風險 | ⚠️ PARTIAL | 5 筆符合，CVSS 名次是並列第 1／7，本專案落在 #29–#38（後四分之一從 #30 起） |
| 2．中高 CVSS、極高優先度 | ⚠️ PARTIAL | 1 筆符合：NS-BACKUP-01 CVE-2017-0144，CVSS 並列第 19 → 本專案 #14，層級 P1→P0（前四分之一是 #1–#9） |
| 3．控制降低剩餘風險 | ✅ PASS | CVE-2021-41773：有 WAF（STRONG）#16、沒有 #3；CVE-2023-44487：有 WAF（STRONG）#25、沒有 #8 |
| 4．一次措施切斷多條路徑 | ✅ PASS | 單一連線切最多的是 關閉 NS-JUMP-01:3389 的連線：30 → 15；清冊裡登記過的措施最多切 2 條 |

規則先於結果：每個情境是一條逐字對應藍圖 §8.4 的查詢規則，資料裡符合的
每一筆都評。`NO_CASE`（資料裡沒有這種情況）不算通過。

## 情境一：高 CVSS、低環境風險（⚠️ PARTIAL）

- 規則：CVSS ≥ 9 且查無從 Internet 出發的路徑
- 判準：每一筆都落在本專案排序的後四分之一
- 量到：5 筆符合，CVSS 名次是並列第 1／7，本專案落在 #29–#38（後四分之一從 #30 起）
- 限制：查無路徑不是證明不可達（Day 22）；它們沒有消失，只是排在後面。

| rank | cvss_rank | move | asset | cve | cvss | score | band | tie_with_above | kev | epss | tier | tier_before | applicability | review | first | close | options | ok |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 29 | 1 | -28 | NS-MON-01 | CVE-2021-44228 | 10.0 | 7.17 | High | False | True | 0.99999 | P1 | P1 | UNDECIDABLE | True | 補償控制（1h） |  | 1 | False |
| 31 | 7 | -24 | NS-APP-REPORT-01 | CVE-2020-1938 | 9.8 | 6.73 | Medium | False | True | 0.9927 | P2 | P2 | APPLICABLE | True |  |  | 0 | True |
| 32 | 1 | -31 | NS-APP-INTRANET-01 | CVE-2021-44228 | 10.0 | 6.29 | Medium | False | True | 0.99999 | P2 | P2 | UNDECIDABLE | True |  |  | 0 | True |
| 33 | 7 | -26 | NS-APP-INTRANET-01 | CVE-2023-22515 | 9.8 | 6.23 | Medium | False | True | 0.99156 | P2 | P2 | APPLICABLE | False |  |  | 0 | True |
| 38 | 7 | -31 | NS-LAB-CONFLUENCE-01 | CVE-2022-26134 | 9.8 | 5.43 | Medium | False | True | 0.99999 | P2 | P2 | APPLICABLE | True | 隔離（1h） |  | 1 | True |

## 情境二：中高 CVSS、極高優先度（⚠️ PARTIAL）

- 規則：8 ≤ CVSS < 9、KEV 收錄、Internet 可達、能通往核心資料庫
- 判準：本專案排名前四分之一
- 量到：1 筆符合：NS-BACKUP-01 CVE-2017-0144，CVSS 並列第 19 → 本專案 #14，層級 P1→P0（前四分之一是 #1–#9）
- 限制：往前移了，但沒到頂端。升到 P0 靠的是 §9.6 覆寫，而覆寫後 24/40 都是 P0——在這份資料上 P0 不構成「極高」。分數上輸在 S（8.8 對 9.8）與 E（DATA 區不面對 Internet），而 B 與 T 在頂端沒有鑑別力（全是 CRITICAL、全在 KEV），補不回來。

| rank | cvss_rank | move | asset | cve | cvss | score | band | tie_with_above | kev | epss | tier | tier_before | applicability | review | first | close | options | ok |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 14 | 19 | 5 | NS-BACKUP-01 | CVE-2017-0144 | 8.8 | 8.71 | High | False | True | 0.9923 | P0 | P1 | UNDECIDABLE | True |  |  | 0 | False |

## 情境三：控制降低剩餘風險（✅ PASS）

- 規則：同一 CVE、同區域同角色；一台有驗證過的控制、一台沒有
- 判準：有控制的那台排在後面
- 量到：CVE-2021-41773：有 WAF（STRONG）#16、沒有 #3；CVE-2023-44487：有 WAF（STRONG）#25、沒有 #8
- 限制：反方向也成立：內網應用的 EDR 證據過期 117 天 → UNKNOWN，不折減（Day 12）。控制要有驗證日期才算數。

| cve | guarded | open | guarded_rank | open_rank | control | ok |
|---|---|---|---|---|---|---|
| CVE-2021-41773 | NS-WEB-PORTAL-01 | NS-WEB-PORTAL-02 | 16 | 3 | STRONG | True |
| CVE-2023-44487 | NS-WEB-PORTAL-01 | NS-WEB-PORTAL-02 | 25 | 8 | STRONG | True |

## 情境四：一次措施切斷多條路徑（✅ PASS）

- 規則：關閉一條連線，或隔離一台
- 判準：切掉 ≥ 2 條通往 Crown Jewel 的路徑
- 量到：單一連線切最多的是 關閉 NS-JUMP-01:3389 的連線：30 → 15；清冊裡登記過的措施最多切 2 條
- 限制：模型做得到，清冊沒登記。藍圖原文「修補跳板」在這個圖模型裡切 0 條——圖不看漏洞（ADR-day-27）。

| measure | paths | registered | ok |
|---|---|---|---|
| 關閉 NS-JUMP-01:3389 的連線 | 30 → 15 | False | True |
| REM-004 isolate NS-APP-BILLING-01 | 30 → 28 | True | True |

## 對照人工排序（Day 17 基準）

| 排序 | Kendall τ-b | 一致 | 分歧 | 平手 |
|---|---:|---:|---:|---:|
| 本專案 | 0.6 | 8 | 2 | 0 |
| 只看 CVSS | 0.527 | 7 | 2 | 1 |

**效度威脅**：只有 5 筆，排序者是「作者本人（同時是模型作者——見上方效度威脅）」。
這是自我一致性檢查，不是獨立驗證；差 0.07 在 5 筆上就是一組比較的差別。

## CVSS 排名與本專案排名：差異逐筆說明（成功標準 #5）

主因＝方向與移動一致、偏離全體中位數最多的那一項（S 以外）。算出來的，不是寫上去的。

| 本專案 | CVSS（並列） | 移動 | 資產 | CVE | CVSS | 分數 | 主因 |
|---:|---:|---:|---|---|---:|---:|---|
| 1 | 7 | +6 | NS-VPN-GW-01 | CVE-2024-21762 | 9.8 | 9.86 | E 曝險 +0.80（no-control） |
| 2 | 7 | +5 | NS-VPN-GW-01 | CVE-2018-13379 | 9.8 | 9.86 | E 曝險 +0.80（no-control） |
| 3 | 7 | +4 | NS-WEB-PORTAL-02 | CVE-2021-41773 | 9.8 | 9.69 | E 曝險 +0.80（no-control） |
| 4 | 1 | -3 | NS-EDGE-RTR-01 | CVE-2023-20198 | 10.0 | 9.42 | A 路徑 -0.33（attack_graph） |
| 5 | 1 | -4 | NS-API-GW-01 | CVE-2021-44228 | 10.0 | 9.4 | 沒有一項低於中位數：是別筆往前擠，不是它往後退 |
| 6 | 7 | +1 | NS-API-GW-01 | CVE-2022-22965 | 9.8 | 9.34 | A 路徑 +0.25（attack_graph） |
| 7 | 1 | -6 | NS-APP-ORDER-01 | CVE-2021-44228 | 10.0 | 9.1 | 沒有一項低於中位數：是別筆往前擠，不是它往後退 |
| 8 | 28 | +20 | NS-WEB-PORTAL-02 | CVE-2023-44487 | 7.5 | 9.05 | E 曝險 +0.80（no-control） |
| 9 | 7 | -2 | NS-APP-ORDER-01 | CVE-2020-1938 | 9.8 | 9.04 | 沒有一項低於中位數：是別筆往前擠，不是它往後退 |
| 10 | 7 | -3 | NS-APP-BILLING-01 | CVE-2023-34362 | 9.8 | 8.96 | 沒有一項低於中位數：是別筆往前擠，不是它往後退 |
| 11 | 7 | -4 | NS-JUMP-01 | CVE-2019-0708 | 9.8 | 8.96 | 沒有一項低於中位數：是別筆往前擠，不是它往後退 |
| 12 | 1 | -11 | NS-AD-DC-01 | CVE-2020-1472 | 10.0 | 8.85 | A 路徑 -0.10（attack_graph） |
| 13 | 33 | +20 | NS-API-GW-01 | CVE-2016-2107 | 5.9 | 8.82 | E 曝險 +0.80（control:waf@2026-08-14 (blind to CWE-310)） |
| 14 | 19 | +5 | NS-BACKUP-01 | CVE-2017-0144 | 8.8 | 8.71 | A 路徑 +0.10（attack_graph） |
| 15 | 33 | +18 | NS-WEB-PORTAL-01 | CVE-2013-2566 | 5.9 | 8.56 | E 曝險 +0.80（control:waf@2026-08-14 (blind to CWE-326/CWE-327)） |
| 16 | 7 | -9 | NS-WEB-PORTAL-01 | CVE-2021-41773 | 9.8 | 8.49 | E 曝險 -0.40（control:waf@2026-08-14 (applies to AV:NETWORK)） |
| 17 | 7 | -10 | NS-MAIL-GW-01 | CVE-2021-26855 | 9.8 | 8.49 | B 業務 -0.60（data:CONFIDENTIAL） |
| 18 | 24 | +6 | NS-APP-BILLING-01 | CVE-2021-3156 | 7.8 | 8.4 | A 路徑 +0.07（attack_graph） |
| 19 | 24 | +5 | NS-DB-CUSTOMER-01 | CVE-2021-3156 | 7.8 | 8.37 | A 路徑 +0.03（attack_graph） |
| 20 | 24 | +4 | NS-DB-BILLING-01 | CVE-2022-0847 | 7.8 | 8.37 | A 路徑 +0.03（attack_graph） |
| 21 | 28 | +7 | NS-BACKUP-01 | CVE-2014-0160 | 7.5 | 8.35 | A 路徑 +0.10（attack_graph） |
| 22 | 32 | +10 | NS-DB-CUSTOMER-01 | CVE-2016-5195 | 7.0 | 8.14 | A 路徑 +0.03（attack_graph） |
| 23 | 38 | +15 | NS-WEB-PORTAL-02 | CVE-2015-4000 | 3.7 | 7.99 | E 曝險 +0.80（no-control） |
| 24 | 23 | -1 | NS-MAIL-GW-01 | CVE-2022-41082 | 8.0 | 7.99 | B 業務 -0.60（data:CONFIDENTIAL） |
| 25 | 28 | +3 | NS-WEB-PORTAL-01 | CVE-2023-44487 | 7.5 | 7.85 | 沒有一項高於中位數：是別筆往後退，不是它往前衝 |
| 26 | 37 | +11 | NS-EDGE-RTR-01 | CVE-2025-21590 | 4.4 | 7.85 | E 曝險 +0.80（no-control） |
| 27 | 19 | -8 | NS-AD-DC-01 | CVE-2021-34527 | 8.8 | 7.79 | E 曝險 -0.72（control:mfa_admin_tiering@2026-08-28 (applies to AV:NETWORK)） |
| 28 | 19 | -9 | NS-FILE-SRV-01 | CVE-2017-0144 | 8.8 | 7.46 | B 業務 -0.60（rto:24h） |
| 29 | 1 | -28 | NS-MON-01 | CVE-2021-44228 | 10.0 | 7.17 | A 路徑 -1.19（attack_graph） |
| 30 | 19 | -11 | NS-OPS-WS-07 | CVE-2023-4863 | 8.8 | 6.83 | A 路徑 -1.19（attack_graph） |
| 31 | 7 | -24 | NS-APP-REPORT-01 | CVE-2020-1938 | 9.8 | 6.73 | B 業務 -1.20（data:INTERNAL） |
| 32 | 1 | -31 | NS-APP-INTRANET-01 | CVE-2021-44228 | 10.0 | 6.29 | A 路徑 -1.46（attack_graph） |
| 33 | 7 | -26 | NS-APP-INTRANET-01 | CVE-2023-22515 | 9.8 | 6.23 | A 路徑 -1.46（attack_graph） |
| 34 | 36 | +2 | NS-FILE-SRV-01 | CVE-2018-15919 | 5.3 | 5.68 | 沒有一項高於中位數：是別筆往後退，不是它往前衝 |
| 35 | 33 | -2 | NS-APP-REPORT-01 | CVE-2016-2107 | 5.9 | 5.61 | B 業務 -1.20（data:INTERNAL） |
| 36 | 31 | -5 | NS-PLC-DC-ENV | CVE-2024-6242 | 7.3 | 5.51 | A 路徑 -1.29（attack_graph） |
| 37 | 27 | -10 | NS-APP-INTRANET-01 | CVE-2021-23017 | 7.7 | 5.49 | A 路徑 -1.46（attack_graph） |
| 38 | 7 | -31 | NS-LAB-CONFLUENCE-01 | CVE-2022-26134 | 9.8 | 5.43 | A 路徑 -1.46（attack_graph） |
