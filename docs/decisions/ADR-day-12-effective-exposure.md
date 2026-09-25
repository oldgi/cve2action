# ADR｜Day 12：有效曝險的兩個輸入都用推導，並標明來源與有效期

- 日期：2026-09-25
- 狀態：Accepted for v0.1
- 影響範圍：`normalization/exposure.py`、`risk_rules.yaml`、`asset_context.csv` 契約

## 背景

Day 11 的 `asset_context.csv` 是手寫的：reachability 照 Zone 對應、control_effectiveness 照
`controls.csv` 一對一抄。兩者都沒有留下「這個值從哪來」，也無法重現。

藍圖 Day 12 的驗收是「Reachability 與 Control Effectiveness 可重現」。

## 決策

1. **Zone → Reachability 是假設，不是事實。** Zone 是行政標籤；一台在 DMZ 的機器可能只對
   合作夥伴開放，一台在 CORP 的機器可能因一條 NAT 規則而對外。對應表因此外部化到
   `risk_rules.yaml` 的 `exposure.zone_reachability`，視同權重，變更須更新本 ADR。

2. **觀測優先於推導。** `derive_reachability` 接受 observed 值並覆寫 Zone 假設，來源記為
   `observed`。Day 20 的 Reachability Engine 會從實際網路規則產生這個值。

3. **每個推導值都帶 `source`。** 輸出新增 `reachability_source`（`zone:DMZ` / `observed`）與
   `control_source`（`control:waf@2026-08-14` / `no-control` / 過期原因）。看得到來源，
   才有辦法質疑它。

4. **控制證據會過期。** `exposure.control_evidence_max_age_days`（v0.1 為 90 天）。超過期限的
   證據不能再拿來打折，該控制降為 **UNKNOWN 而非 NONE**——過期不代表控制失效，是我們
   不知道它現在還有沒有效。沒有登錄任何控制才是 NONE。

5. **多個控制取最強，不相乘。** WAF 與 EDR 可能被同一個繞過手法同時穿過，把它們當獨立
   事件相乘（0.4 × 0.7 = 0.28）是假精確。UNKNOWN 或過期的控制不參與比較，也不懲罰其他
   有證據的控制。

6. **情境時點必須固定。** 證據年齡以 `as_of` 計算，模擬資料集用 `SCENARIO_AS_OF = 2026-09-24`，
   不得用 `date.today()`——否則資料集每天都不一樣，Day 18 的 baseline 就沒有意義。

## 後果

- 推導出的 asset_context 前五欄與 Day 11 手寫版**完全相同**（測試驗證），資料沒變，只是
  多記了來源；`asset_context.csv` 增加兩個 source 欄位。
- 收緊 `control_evidence_max_age_days` 到 30 天，Northstar 的過期控制從 1 台增為 3 台，
  `NS-WEB-PORTAL-01` 的 CVE-2021-41773 由 8.4 High 升至 9.9 Critical。有效期因此是會改變
  排序的設定，與權重同級。
- 「取最強」是保守但粗糙的合併方式；控制之間的相依性、以及不同控制對不同利用手法的覆蓋
  差異，留待 Day 15 的 Control calibration。
