# ADR｜Day 13：Business Criticality 由業務事實推導，取最嚴重的維度

- 日期：2026-09-27
- 狀態：Accepted for v0.1
- 影響範圍：`normalization/business.py`、`risk_rules.yaml`、`assets.csv`、新增 `business_context.csv`

## 背景

Day 11 的 `assets.csv` 有一欄 `criticality`，值是我直接標的。它是判斷，不是事實，
既說不出根據也無法重現——與 Day 12 處理 reachability 前的狀況相同。

藍圖 Day 13 的驗收是「業務重要性尺度可重現」。

## 決策

1. **`criticality` 不再是輸入。** `assets.csv` 該欄更名為 `declared_criticality`，僅保留
   作為對照；引擎使用的值由新的 `business_context.csv` 推導。

2. **三項可查證的事實**：`data_class`（存什麼資料）、`rto_hours`（多久不能停）、
   `customer_facing`（是否直接面對客戶）。三者都是業務答得出來的問題，不是資安猜的。

3. **取最嚴重的維度，不平均。** 一台存放受管制資料、但停機容忍度很高的機器仍是 CRITICAL；
   把它跟 RTO 平均，等於用「可以慢慢修」沖淡「資料會外洩」。

4. **缺事實就報錯。** `data_class` 或 `rto_hours` 缺漏時丟 `ExposureError`，不填預設值。

5. **輸出標明哪個維度勝出**（`business_source`：`data:RESTRICTED` / `rto:2h` / `customer-facing`）。

## 後果

- 二十台資產中**四台的推導值與 Day 11 手標值不同**：`NS-MAIL-GW-01` CRITICAL→IMPORTANT、
  `NS-APP-INTRANET-01` IMPORTANT→NORMAL、`NS-FILE-SRV-01` NORMAL→IMPORTANT、
  `NS-PLC-DC-ENV` IMPORTANT→CRITICAL。最後一台不存任何業務資料，純粹因為 RTO 兩小時。
- 排序分布由 Day 11 的 8/22/8 變為 **7/23/8**，三筆發現跨越分級。Day 11 文章引用的是當時
  正確的數字；此處記錄變動來源。
- 這是 Day 18 訂 baseline **之前**的輸入修正。凍結資料集是為了讓校準有意義，不是為了保護
  已知有誤的判斷；baseline 訂定後再改，就必須重跑全部回歸案例。
- RTO 門檻（4 小時 / 24 小時）與 `customer_facing_floor` 同屬會改變排序的設定，變更需更新本 ADR。
