# ADR｜Day 5：Decision Engine v0.1 採 Minimum Context 與可調整加權規則

- 日期：2026-09-19
- 狀態：Accepted for v0.1
- 影響範圍：Decision Engine、scoring、Day 6–18 施工順序

## 背景

Day 1–4 已確認弱掃結果本身不足以決定企業處置優先順序。Day 5 將第一版 Decision Engine 收斂為一條可完整驗證的 Vertical Slice。

原藍圖將完整 scoring 模型安排於 Day 11–18；但若 Day 6 仍沒有最小可執行的 Decision Rule，就無法開始真正的 end-to-end 開發。

## 決策

Decision Engine v0.1 先採 Minimum Context：

- Reachability
- Control Effectiveness
- Business Criticality

Service 與 Environment 保留作定位與解釋，但暫不直接進公式；Owner 暫不進 v0.1。

有效曝險：

```text
Effective Exposure = Reachability × Control Effectiveness
```

其中 UNKNOWN 不得降低曝險。

三個判斷維度先正規化為 0–1：

```text
S = CVSS / 10
E = Effective Exposure
B = Business Impact
```

v0.1 Priority Score：

```text
Priority Score = 10 × (0.50×S + 0.25×E + 0.25×B)
```

權重必須外部化到設定檔，不 hard-code。

## 理由

1. 先完成可執行的 Walking Skeleton，而不是同時完成所有資料來源與完整風險模型。
2. 保留 Day 3 的三把尺，讓概念能直接轉成可計算 Decision Rule。
3. 明確區分 CVSS Severity 與 Contextual Priority，避免把企業優先序誤稱為 CVSS 降級。
4. UNKNOWN 採保守處理，避免缺資料反而降低風險。
5. 50/25/25 僅為 v0.1 baseline，必須在後續案例、EPSS/KEV、控制與攻擊路徑加入後重新校準。

## 與原藍圖的關係

原藍圖中的 CRPS 完整模型不再視為 Day 6 即採用的既定公式，而改為後續 scoring 階段的候選演進方向。

Day 6 先實作 Decision Engine v0.1；Day 7–18 再逐步補外部情報、資料模型、控制、解釋與校準。任何正式改變權重或優先級門檻的決定，仍需新增或更新 ADR。

## 後果

- Day 6 可直接以 `scanner.csv + asset_context.csv + risk_rules.yaml` 開始實作。
- v0.1 的分數只用於排序與驗證，不宣稱事故機率或財務損失。
- 後續加入 EPSS、KEV、攻擊路徑等資訊時，允許公式演進，但必須保留可解釋性與版本紀錄。
