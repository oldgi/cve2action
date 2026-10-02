# ADR-day-18：v0.1 評分門檻——可用的定義，以及明確不修的部分

- 狀態：Accepted
- 日期：2026-10-03
- 影響：新增 `config/acceptance.yaml`、`scoring/acceptance.py`、CLI `cve2action acceptance`；CI 新增兩道閘門
- 相關：[藍圖 §16 Day 18 門檻](../../CVE2Action-30天總體施工藍圖.md)、[ADR-day-16](ADR-day-16-explain-api.md)、[ADR-day-17](ADR-day-17-calibration-test.md)

## 背景

藍圖 §16 的 Day 18 門檻有三條：每項因子與來源皆可解釋、至少五個案例完成人工比較與回歸測試、50/25/25 僅是 baseline 且調整須留版本與 ADR。前兩條在 Day 16、17 做掉了。剩下的問題是最難的那個：**什麼算可用？**

「排得還行」不是答案。需要一組量得出來的條件，以及對沒達標的部分明確的處置。

## 決策

### 1. 門檻分 structural 與 empirical，不可混用

| 類型 | 問的是什麼 | 怎麼驗 | 換資料集會變嗎 |
|---|---|---|---|
| structural | 公式本身的性質 | 合成探針 | 不會 |
| empirical | 這份資料上的表現 | 實測 | 會 |

這不是潔癖。**從 Day 11 到 Day 17，我把「Northstar 產不出 Low」寫成「v0.1 公式產不出 Low」**，前者是資料集的事實，後者是對公式的指控。十行合成探針就能拆穿：

```text
CVSS 5.5 / ISOLATED / STRONG / NORMAL → 3.95 Low
```

公式四個分級全部構造得出來。Northstar 沒有 Low，是因為它沒有「低嚴重度 × 隔離 × 不重要」這個組合——它最低的 CVSS 是 3.7（Logjam），而那一筆落在對外的入口網站上。

把資料集的缺口當成公式的缺陷去調權重，會讓公式去遷就一份特定的資料。這個教訓與 Day 17 的 `verdict: data` 是同一件事。

### 2. 八條門檻

**structural（3）**：四個分級都構造得出來、缺資料不得讓分數變低、任一因子單獨變大分數不得下降。

**empirical（5）**：每筆都有完整因子分解與來源、分辨力（相異分數比例 ≥ 0.70）、分級平衡（單一分級 ≤ 50%）、值域利用（分數跨距 ≥ 0–10 的 60%）、頂端飽和（撞 10.0 的比例 ≤ 5%）。

門檻值外部化於 `config/acceptance.yaml`，並宣告 `applies_to_rules_version`——規則進版就要重新量，有測試盯著這一行。

### 3. 結果：6 通過、2 豁免、0 阻擋

| 條件 | 實測 | 門檻 | 結論 |
|---|---:|---:|---|
| bands_reachable | 四級全可達 | all | PASS |
| degradation_safe | 0 違規 | all | PASS |
| monotonic | 0 違規 | all | PASS |
| explainable | 38/38 | 1.0 | PASS |
| discrimination | 0.7368 | ≥ 0.70 | PASS |
| **band_balance** | **0.6316** | ≤ 0.50 | **WAIVED** |
| **range_coverage** | **0.44** | ≥ 0.60 | **WAIVED** |
| ceiling_saturation | 0.0263 | ≤ 0.05 | PASS |

### 4. 沒過的兩條，選擇不修——而且寫下為什麼

兩條失敗同一個根因：**輸入的解析度就這麼粗。** `business_criticality` 只有三檔（1.0／0.7／0.4）、`reachability` 三檔、`control_effectiveness` 四檔，`E` 實際只取到五個值。輸出不可能比輸入細。

要攤開分布就得改值域映射，而那會讓 Day 5 到 Day 17 建立的**每一個回歸基準同時失效**。v0.1 的目的是凍結一個可比較的起點，不是讓分布看起來漂亮。

兩條都豁免到 **Day 20**：可達性引擎會用觀測到的連線取代 zone 推導，`E` 不再只有五個值，分布會自然變寬。屆時重新量；**如果那時仍然這麼集中，才是公式的問題。**

`waivers` 缺 `reason` 或 `revisit_on` 會被載入時拒絕。拿掉 waiver，閘門立刻變紅——有測試證明這件事，否則 waiver 只是裝飾。

### 5. v0.1 的 baseline 就此凍結

`risk_rules.yaml` 0.3.0 的權重 0.35/0.15/0.25/0.25 與全部值域映射，連同 `acceptance.yaml` 0.1.0，構成 v0.1 的評分 baseline。後續任何調整都必須：新增或更新 ADR、重新跑 `acceptance` 與 `calibrate`、更新受影響的回歸數字。

## 替代方案

- **調權重讓分布漂亮**：這是 fit to one dataset。被 §4 的根因分析否決——問題在值域解析度，不在權重。
- **把分級門檻改成依分位數切**：排序會變得依賴批次組成，同一筆 finding 在不同批次得到不同分級。與「相同輸入必得相同輸出」直接衝突。
- **不設門檻，只寫文件描述現況**：那樣下一次改動沒有東西會擋住退步。

## 後果

- 新增 14 個測試；CI 新增兩道閘門（校準分歧必須有解釋、門檻沒過必須有 waiver）。
- 文件化的已知缺陷從「散在文章與 CHANGELOG 裡的註記」變成**會在 CI 紅燈的條件**。
- 一個長期誤解被更正：公式產得出 Low，是資料集沒有那種資產。Day 11 的測試註解與相關說法需一併修正。
- 尚未納入門檻的：穩定性（輸入小擾動不應造成排序大翻轉）。Day 20 之後 `E` 會變成連續值，屆時這條才有意義。
