# Day 6｜讓第一條決策鏈跑起來

**Decision Engine v0.1: The First Vertical Slice**

![Day 6 cover](../images/day-06-cover.png)

昨天，我們把 CVE2Action v0.1 的邊界畫完了：

> **Minimum Context、Decision Rules、MVP I/O，全部凍結。**

所以今天不再討論 Scope。今天開工。

目標只有一行：

```text
scanner.csv + asset_context.csv + risk_rules.yaml
                      ↓
              Decision Engine
                      ↓
              ranked_result.csv
```

---

## 規格寫在文件裡，不等於決策鏈能跑

Day 1–5 累積了很多「應該怎麼判斷」的想法。

但截至昨天，這個專案還沒有一行程式碼。

如果現在就去接 NVD、EPSS、KEV，很容易變成：資料蒐集器寫了一堆，決策鏈還是斷的。

所以 Day 6 只做一件事：

> **讓最小的一條決策鏈，從輸入走到輸出，中間每一步都可驗證。**

這就是 Vertical Slice：不求寬，先求通。

---

## 第一刀：Decision Rules 不寫死在程式裡

![Decision Rules 外部化](../images/day-06-rules-external.png)

Day 5 說過，50/25/25 不是標準答案，只是 v0.1 的起始假設。

**會被推翻的東西，就不能寫死在程式裡。**

所以權重、值域映射、分級門檻，全部放進 `risk_rules.yaml`：

```yaml
weights:
  severity: 0.50   # S = CVSS / 10
  exposure: 0.25   # E = Reachability × Control
  business: 0.25   # B = Business Impact

reachability:
  INTERNET: 1.0
  INTERNAL: 0.6
  ISOLATED: 0.2

control_effectiveness:
  NONE: 1.0
  PARTIAL: 0.7
  STRONG: 0.4
  UNKNOWN: 1.0   # 不知道，就不能假裝已有防護
```

而且載入時就驗證，違反直接拒載：

```text
權重和必須等於 1
值域的鍵不得增刪
UNKNOWN 不得低於 NONE
分級必須涵蓋 0–10
```

> **規則檔壞掉，就拒載。不能默默補一個看似合理的預設值。**

---

## 跑一次：CVSS 最高的，掉到第四名

模擬資料是 6 筆虛構 finding（Northstar 虛構環境，含 Day 5 的 Case A / B）：

```bash
cve2action rank \
  --scanner data/synthetic/day-06-scanner.csv \
  --context data/synthetic/day-06-asset-context.csv \
  --rules   config/risk_rules.yaml \
  --out     ranked_result.csv
```

![排序結果](../images/day-06-rank-flip.png)

輸出的 `ranked_result.csv`：

| # | Asset | CVSS | Context | Priority |
|---|---|---:|---|---|
| 1 | NS-MAIL-GW-02 | 8.8 | INTERNET × NONE × CRITICAL | **9.40 Critical** |
| 2 | NS-APP-INTRANET-01 | 10.0 | INTERNAL × UNKNOWN × IMPORTANT | 8.25 High |
| 3 | NS-MAIL-GW-01 | 8.8 | INTERNET × STRONG × CRITICAL | 7.90 High |
| 4 | NS-LAB-CONFLUENCE-01 | **9.8** | ISOLATED × PARTIAL × NORMAL | **6.25 Medium** |
| 5 | NS-FILE-SRV-01 | 5.3 | INTERNAL × PARTIAL × NORMAL | 4.70 Medium |
| — | NS-IOT-CAM-77 | 9.8 | （找不到 context） | **NEEDS_CONTEXT** |

三件事值得看：

**一、Day 5 的紙上推演，現在是可重跑的程式輸出。**

Case A（9.8、隔離）= 6.25 Medium；Case B（8.8、對外核心）= 7.90 High。排序翻轉，數字分毫不差。

**二、每一列都說得出理由。**

`reason` 欄位不是裝飾：

```text
CVSS 9.8 (S=0.98); ISOLATED x PARTIAL -> E=0.14;
NORMAL -> B=0.4;
score = 10 x (0.5xS + 0.25xE + 0.25xB) = 6.25 [Medium]
```

主管問「為什麼 9.8 不是第一個修」，這一行就是答案。

**三、UNKNOWN 和「缺資料」是兩件事。**

![UNKNOWN 與 NEEDS_CONTEXT](../images/day-06-unknown-vs-needs-context.png)

第 2 名那台 `UNKNOWN` 控制的主機，是**合法值**：控制措施有登錄，但沒人能證明有效。它照算，而且用最保守的係數 1.0，所以 10 分的 Log4Shell 還是 High。

最後一列的 `NEEDS_CONTEXT` 則是**缺資料**：scanner 掃得到，資產清冊裡卻沒有這台設備。它不評分、不猜預設值、不隱藏，固定沉在清單最底部等人補資料。

> **不知道防護有沒有效 → 當作沒有防護，照算。
> 連資產是誰都不知道 → 不算，標出來。**

---

## 用測試把 Day 5 鎖住

公式現在能算，但明天的我可能手滑改壞它。

所以 Day 5 的驗收數字，全部變成回歸測試：

```text
Case A                 → 6.25 / Medium
Case B                 → 7.90 / High
Case B（無控制）        → 9.40 / Critical
排序                   → B 必須在 A 前面
UNKNOWN vs NONE        → 分數必須相同
權重和 ≠ 1 的規則檔     → 必須拒載
```

22 個測試，加上 GitHub Actions：每次 push 自動跑 lint、測試、資料驗證，最後實跑一次引擎當 smoke test。

從今天起，**改壞公式的人（包括未來的我）會在 CI 被抓到。**

---

## 符合預期嗎？限制在哪

符合的部分：決策鏈通了，排序翻轉可重現，理由說得出口。

但誠實列出這一版還不知道的事：

- **它看不到威脅。** 沒有 EPSS、沒有 KEV。已被實際利用的漏洞，目前和沒人理的漏洞同分。
- **它假設資產歸併已完成。** 多 IP 同設備的歸併（Day 1 的第一道門）還沒做，v0.1 假設 scanner.csv 已是乾淨結果。
- **它看不到路徑。** INTERNET/INTERNAL/ISOLATED 是人工標籤，不是從網路拓樸算出來的有效可達性。

這些不是遺漏，是刻意留下的施工順序。

---

## 明天

決策鏈通了，但引擎吃的 CVSS 還是模擬資料手填的。

明天開始接第一個真實資料來源：

> **Day 7｜打開 NVD：取得 CVE 與 CVSS 資料。**

## 資料與重現

- [Decision Engine v0.1 開發規格](../architecture/decision-engine-v0.1-spec.md)
- [risk_rules.yaml](../../config/risk_rules.yaml)
- [Day 6 模擬資料](../../data/synthetic/day-06-scanner.csv)（[asset context](../../data/synthetic/day-06-asset-context.csv)）
- [回歸測試](../../tests/test_engine.py)

所有資產、環境與控制均為虛構；CVE 編號取自公開來源，僅作為模擬弱掃輸出的示例。

#VerticalSlice #DecisionEngine #WalkingSkeleton #ExplainableRisk
