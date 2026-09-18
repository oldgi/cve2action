# Day 4｜為消失的「我們」畫像

昨天，我們留下了三把尺：

> **嚴重度看漏洞。**  
> **威脅看攻擊。**  
> **風險看我們。**

今天準備把第三把尺放進 CVE2Action，應該也有不少人有一瞬間的恍惚：

> **「我們」是什麼？「我們」在哪裡？看不見「我們」，又怎麼知道風險？**

這個看不見的「我們」，其實散落在設備清單、業務流程、網路架構、系統組態與各種管理資訊裡。它們共同勾勒出漏洞所在的**企業情境**。下面，我們用 **Context** 代稱這些資訊。

---

## 弱掃看得見漏洞，卻看不見它身後的「我們」

弱掃工具很擅長回答：

> **哪台設備有什麼漏洞？有多嚴重？**

執行掃描的人，也可以很快產出一份 Critical、High、Medium 排得整整齊齊的報告。

但報告裡通常看不出：

- 這是 TEST 還是 PRD？
- Internet 碰不碰得到？
- 承載的是一般服務還是客戶交易？
- 真的被攻陷，業務代價有多大？

這不是弱掃做錯了什麼。

**它只是完成了「找到漏洞」的工作，還沒有足夠資訊回答「我們該先處理哪一個」。**

前三天，其實已經慢慢拼出了 Decision Engine 的骨架：

```text
Severity ───┐
Threat ─────┼──→ Decision ──→ Action
Context ────┘
```

Severity 可以從 CVSS 取得；Threat 可以透過 EPSS、CISA KEV 等外部情報補進來。真正缺的，是弱掃報告之外的 Context。

所以今天不是再找一個 Score，而是：

> **把漏洞放回它真正存在的企業環境裡，替 Decision Engine 畫出一張「我們」的像。**

![弱掃看見的與它看不見的](../images/day-04-visible-vs-context.png)

**圖說：弱掃完成了漏洞發現；但從 Vulnerability 走到 Risk，中間還少了企業自己的 Context。**

---

## 第一張像，不需要畫得很細

如果目的是決定「先處理誰」，我先只問三個問題。

### 1. 它是誰？—— Asset

```text
TEST-01              PAYMENT-PRD-01
Test                  Production
Low Criticality       High Criticality
```

漏洞沒變，業務位置變了。第一版先留下：

```text
environment
criticality
```

它們不是直接決定「立刻修」，而是回答：**這個漏洞發生在哪裡？**

### 2. 攻擊者碰得到嗎？—— Reachability

假設兩台都是 Production：

```text
A                       B
Internal only           Internet exposed
CVSS 9.8                CVSS 9.8
```

完整的 Firewall Rule、NAT、WAF、Network Topology 當然都會影響答案。但第一版，我只想知道：

```text
internet_exposed = true / false
```

因為它已經能回答一個會明顯改變優先順序的問題：**外面的攻擊者，有沒有一條直接的路？**

### 3. 真的出事，會傷到什麼？—— Impact

最後，假設兩台都是 Production、Internet exposed、CVSS 9.8，一台是活動網站，一台承載客戶交易。讓它們再次分開的，是攻擊成功後的代價。

所以再留下：

```text
business_impact
```

至此，「風險看我們」不再只是一句話：

```text
Asset          → 它在哪裡？
Reachability   → 攻擊者碰得到嗎？
Impact         → 真的出事會傷到什麼？
```

---

## 然後，事情開始失控

做到這裡，有 Infra 經驗的人應該已經開始想到更多東西了。

Asset 可以接 CMDB：Owner / OS / Application / Location / Environment / Business Service / Criticality……

Reachability 可以繼續挖：Firewall / WAF / NAT / Load Balancer / Network Zone / VPN / Security Group……

Impact 更是無底洞：CIA / RTO / RPO / Data Classification / Transaction Volume / Customer Impact / Compliance Impact……

每一個都有用，每一個都有理由接。再想十分鐘，還可以多二十個。

![企業 Context 的無底洞](../images/day-04-context-rabbit-hole.png)

**圖說：如果「有助於判斷」就是納入條件，我們最後做出來的不會是 Decision Engine，而是另一個企業整合專案。**

這裡才是今天真正的工程問題：

> **我們不是不知道還能加什麼，而是不知道該在哪裡停。**

---

## 所以，先故意畫得不像

一張畫像的目的，不是把每根頭髮都畫出來，而是讓人認得出：**這是誰。**

Decision Engine 也是。第一版不需要完整理解企業，只需要掌握**足以改變決策的最小特徵**。

| 維度 | CVE2Action v0.1 |
|---|---|
| Severity | CVSS |
| Threat | EPSS、KEV |
| Asset | environment、criticality |
| Reachability | internet_exposed |
| Impact | business_impact |

暫時不做：**完整 CMDB 整合、Firewall Path Analysis、IAM 關聯、Network Topology、Attack Path、自動估算營運損失。**

不是因為它們不重要，而是第一版沒有它們，**仍然可以回答比 CVSS 更多的問題。**

![CVE2Action v0.1 第一張企業畫像](../images/day-04-v01-portrait.png)

**圖說：我們終於讓 Decision Engine 看見弱掃報告裡原本缺席的「我們」。但看得見，不代表它已經會決定。**

---

## 畫像完成了，決策還沒有

回到四天前的問題：

> **1,284 個漏洞，到底先修哪一個？**

現在，我們已經有：

```text
Severity + Threat +「我們」
            ↓
            ?
            ↓
        Priority
            ↓
         Action
```

那個 `?` 很重要。

知道「這是一台 Internet exposed、承載關鍵業務的 Production Server」，和知道「所以它必須在 24 小時內處理」，是兩件不同的事。

**前者是 Context。後者才是 Decision。**

今天，我們只是替消失的「我們」畫出了第一張像。它很粗糙，但已經足以讓兩個同樣的 9.8，不再看起來完全一樣。

接下來真正困難的問題反而浮出來了：

> **這張像到底要畫到多細，才足以支撐第一版決策？**

再多一點，Scope 就開始膨脹；再少一點，Decision Engine 又可能只是換皮的 CVSS 排序器。

所以在填上那個 `?` 之前，我們得先做一件工程上更重要的事：

> **決定第一版做到哪裡，就停。**

**Day 5｜把 CVE2Action v0.1 的邊界畫出來。**
