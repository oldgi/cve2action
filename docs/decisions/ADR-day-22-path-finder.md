# ADR-day-22：「查無路徑」有四種意思，只有一種接近安全

- 狀態：Accepted
- 日期：2026-10-05
- 影響：新增 `attack_graph/diagnose.py`、CLI `cve2action path`；新增 `.gitattributes`
- 相關：藍圖 §10 Day 22、§16 Day 24 路徑門檻、[ADR-day-20](ADR-day-20-reachability.md)、[ADR-day-21](ADR-day-21-identity-preconditions.md)

## 背景

藍圖 §16 的 Day 24 門檻寫了一句：「無法到達的資產不會被誤標為可達」。

反過來那半句沒寫，但更容易出事：**可達的資產不應該被誤標為安全。** 路徑搜尋回空集合，看起來像好消息，實際上可能只代表清冊沒資料。

## 決策

### 1. 空集合要分四種

| 判定 | 意思 | 要做什麼 |
|---|---|---|
| `NO_INBOUND` | 清冊裡沒有任何指向它的連線或權限關係 | **去查清冊**——這是資料缺口 |
| `SOURCE_UNREACHABLE` | 有入邊，但來源自己也到不了 | 看來源那條鏈 |
| `BLOCKED_BY_POLICY` | 入邊**全部**被政策明文拒絕 | 這才接近「被擋住」 |
| `EXCLUDED` | 入邊因服務沒在聽、前提不成立等被排除 | 看排除理由，可能只是暫時 |

`NoPath.means_safe` 只對 `BLOCKED_BY_POLICY` 回真，而且輸出會把這個數字單獨講出來：「其中真的算『被擋住』的：N 台」。

混合情況（部分政策拒絕、部分其他理由）判為 `EXCLUDED` 而非 `BLOCKED_BY_POLICY`——只要有一條不是被政策擋的，就不能說它是被政策擋住的。

### 2. 呈現一條，說明其餘

`cve2action path --to ASSET` 預設只展開**最短那一條**，前面加一段摘要：幾條路徑、用到幾個中間節點、哪些節點被共用最多。`--all` 才全部展開。

這是 Day 20 確立的立場（路徑的數量不是資訊量）的落地。

### 3. 排序是決定性的

依跳數、再依沿途資產名。同樣的資料每次得到同一條「最短路徑」，文章與截圖才對得上。

**但最短不等於最危險**——這是 Day 23 的題目，今天只排跳數，而且在文章裡講明這個限制。

## 實測結果

20 台資產：**有路徑 14 台、查無路徑 6 台。**

六台全部是 `NO_INBOUND`，**沒有一台是被擋住的**。其中 `NS-APP-INTRANET-01` 身上有 Log4Shell 與 Confluence RCE，它「安全」的唯一理由是沒有人記錄過誰連得到內部網站。

資料集沒有另外三種判定的例子，所以它們用合成輸入做單元測試——與 Day 20 的 `DRIFT` 同樣的處理。

## 順帶修掉一個偽裝成測試問題的設定缺口

`test_rebuilding_from_snapshots_is_byte_identical` 間歇性紅燈。Day 19 我以為是「測試會改寫版控檔案」，改成建到暫存目錄後仍然偶發。

真正的原因是 **`core.autocrlf=true` 且 repo 沒有 `.gitattributes`**：每次 `checkout`／`merge` 會把工作區的文字檔改寫成 CRLF，而建置腳本寫 LF，逐位元組比對自然炸——紅的時機取決於上一次做了什麼 git 操作，所以看起來像隨機。

新增 `.gitattributes`（`* text=auto eol=lf`）並 renormalize。這也讓整個開發過程中那串 "LF will be replaced by CRLF" 警告消失。

**教訓與 Day 18 同一條**：間歇性失敗先別怪測試，先問「它依賴的環境是不是在變」。

## 後果

- 新增 16 個測試；`cve2action path` 可查單一資產或整份覆蓋狀況。
- 尚未做到：路徑排序只看跳數。Day 23 會把路徑條件變成分數（並同時決定公式形式）。
- 尚未做到：`SOURCE_UNREACHABLE` 的判定依賴呼叫端傳入的 `reachable` 集合，需要先對全部資產跑一次搜尋。資產數大時這個做法會太慢，但 20 台的規模下不值得先優化。
